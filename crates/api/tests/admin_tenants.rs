//! テナント作成・管理 API の E2E 統合テスト（MT11、ADR-0009 §4・§5・§6）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_tenants
//!
//! 検証する保証（ADR-0009）:
//! - テナント作成は `idp.system.admin`（seed で root へ付与済み）のみ可能（§4）。権限が無ければ 403。
//! - 作成時に初期管理者ユーザーが自動生成され、`must_change_password = 1`・新テナント scope の
//!   `idp.tenant.admin` を保有する（§5）。
//! - `generated_password` はレスポンスに一度だけ平文で返り、監査ログには出さない（§5）。
//! - 作成された子テナントの管理者（`idp.tenant.admin`）はテナントを作成できない（§4。system.admin は
//!   root scope でしか存在できないため）。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use support::{body_json, create_sso_session, post as admin_post, send};

#[tokio::test]
async fn root_system_admin_can_create_tenant_with_generated_admin() {
    let Some(env) = support::setup("admin tenants").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenants_uri = format!("/{}/admin/tenants", env.root_tenant_id);

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(&tenants_uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "name": "Acme", "admin_email": "a@acme.example.com" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // system.admin による作成 → 201・generated_password を返す。
    let admin_email = format!(
        "owner-{}@acme.example.com",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &tenants_uri,
            json!({ "name": "Acme Inc", "admin_email": admin_email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create -> 201");
    let created = body_json(res).await;
    let new_tenant_id = created["id"].as_str().expect("tenant id").to_string();
    let new_admin_id = created["admin_user_id"]
        .as_str()
        .expect("admin id")
        .to_string();
    let generated = created["generated_password"]
        .as_str()
        .expect("password")
        .to_string();
    assert!(generated.len() >= 32, "generated password >= 32 chars");
    assert_eq!(
        created["parent_tenant_id"].as_str(),
        Some(env.root_tenant_id.as_str())
    );

    // 新テナントは root の子として実在し ACTIVE。
    let (parent, status): (Option<String>, String) =
        sqlx::query_as("SELECT parent_tenant_id, status FROM tenants WHERE id = ?")
            .bind(&new_tenant_id)
            .fetch_one(&env.pool)
            .await
            .expect("tenant row");
    assert_eq!(parent.as_deref(), Some(env.root_tenant_id.as_str()));
    assert_eq!(status, "ACTIVE");

    // 初期管理者は must_change_password = 1・所属元が新テナント。
    let (mcp, home): (bool, String) =
        sqlx::query_as("SELECT must_change_password, tenant_id FROM users WHERE id = ?")
            .bind(&new_admin_id)
            .fetch_one(&env.pool)
            .await
            .expect("admin user row");
    assert!(mcp, "generated admin must change password");
    assert_eq!(home, new_tenant_id);

    // 新テナント scope の idp.tenant.admin を保有する。
    let perm_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM user_permissions \
         WHERE user_id = ? AND permission_code = 'idp.tenant.admin' AND tenant_id = ?",
    )
    .bind(&new_admin_id)
    .bind(&new_tenant_id)
    .fetch_one(&env.pool)
    .await
    .expect("perm count")
    .get::<i64, _>("c");
    assert_eq!(
        perm_count, 1,
        "new admin holds idp.tenant.admin for the new tenant"
    );

    // 監査に tenant.created が記録され、生成パスワードは reason に含まれない（§5）。
    let leaked: i64 = sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE reason LIKE ?")
        .bind(format!("%{generated}%"))
        .fetch_one(&env.pool)
        .await
        .expect("audit scan")
        .get::<i64, _>("c");
    assert_eq!(leaked, 0, "generated password must not appear in audit log");
    let created_events: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'tenant.created' AND tenant_id = ?",
    )
    .bind(&new_tenant_id)
    .fetch_one(&env.pool)
    .await
    .expect("audit count")
    .get::<i64, _>("c");
    assert_eq!(created_events, 1, "tenant.created audit recorded");

    // 新テナントの管理者（idp.tenant.admin）はテナントを作成できない（§4。403）。
    let child_admin_cookie = create_sso_session(&env.pool, &new_admin_id).await;
    let res = send(
        &env.app,
        admin_post(
            &child_admin_cookie,
            &format!("/{new_tenant_id}/admin/tenants"),
            json!({ "name": "Sub", "admin_email": "x@sub.example.com" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant admin cannot create tenants (system.admin is root-scoped only)"
    );
}

/// テナント開通 unit of work（REF2）: 途中で失敗した場合、テナント・ユーザー・メンバーシップの
/// **どの行も残らない**（単一トランザクションで全ロールバック）。最終ステップの権限付与を
/// `permissions` マスタに無いコードで失敗させ、先行 3 INSERT が巻き戻ることを実 DB で検証する。
#[tokio::test]
async fn provisioning_rolls_back_all_rows_when_a_step_fails() {
    use idp_api::domain::repositories::TenantProvisioningRepository;
    use idp_api::domain::tenant::{Tenant, TenantId};
    use idp_api::domain::tenant_membership::TenantMembership;
    use idp_api::domain::user::User;
    use idp_api::domain::values::{TenantStatus, UserStatus};
    use idp_api::infrastructure::repositories::tenant_provisioning::SqlxTenantProvisioningRepository;

    let Some(env) = support::setup("admin tenants rollback").await else {
        return;
    };
    let now = chrono::Utc::now();
    let parent = TenantId::from(uuid::Uuid::parse_str(&env.root_tenant_id).unwrap());
    let tenant = Tenant {
        id: TenantId::from(uuid::Uuid::now_v7()),
        parent_tenant_id: Some(parent),
        name: "Rollback Probe".to_string(),
        status: TenantStatus::Active,
        self_registration_enabled: false,
        created_at: now,
        updated_at: now,
    };
    let admin = User {
        id: uuid::Uuid::now_v7(),
        tenant_id: tenant.id,
        sub: uuid::Uuid::now_v7(),
        email: "rollback@probe.example.com".to_string(),
        email_verified: false,
        preferred_username: None,
        name: None,
        language: None,
        password_hash: "unused-hash".to_string(),
        must_change_password: true,
        status: UserStatus::Active,
        failed_login_count: 0,
        locked_until: None,
        created_at: now,
        updated_at: now,
    };
    let membership = TenantMembership::new_home(tenant.id, admin.id, now);

    let provisioning = SqlxTenantProvisioningRepository::new(env.pool.clone());
    let result = provisioning
        .provision(
            &tenant,
            &admin,
            &membership,
            "idp.no.such.permission", // permissions マスタに無いコード → FK 違反で最終 INSERT が失敗
            now,
        )
        .await;
    assert!(result.is_err(), "unknown permission code must fail");

    // 先行して INSERT したテナント・ユーザー・メンバーシップも一切残らない（全ロールバック）。
    let tenant_rows: i64 = sqlx::query("SELECT COUNT(*) AS c FROM tenants WHERE id = ?")
        .bind(tenant.id.as_uuid().to_string())
        .fetch_one(&env.pool)
        .await
        .expect("tenant count")
        .get::<i64, _>("c");
    assert_eq!(tenant_rows, 0, "tenant row rolled back");
    let user_rows: i64 = sqlx::query("SELECT COUNT(*) AS c FROM users WHERE id = ?")
        .bind(admin.id.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("user count")
        .get::<i64, _>("c");
    assert_eq!(user_rows, 0, "admin user row rolled back");
    let membership_rows: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM tenant_memberships WHERE user_id = ?")
            .bind(admin.id.to_string())
            .fetch_one(&env.pool)
            .await
            .expect("membership count")
            .get::<i64, _>("c");
    assert_eq!(membership_rows, 0, "membership row rolled back");
}
