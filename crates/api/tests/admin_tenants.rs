//! テナント作成・管理 API の E2E 統合テスト（MT11、ADR-0009 §4・§5・§6）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_tenants
//!
//! 検証する保証（ADR-0009）:
//! - テナント作成は `idp.system.admin`（seed で root へ付与済み）のみ可能（§4）。権限が無ければ 403。
//! - 作成時に**作成者自身**が新テナントのブートストラップ管理者になる: 新テナント scope の
//!   ACTIVE な GUEST メンバーシップと `idp.tenant.admin` を保有する（§4）。初期管理者ユーザーは
//!   自動生成されず、平文パスワードも返らない。
//! - 作成者は新テナントの管理 API を操作できる（自身の SSO セッションのまま）。
//! - 新テナント scope に `idp.system.admin` は存在しないため、作成者でもそこからは子テナントを
//!   作成できない（§4。system.admin は root scope でしか存在できない）。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use support::{body_json, create_sso_session, get as send_get, post as admin_post, send};

#[tokio::test]
async fn root_system_admin_creates_tenant_and_becomes_bootstrap_admin() {
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
            .body(Body::from(json!({ "name": "Acme" }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // system.admin による作成 → 201・作成したテナントを返す（平文パスワードは返さない）。
    let res = send(
        &env.app,
        admin_post(&admin_cookie, &tenants_uri, json!({ "name": "Acme Inc" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create -> 201");
    let created = body_json(res).await;
    let new_tenant_id = created["id"].as_str().expect("tenant id").to_string();
    assert!(
        created.get("generated_password").is_none(),
        "no plaintext password is returned in the new flow"
    );
    assert!(
        created.get("admin_user_id").is_none(),
        "no separate admin user is minted"
    );
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

    // 作成者（root 管理者）が新テナントの ACTIVE な GUEST メンバーシップを持つ。
    let (mtype, mstatus): (String, String) = sqlx::query_as(
        "SELECT membership_type, status FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(&new_tenant_id)
    .bind(&env.root_admin_id)
    .fetch_one(&env.pool)
    .await
    .expect("bootstrap membership row");
    assert_eq!((mtype.as_str(), mstatus.as_str()), ("GUEST", "ACTIVE"));

    // 作成者が新テナント scope の idp.tenant.admin を保有する。
    let perm_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM user_permissions \
         WHERE user_id = ? AND permission_code = 'idp.tenant.admin' AND tenant_id = ?",
    )
    .bind(&env.root_admin_id)
    .bind(&new_tenant_id)
    .fetch_one(&env.pool)
    .await
    .expect("perm count")
    .get::<i64, _>("c");
    assert_eq!(
        perm_count, 1,
        "creator holds idp.tenant.admin for the new tenant"
    );

    // 監査に tenant.created が記録される。
    let created_events: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'tenant.created' AND tenant_id = ?",
    )
    .bind(&new_tenant_id)
    .fetch_one(&env.pool)
    .await
    .expect("audit count")
    .get::<i64, _>("c");
    assert_eq!(created_events, 1, "tenant.created audit recorded");

    // 作成者は新テナントの管理 API を操作できる（ブートストラップ管理者。自身の SSO セッションのまま）。
    let res = send(
        &env.app,
        send_get(&admin_cookie, &format!("/{new_tenant_id}/admin/members")),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "creator can operate the new tenant as bootstrap admin"
    );

    // ただし新テナント scope に idp.system.admin は存在しないため、そこからは子テナントを作れない
    // （§4。system.admin は root scope でしか存在できない）。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &format!("/{new_tenant_id}/admin/tenants"),
            json!({ "name": "Sub" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant.admin cannot create tenants from a non-root scope (system.admin is root-scoped only)"
    );
}

/// テナント開通 unit of work（REF2）: 途中で失敗した場合、テナント・メンバーシップの
/// **どの行も残らない**（単一トランザクションで全ロールバック）。最終ステップの権限付与を
/// `permissions` マスタに無いコードで失敗させ、先行 2 INSERT が巻き戻ることを実 DB で検証する。
#[tokio::test]
async fn provisioning_rolls_back_all_rows_when_a_step_fails() {
    use idp_api::domain::repositories::TenantProvisioningRepository;
    use idp_api::domain::tenant::{Tenant, TenantId};
    use idp_api::domain::tenant_membership::TenantMembership;
    use idp_api::domain::values::TenantStatus;
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
    // 作成者（既存の root 管理者）を新テナントのブートストラップ管理者にする想定のメンバーシップ。
    let creator = uuid::Uuid::parse_str(&env.root_admin_id).unwrap();
    let membership = TenantMembership::new_active_guest(tenant.id, creator, now);

    let provisioning = SqlxTenantProvisioningRepository::new(env.pool.clone());
    let result = provisioning
        .provision(
            &tenant,
            &membership,
            "idp.no.such.permission", // permissions マスタに無いコード → FK 違反で最終 INSERT が失敗
            now,
        )
        .await;
    assert!(result.is_err(), "unknown permission code must fail");

    // 先行して INSERT したテナント・メンバーシップも一切残らない（全ロールバック）。
    let tenant_rows: i64 = sqlx::query("SELECT COUNT(*) AS c FROM tenants WHERE id = ?")
        .bind(tenant.id.as_uuid().to_string())
        .fetch_one(&env.pool)
        .await
        .expect("tenant count")
        .get::<i64, _>("c");
    assert_eq!(tenant_rows, 0, "tenant row rolled back");
    let membership_rows: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(tenant.id.as_uuid().to_string())
    .bind(creator.to_string())
    .fetch_one(&env.pool)
    .await
    .expect("membership count")
    .get::<i64, _>("c");
    assert_eq!(membership_rows, 0, "membership row rolled back");
}
