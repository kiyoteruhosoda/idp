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

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Request, StatusCode};
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::infrastructure::crypto;
use idp_api::presentation::router;
use idp_api::presentation::state::AppState;
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

struct TestEnv {
    app: axum::Router,
    pool: MySqlPool,
    root_tenant_id: String,
    admin_id: String,
}

async fn setup() -> Option<TestEnv> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping admin tenants integration test");
        return None;
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let root_tenant_id: String =
        sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("root tenant seeded");
    let admin_id: String = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = ? AND email = 'admin@example.com'",
    )
    .bind(&root_tenant_id)
    .fetch_one(&pool)
    .await
    .expect("initial admin seeded");

    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    Some(TestEnv {
        app: router::build(state),
        pool,
        root_tenant_id,
        admin_id,
    })
}

async fn create_sso_session(pool: &MySqlPool, user_id: &str) -> String {
    let session_id = crypto::random_hex(32);
    let session_hash = crypto::sha256_hex(&session_id);
    sqlx::query(
        "INSERT INTO sso_sessions \
         (session_hash, user_id, auth_time, idle_expires_at, absolute_expires_at) \
         VALUES (?, ?, UTC_TIMESTAMP(6), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 HOUR), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 8 HOUR))",
    )
    .bind(&session_hash)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert sso session");
    session_id
}

async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn admin_post(cookie: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn root_system_admin_can_create_tenant_with_generated_admin() {
    let Some(env) = setup().await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.admin_id).await;
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
    let admin_email = format!("owner-{}@acme.example.com", &uuid::Uuid::new_v4().simple().to_string()[..8]);
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
    let new_admin_id = created["admin_user_id"].as_str().expect("admin id").to_string();
    let generated = created["generated_password"].as_str().expect("password").to_string();
    assert!(generated.len() >= 32, "generated password >= 32 chars");
    assert_eq!(created["parent_tenant_id"].as_str(), Some(env.root_tenant_id.as_str()));

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
    assert_eq!(perm_count, 1, "new admin holds idp.tenant.admin for the new tenant");

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
