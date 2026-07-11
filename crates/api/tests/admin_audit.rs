//! 監査ログ参照 API の E2E 統合テスト（Progress A3、設計仕様 §7）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_audit
//!
//! 初期管理者の SSO セッションを直接作成し、クライアント登録で監査イベント（client.registered）を
//! 発生させてから、`/admin/audit-logs` の絞り込みで取得できること・権限制御を検証する。

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
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const REDIRECT_URI: &str = "https://app.example.com/callback";

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

async fn setup() -> Option<(axum::Router, MySqlPool, String, String)> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping admin audit integration test");
        return None;
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    // 過渡期（MT9 まで）: seed 済み root テナントを既定テナントとして注入する。
    // 初期管理者の UUID は動的採番のため DB から引く。
    let root_tenant_id: String =
        sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("root tenant seeded");
    let admin_id: String =
        sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = ? AND email = 'admin@example.com'")
            .bind(&root_tenant_id)
            .fetch_one(&pool)
            .await
            .expect("initial admin seeded");
    let root = idp_api::domain::tenant::TenantId::from(
        uuid::Uuid::parse_str(&root_tenant_id).expect("root UUID"),
    );

    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock), root);
    Some((router::build(state), pool, root_tenant_id, admin_id))
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

fn get_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn admin_can_query_audit_logs_with_filters() {
    let Some((app, pool, root_tenant_id, admin_id)) = setup().await else {
        return;
    };
    let admin_cookie = create_sso_session(&pool, &admin_id).await;

    // 監査イベントを発生させる: クライアント登録（client.registered / result=success）。
    let res = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/admin/clients"))
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::from(
                json!({
                    "app_name": "Audit Probe",
                    "client_type": "public",
                    "redirect_uris": [REDIRECT_URI],
                    "scopes": ["openid"],
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    // event_type で絞り込み → 少なくとも 1 件、登録した client_id を含む。
    let res = send(
        &app,
        get_with_cookie(
            &format!("/{root_tenant_id}/admin/audit-logs?event_type=client.registered"),
            &admin_cookie,
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let logs = body_json(res).await;
    let arr = logs.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "expected at least one client.registered log"
    );
    assert!(arr.iter().all(|e| e["event_type"] == "client.registered"));
    assert!(
        arr.iter()
            .any(|e| e["client_id"] == created_client_id.as_str()),
        "logs should include the newly registered client_id"
    );
    // 監査行には処理テナント（root）が記録される（ADR-0009 §8）。
    let recorded_tenant: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM audit_log WHERE client_id = ? AND event_type = 'client.registered' \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(&created_client_id)
    .fetch_one(&pool)
    .await
    .expect("query audit tenant_id");
    assert_eq!(recorded_tenant.as_deref(), Some(root_tenant_id.as_str()));
    // occurred_at 降順（新しい順）で返る。
    let times: Vec<&str> = arr
        .iter()
        .map(|e| e["occurred_at"].as_str().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted, "results must be newest-first");

    // result=failure の絞り込みは client.registered を含まない。
    let res = send(
        &app,
        get_with_cookie(
            &format!("/{root_tenant_id}/admin/audit-logs?event_type=client.registered&result=failure"),
            &admin_cookie,
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_json(res).await.as_array().unwrap().is_empty());

    // from の形式不正 → 400。
    let res = send(
        &app,
        get_with_cookie(&format!("/{root_tenant_id}/admin/audit-logs?from=not-a-date"), &admin_cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 未認証 → 401。
    let res = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/{root_tenant_id}/admin/audit-logs"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 権限の無い利用者 → 403。
    let plain_user_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&plain_user_id)
    .bind(&root_tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!(
        "audit-plain-{}@example.com",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ))
    .execute(&pool)
    .await
    .expect("insert plain user");
    let plain_cookie = create_sso_session(&pool, &plain_user_id).await;
    let res = send(&app, get_with_cookie(&format!("/{root_tenant_id}/admin/audit-logs"), &plain_cookie)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
