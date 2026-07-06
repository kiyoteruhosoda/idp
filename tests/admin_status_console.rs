//! 状況確認画面（A3）の E2E 統合テスト。監査／ログインログ一覧・クライアント状況一覧。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_status_console
//!
//! 画面は `/admin/console/audit-logs`・`/admin/console/status`（JSON API `/admin/audit-logs` とは経路を
//! 分離）。初期管理者（seed 0002 + 0004 で idp.admin 付与済み）の SSO セッションを直接作成し、その
//! Cookie で画面を開く。読み取り専用のため CSRF は無い。

use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION};
use axum::http::{Request, StatusCode};
use idp::config::Config;
use idp::domain::clock::Clock;
use idp::infrastructure::crypto;
use idp::presentation::router;
use idp::presentation::state::AppState;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
static MIGRATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

const ADMIN_ID: &str = "00000000-0000-0000-0000-000000000001";

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

struct TestEnv {
    app: axum::Router,
    pool: MySqlPool,
}

async fn setup() -> Option<TestEnv> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping admin status console integration test");
        return None;
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    {
        let _guard = MIGRATE_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        MIGRATOR.run(&pool).await.expect("run migrations");
    }
    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    Some(TestEnv {
        app: router::build(state),
        pool,
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

/// クライアントを 1 件登録し、public な client_id を返す。
async fn create_client(pool: &MySqlPool, client_id: &str, app_name: &str) {
    sqlx::query(
        "INSERT INTO clients \
         (id, client_id, client_type, client_status, app_name, redirect_uris, grant_types, \
          response_types, scopes, token_endpoint_auth_method, require_pkce) \
         VALUES (?, ?, 'public', 'ACTIVE', ?, \
                 '[\"https://a.example.com/cb\"]', '[\"authorization_code\"]', \
                 '[\"code\"]', '[\"openid\"]', 'none', 1)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(client_id)
    .bind(app_name)
    .execute(pool)
    .await
    .expect("insert client");
}

/// 成功したトークン発行の監査ログを 1 件入れる（最終利用時刻の導出用）。
async fn insert_token_issued(pool: &MySqlPool, client_id: &str) {
    sqlx::query(
        "INSERT INTO audit_log (event_type, occurred_at, client_id, result, correlation_id) \
         VALUES ('token.issued', UTC_TIMESTAMP(6), ?, 'success', ?)",
    )
    .bind(client_id)
    .bind(crypto::random_hex(8))
    .execute(pool)
    .await
    .expect("insert audit log");
}

async fn create_plain_user(pool: &MySqlPool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(format!("plain-{}@example.com", &id[..8]))
    .execute(pool)
    .await
    .expect("insert plain user");
    id
}

async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn get_authed(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn admin_views_client_status_and_audit_logs() {
    let Some(env) = setup().await else {
        return;
    };
    let cookie = create_sso_session(&env.pool, ADMIN_ID).await;
    let client_id = format!("status-client-{}", &crypto::random_hex(4));
    create_client(&env.pool, &client_id, "Status Console App").await;
    insert_token_issued(&env.pool, &client_id).await;

    // 未認証で状況一覧 → ログイン画面へ 302。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console/status")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers().get(LOCATION).unwrap(), "/admin/console/login");

    // クライアント状況一覧 → 200・登録クライアントと最終利用時刻（token.issued 由来）を表示。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/status")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains("Status Console App"), "client shown");
    assert!(text.contains(&client_id));
    // 利用実績があるので「-」ではなく日時（年）が入る。
    assert!(text.contains("T"), "last-used timestamp rendered");

    // 監査ログ一覧 → 200・token.issued 行が見える。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/audit-logs")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains("token.issued"), "audit row shown");
    assert!(text.contains(&client_id));

    // result=failure で絞り込む → success の token.issued 行は出ない。
    let res = send(
        &env.app,
        get_authed(&cookie, "/admin/console/audit-logs?result=failure"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(!text.contains(&client_id), "success rows filtered out");

    // 不正な from 日時 → 200・エラー表示（検索は実行しない）。
    let res = send(
        &env.app,
        get_authed(&cookie, "/admin/console/audit-logs?from=not-a-date"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("Invalid date-time"));
}

#[tokio::test]
async fn non_admin_is_forbidden_on_status_screens() {
    let Some(env) = setup().await else {
        return;
    };
    let user_id = create_plain_user(&env.pool).await;
    let cookie = create_sso_session(&env.pool, &user_id).await;

    let res = send(&env.app, get_authed(&cookie, "/admin/console/status")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = send(&env.app, get_authed(&cookie, "/admin/console/audit-logs")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
