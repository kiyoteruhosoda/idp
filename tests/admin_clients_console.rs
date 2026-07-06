//! クライアント（RP）管理画面（A1）の E2E 統合テスト。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_clients_console
//!
//! 画面は `/admin/console/clients*`（JSON API `/admin/clients*` とは経路を分離）。初期管理者
//! （seed 0002 + 0004 で idp.admin 付与済み）の SSO セッションを直接作成し、その Cookie で画面を操作する。
//! CSRF は SSO セッション id 由来の同期トークン（sha256("console-csrf:" + sso_session_id)）。

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION};
use axum::http::{Request, StatusCode};
use idp::config::Config;
use idp::domain::clock::Clock;
use idp::infrastructure::crypto;
use idp::presentation::router;
use idp::presentation::state::AppState;
use serde_json::Value;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
static MIGRATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

const ADMIN_ID: &str = "00000000-0000-0000-0000-000000000001";
const REDIRECT_URI: &str = "https://app.example.com/callback";

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
        eprintln!("TEST_DATABASE_URL not set; skipping admin clients console integration test");
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

fn console_csrf(sso: &str) -> String {
    crypto::sha256_hex(&format!("console-csrf:{sso}"))
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

fn form_post(cookie: &str, uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::from(body))
        .unwrap()
}

fn get_authed(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::empty())
        .unwrap()
}

/// JSON 管理 API から最新のクライアント一覧を取り出す（画面が作成した client_id を掴むため）。
async fn list_clients_json(app: &axum::Router, cookie: &str) -> Vec<Value> {
    let res = send(app, get_authed(cookie, "/admin/clients")).await;
    let text = body_text(res).await;
    serde_json::from_str::<Vec<Value>>(&text).unwrap_or_default()
}

#[tokio::test]
async fn admin_manages_clients_through_console_screens() {
    let Some(env) = setup().await else {
        return;
    };
    let cookie = create_sso_session(&env.pool, ADMIN_ID).await;
    let csrf = console_csrf(&cookie);

    // 未認証で一覧 → ログイン画面へ 302。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console/clients")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers().get(LOCATION).unwrap(), "/admin/console/login");

    // 一覧（認証済み）→ 200。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/clients")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("Clients"));

    // 新規登録フォーム → 200・CSRF トークン埋め込み。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/clients/new")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains(&csrf));

    // CSRF 不一致で作成 → 400。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            "/admin/console/clients/new",
            format!("app_name=Bad&client_type=public&redirect_uris={REDIRECT_URI}&scopes=openid&csrf_token=wrong"),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "csrf mismatch -> 400"
    );

    // 不正な scope（openid 無し）→ 400・フォーム再表示。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            "/admin/console/clients/new",
            format!("app_name=Bad&client_type=public&redirect_uris={REDIRECT_URI}&scopes=email&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "invalid scope -> 400"
    );

    // confidential クライアント作成 → 200・secret を一度だけ表示。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            "/admin/console/clients/new",
            format!("app_name=Console App&client_type=confidential&redirect_uris={REDIRECT_URI}&scopes=openid%20profile&require_pkce=on&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create -> 200");
    let created = body_text(res).await;
    assert!(created.contains("Client secret"), "shows secret once");
    assert!(created.contains("Console App") || created.contains("registered"));

    // 作成した client_id を JSON API から取得。
    let clients = list_clients_json(&env.app, &cookie).await;
    let client = clients
        .iter()
        .find(|c| c["app_name"] == "Console App")
        .expect("created client present");
    let client_id = client["client_id"].as_str().unwrap().to_string();
    assert_eq!(client["client_type"], "confidential");

    // 詳細 → 200・app_name 表示。
    let res = send(
        &env.app,
        get_authed(&cookie, &format!("/admin/console/clients/{client_id}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("Console App"));

    // 編集で DISABLED に → 302 詳細へ。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("/admin/console/clients/{client_id}/edit"),
            format!("app_name=Console App&redirect_uris={REDIRECT_URI}&scopes=openid&client_status=DISABLED&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND, "update -> 302");
    assert_eq!(
        res.headers().get(LOCATION).unwrap(),
        &format!("/admin/console/clients/{client_id}")
    );

    // 詳細で DISABLED を確認。
    let res = send(
        &env.app,
        get_authed(&cookie, &format!("/admin/console/clients/{client_id}")),
    )
    .await;
    assert!(body_text(res).await.contains("DISABLED"));

    // secret 再発行 → 200・新しい secret 表示。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("/admin/console/clients/{client_id}/rotate-secret"),
            format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "rotate -> 200");
    assert!(body_text(res).await.contains("Client secret"));

    // 不存在の詳細 → 404。
    let res = send(
        &env.app,
        get_authed(&cookie, "/admin/console/clients/does-not-exist"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn non_admin_is_forbidden_on_console_clients() {
    let Some(env) = setup().await else {
        return;
    };
    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&user_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(format!("plain-{}@example.com", &user_id[..8]))
    .execute(&env.pool)
    .await
    .expect("insert plain user");
    let cookie = create_sso_session(&env.pool, &user_id).await;

    // 権限の無い利用者 → 403 HTML（未認証の 302 とは区別）。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/clients")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
