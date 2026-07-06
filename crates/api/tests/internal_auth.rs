//! 内部認証 API（`/internal/authenticate*`、ADR-0007 §3・§5）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test internal_auth
//!
//! web（将来）→api のサービス間 I/F を検証する。web は資格情報・auth_session 参照・接続元情報を
//! JSON で転送し、api は SSO/code を発行して `result` タグ付き JSON を返す。サービス認証トークン
//! （`X-Internal-Auth-Token`）が無ければ 401 で遮断される。

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use idp_api::application::login::csrf_token;
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::presentation::router;
use idp_api::presentation::state::AppState;
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT_URI: &str = "http://localhost:3000/callback";
const SERVICE_TOKEN: &str = "test-internal-service-token";
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

async fn setup() -> Option<(axum::Router, MySqlPool)> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping internal_auth integration test");
        return None;
    };
    // 内部サービストークンを既知値に固定する（このテストが唯一 /internal/* を使う）。
    std::env::set_var("INTERNAL_SERVICE_TOKEN", SERVICE_TOKEN);

    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    state
        .keys
        .ensure_active_key()
        .await
        .expect("bootstrap signing key");
    Some((router::build(state), pool))
}

async fn insert_public_client(pool: &MySqlPool) -> String {
    let client_id = format!(
        "int-public-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    sqlx::query(
        "INSERT INTO clients (id, client_id, client_secret_hash, client_type, client_status, \
         app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method, require_pkce) \
         VALUES (?, ?, NULL, 'public', 'ACTIVE', 'Internal Auth Test App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', '[\"openid\",\"profile\",\"email\"]', 'none', 1)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&client_id)
    .bind(json!([REDIRECT_URI]).to_string())
    .execute(pool)
    .await
    .expect("insert public client");
    client_id
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

fn cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let raw = v.to_str().ok()?;
            let (k, rest) = raw.split_once('=')?;
            (k == name).then(|| rest.split(';').next().unwrap_or("").to_string())
        })
}

async fn register_user(app: &axum::Router, username: &str, password: &str) {
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
        "name": "Internal Auth Tester",
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// `/authorize` を開始して `auth_session_id` Cookie を得る（未ログインなので /login へ 302）。
async fn start_authorize(app: &axum::Router, client_id: &str) -> String {
    let uri = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20profile%20email&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
        "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
    );
    let response = send(app, Request::builder().uri(uri).body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::FOUND, "authorize -> login");
    cookie_value(&response, "auth_session_id").expect("auth_session_id cookie")
}

fn post_internal(uri: &str, token: Option<&str>, payload: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::from(payload.to_string())).unwrap()
}

#[tokio::test]
async fn authenticate_requires_service_token_and_issues_sso_and_code() {
    let Some((app, pool)) = setup().await else {
        return;
    };

    let client_id = insert_public_client(&pool).await;
    let username = format!("int{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    register_user(&app, &username, password).await;

    // サービストークンが無ければ 401（本文まで到達しない）。
    let auth_session = start_authorize(&app, &client_id).await;
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            None,
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "missing token");

    // 誤ったトークンも 401。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some("wrong-token"),
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token");

    // CSRF 不一致（正しいトークンだが csrf が違う）→ result=csrf_mismatch。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": "0".repeat(64),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "csrf_mismatch");

    // 正常系: 認証成功 → SSO セッション id と code 付き redirect を返す。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session),
                "ip_address": "203.0.113.7",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authenticate success");
    let body = body_json(response).await;
    assert_eq!(body["result"], "success");
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .starts_with(REDIRECT_URI),
        "redirect_to should point at the RP: {body}"
    );
    assert!(!body["sso_session_id"].as_str().unwrap().is_empty());
    assert!(body["sso_absolute_ttl_secs"].as_u64().unwrap() > 0);

    // SSO セッションが DB に作成され、web から転送された接続元 IP が記録されている
    // （並行する他テストと干渉しないよう、この試行に固有の IP で絞り込む）。
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE ip_address = ?")
            .bind("203.0.113.7")
            .fetch_one(&pool)
            .await
            .expect("query sso_sessions");
    assert!(count >= 1, "an SSO session recorded with the forwarded IP");
}

#[tokio::test]
async fn admin_authenticate_rejects_unknown_user() {
    let Some((app, _pool)) = setup().await else {
        return;
    };

    // 認証情報が誤り（未登録ユーザー）→ result=invalid_credentials。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            Some(SERVICE_TOKEN),
            json!({
                "username": format!("nobody-{}", uuid::Uuid::new_v4()),
                "password": "whatever",
                "ip_address": "203.0.113.9",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "invalid_credentials");

    // サービストークンが無ければ 401。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            None,
            json!({ "username": "x", "password": "y" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
