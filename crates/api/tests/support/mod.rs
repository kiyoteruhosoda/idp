//! 統合テストの共通支援モジュール（REF1）。
//!
//! 各テストバイナリは `mod support;` で取り込む（cargo は `tests/` 直下の `.rs` のみを
//! テストバイナリとしてビルドし、サブディレクトリはモジュールとして共有できる）。
//!
//! ここに集約しているもの:
//! - DB 接続・マイグレーション・署名鍵ブートストラップ（いずれもプロセス内で一度だけ。
//!   新規 DB へ複数テストの setup が並走したときの seed 競合・ACTIVE 鍵の複数本化を防ぐ）
//! - `AppState` / ルータの組み立て（`TestEnv`）
//! - SSO セッション・利用者・クライアントのテストデータ生成
//! - リクエストビルダとレスポンス読み取り
#![allow(dead_code)]

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Method, Request};
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::domain::password::PasswordHasher as _;
use idp_api::infrastructure::crypto;
use idp_api::infrastructure::password::Argon2PasswordHasher;
use idp_api::presentation::router;
use idp_api::presentation::state::AppState;
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// マイグレーションはプロセス内で一度だけ実行する（seed INSERT の並走競合を防ぐ）。
static MIGRATIONS: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// 署名鍵ブートストラップもプロセス内で一度だけ行う（`insert_if_no_active` が排他だとしても、
/// テスト毎に呼ぶ必要はない）。
static KEY_BOOTSTRAP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// 内部認証エンドポイント（`/internal/*`）のサービストークン（ADR-0007 §5）。
/// `setup()` が `INTERNAL_SERVICE_TOKEN` へ固定注入する。
pub const SERVICE_TOKEN: &str = "test-internal-service-token";
pub const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

// RFC 7636 Appendix B のテストベクタ（S256）。
pub const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";
pub const REDIRECT_URI_ENC: &str = "http%3A%2F%2Flocalhost%3A3000%2Fcallback";

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// 組み立て済みのテスト環境。
pub struct TestEnv {
    pub app: axum::Router,
    pub pool: MySqlPool,
    /// 基底 issuer（`config.issuer()`）。per-tenant issuer は `<issuer>/<tenant_id>`。
    pub issuer: String,
    /// seed 済み root テナントの UUID（動的採番のため DB から引く）。
    pub root_tenant_id: String,
    /// seed の初期管理者（root 所属・idp.system.admin 保有）の内部 ID。
    pub root_admin_id: String,
    /// LoginService が検証に使う CSRF HMAC 鍵（CI の `CSRF_SECRET` 上書きに追従）。
    pub csrf_secret: [u8; 32],
}

/// `TEST_DATABASE_URL` の DB へ接続し、マイグレーションをプロセス内で一度だけ適用する。
/// 既定では未設定を失敗にする（CI/--check で DB テストをスキップ不能にする）。
/// ローカルで意図的に DB 統合テストだけを省略する場合のみ `IDP_ALLOW_DB_TEST_SKIP=1` を指定する。
pub async fn connect_pool(test_name: &str) -> Option<MySqlPool> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        if std::env::var("IDP_ALLOW_DB_TEST_SKIP").ok().as_deref() == Some("1") {
            eprintln!(
                "TEST_DATABASE_URL not set; intentionally skipping {test_name} integration test"
            );
            return None;
        }
        panic!("TEST_DATABASE_URL is required for {test_name} integration test; set IDP_ALLOW_DB_TEST_SKIP=1 only for local unit-only runs");
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATIONS
        .get_or_init(|| async {
            MIGRATOR.run(&pool).await.expect("run migrations");
        })
        .await;
    Some(pool)
}

/// アプリ全体（AppState + ルータ）を組み立てる。署名鍵はプロセス内で一度だけブートストラップする。
pub async fn setup(test_name: &str) -> Option<TestEnv> {
    // 内部認証エンドポイントのサービストークンを既知値に固定する（/internal/* を使うテスト向け）。
    std::env::set_var("INTERNAL_SERVICE_TOKEN", SERVICE_TOKEN);
    let pool = connect_pool(test_name).await?;

    let root_tenant_id: String =
        sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("root tenant seeded");
    let root_admin_id: String = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = ? AND email = 'admin@example.com'",
    )
    .bind(&root_tenant_id)
    .fetch_one(&pool)
    .await
    .expect("initial admin seeded");

    // 自己登録は既定 OFF（SEC6）。register を使うテストフローが動くよう root テナントでは有効化する
    // （無効時の挙動は register テストが明示的に OFF へ切り替えて検証する）。
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&root_tenant_id)
        .execute(&pool)
        .await
        .expect("enable self-registration for root tenant");

    let config = Arc::new(Config::from_env().expect("load config"));
    let issuer = config.issuer().to_string();
    let csrf_secret = *config.csrf_secret();
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    KEY_BOOTSTRAP
        .get_or_init(|| async {
            state
                .keys
                .ensure_active_key()
                .await
                .expect("bootstrap signing key");
        })
        .await;
    Some(TestEnv {
        app: router::build(state),
        pool,
        issuer,
        root_tenant_id,
        root_admin_id,
        csrf_secret,
    })
}

/// 登録 API で作った利用者をメール検証済みにする。
/// OIDC / internal auth の既存フロー検証ではメール検証ゲートではなく同意・CSRF・token 発行を検証したいため、
/// テストデータだけ明示的に検証済みに寄せる。
pub async fn mark_email_verified(pool: &MySqlPool, tenant_id: &str, username: &str) {
    let result = sqlx::query(
        "UPDATE users SET email_verified = 1 WHERE tenant_id = ? AND preferred_username = ?",
    )
    .bind(tenant_id)
    .bind(username)
    .execute(pool)
    .await
    .expect("mark email verified");
    assert_eq!(
        result.rows_affected(),
        1,
        "mark one registered user verified"
    );
}

// ── テストデータ生成 ─────────────────────────────────────────────────────────

/// 指定ユーザーの有効な SSO セッションを作成し、Cookie 用の平文 session_id を返す。
pub async fn create_sso_session(pool: &MySqlPool, user_id: &str) -> String {
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

/// 権限を持たない利用者を指定テナントへ直接作成し、その内部 ID を返す。
pub async fn create_plain_user(pool: &MySqlPool, tenant_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("plain-{}@example.com", unique()))
    .execute(pool)
    .await
    .expect("insert plain user");
    // 実運用のユーザー作成と同様に HOME メンバーシップ（ACTIVE）も投影する。権限の付与・剥奪は
    // 当該テナントの ACTIVE メンバーであることを要求する（ADR-0009 §4）ため、これが無いと 404 になる。
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'HOME', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert home membership");
    id
}

/// 一意な public client を指定テナントへ直接登録して client_id を返す。
/// `scopes` は許可 scope（例: `&["openid"]`、`&["openid", "profile", "email"]`）。
pub async fn insert_public_client(pool: &MySqlPool, tenant_id: &str, scopes: &[&str]) -> String {
    let client_id = format!("it-public-{}", unique());
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method, require_pkce) \
         VALUES (?, ?, ?, NULL, 'public', 'ACTIVE', 'Integration Test App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'none', 1)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .execute(pool)
    .await
    .expect("insert public client");
    client_id
}

/// 一意な confidential client を指定テナントへ直接登録して `(client_id, client_secret)` を返す。
pub async fn insert_confidential_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String) {
    let client_id = format!("it-conf-{}", unique());
    let secret = "e2e-super-secret-value";
    let secret_hash = Argon2PasswordHasher::new()
        .hash(secret)
        .expect("hash secret");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method, require_pkce) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration Confidential App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'client_secret_basic', 1)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .execute(pool)
    .await
    .expect("insert confidential client");
    (client_id, secret.to_string())
}

/// ランダムな識別子片（メール・名前の一意化に使う。12 文字の hex）。
pub fn unique() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

// ── リクエスト・レスポンスヘルパー ───────────────────────────────────────────

pub async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

pub async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// SSO Cookie 付きのリクエストを組み立てる（JSON ボディは `Some` のときのみ付与）。
pub fn request(method: Method, cookie: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"));
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

pub fn get(cookie: &str, uri: &str) -> Request<Body> {
    request(Method::GET, cookie, uri, None)
}

pub fn post(cookie: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::POST, cookie, uri, Some(body))
}

pub fn patch(cookie: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::PATCH, cookie, uri, Some(body))
}

pub fn put(cookie: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::PUT, cookie, uri, Some(body))
}

pub fn delete(cookie: &str, uri: &str) -> Request<Body> {
    request(Method::DELETE, cookie, uri, None)
}

/// Cookie 無し・SSO 不要のリクエスト（未認証 401 の検証等に使う）。
pub fn anonymous(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

/// `/internal/*` への POST（サービストークンは `Some` のときのみ付与）。
pub fn post_internal(uri: &str, token: Option<&str>, payload: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::from(payload.to_string())).unwrap()
}

/// `Set-Cookie` ヘッダ群から `name` の値を取り出す。
pub fn cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response.headers().get_all(SET_COOKIE).iter().find_map(|v| {
        let raw = v.to_str().ok()?;
        let (k, rest) = raw.split_once('=')?;
        (k == name).then(|| rest.split(';').next().unwrap_or("").to_string())
    })
}

pub fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string()
}

pub fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .expect("parse redirect URL")
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// `openid` のみの scope（同意ステップ不要）で認可リクエスト URI を組み立てる。
pub fn authorize_uri_openid_only(tenant: &str, client_id: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
}

/// 認可コードをトークンへ交換する（public client・PKCE）。
pub async fn exchange_code(
    app: &axum::Router,
    tenant: &str,
    client_id: &str,
    code: &str,
) -> axum::response::Response {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}&client_id={client_id}"
            )))
            .unwrap(),
    )
    .await
}
