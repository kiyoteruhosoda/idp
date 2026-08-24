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
use base64::{engine::general_purpose::STANDARD, Engine as _};
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
// 32 文字以上（`idp_contracts::deployment::INTERNAL_SERVICE_TOKEN_MIN_LEN`）。SEC11。
pub const SERVICE_TOKEN: &str = "test-internal-service-token-0123456789";
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
    /// web 画面の公開ベース URL（`config.public_web_base_url()`）。`/authorize` のログイン・同意
    /// リダイレクトは ADR-0012 §4 でこの絶対 URL 基点になった（既定は issuer と同一オリジン）。
    pub public_web_base_url: String,
    /// seed 済み root テナントの UUID（固定値だが構造 `parent_tenant_id IS NULL` で DB から引く）。
    pub root_tenant_id: String,
    /// seed の初期管理者（root 所属・idp.system.admin 保有）の内部 ID。
    pub root_admin_id: String,
    /// LoginService が検証に使う CSRF HMAC 鍵（CI の `CSRF_SECRET` 上書きに追従）。
    pub csrf_secret: [u8; 32],
}

/// テストプールの既定接続上限（sqlx の既定値と同じ）。並走数がこれを超えるテストは
/// `connect_pool_with_max_connections` で枠を明示する。
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 10;

/// `TEST_DATABASE_URL` の DB へ接続し、マイグレーションをプロセス内で一度だけ適用する。
/// 既定では未設定を失敗にする（CI/--check で DB テストをスキップ不能にする）。
/// ローカルで意図的に DB 統合テストだけを省略する場合のみ `IDP_ALLOW_DB_TEST_SKIP=1` を指定する。
pub async fn connect_pool(test_name: &str) -> Option<MySqlPool> {
    connect_pool_with_max_connections(test_name, DEFAULT_POOL_MAX_CONNECTIONS).await
}

/// DB を使うテストが共通で行う環境変数の準備。**すべてのテストバイナリで同じ値になる**ように、
/// `setup()` ではなく接続関数（どのテストも必ず通る）で行う。
///
/// - `INTERNAL_SERVICE_TOKEN`: `/internal/*` を叩くテスト向けの既知値。32 文字以上（SEC11）。
/// - `KEY_ENCRYPTION_KEY` / `CSRF_SECRET`: **未設定のときだけ**、開発用既定値と同じバイト列を
///   base64 で明示注入する。ループバック以外のホスト名を使うテスト（`e2e_domain_split`）は
///   本番相当と判定され、開発用既定のままでは起動できないため（SEC11）。実効値を変えないので、
///   共有テスト DB 上の署名鍵をどのテストバイナリからも復号できる状態が保たれる（CI のように
///   環境変数で与えられている場合はそちらを尊重する）。
fn prepare_test_env() {
    std::env::set_var("INTERNAL_SERVICE_TOKEN", SERVICE_TOKEN);
    set_env_if_unset(
        "KEY_ENCRYPTION_KEY",
        &STANDARD.encode(idp_api::config::DEV_KEY_ENCRYPTION_KEY),
    );
    set_env_if_unset(
        "CSRF_SECRET",
        &STANDARD.encode(idp_api::config::DEV_CSRF_SECRET),
    );
}

fn set_env_if_unset(key: &str, value: &str) {
    if std::env::var_os(key).is_none_or(|v| v.is_empty()) {
        std::env::set_var(key, value);
    }
}

/// 接続上限を明示して接続する（同時実行数とプール枠の予算を突き合わせたいテスト向け）。
/// 枠が並走数を下回ると、接続を保持したまま進む処理（例: advisory lock 区間）で acquire 待ちが発生する。
pub async fn connect_pool_with_max_connections(
    test_name: &str,
    max_connections: u32,
) -> Option<MySqlPool> {
    prepare_test_env();
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
        .max_connections(max_connections)
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
    let public_web_base_url = config.public_web_base_url().to_string();
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
        public_web_base_url,
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
        "UPDATE users u \
         JOIN user_login_identifiers p ON p.primary_of_user = u.id \
         SET u.email_verified = 1 \
         WHERE u.tenant_id = ? AND p.normalized_value = ?",
    )
    .bind(tenant_id)
    .bind(username.trim().to_lowercase())
    .execute(pool)
    .await
    .expect("mark email verified");
    assert_eq!(
        result.rows_affected(),
        1,
        "mark one registered user verified"
    );
}

/// 主たるログイン識別子（ユーザー名）から利用者 id を引く。
///
/// AP15b で置き場所が `users.preferred_username` から登録簿
/// （`user_login_identifiers.primary_of_user`）へ移ったので、テストもそちらを見る。
pub async fn find_user_id_by_username(
    pool: &MySqlPool,
    tenant_id: &str,
    username: &str,
) -> Option<String> {
    sqlx::query_scalar(
        "SELECT u.id FROM users u \
         JOIN user_login_identifiers p ON p.primary_of_user = u.id \
         WHERE u.tenant_id = ? AND p.normalized_value = ?",
    )
    .bind(tenant_id)
    .bind(username.trim().to_lowercase())
    .fetch_optional(pool)
    .await
    .expect("find user by username")
}

/// 主たるログイン識別子（表示値）。未設定なら `None`。
pub async fn primary_username(pool: &MySqlPool, user_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT display_value FROM user_login_identifiers WHERE primary_of_user = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read primary login identifier")
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
/// 自己登録 API（`POST /{tenant}/auth/register`）で利用者を 1 人作る。
///
/// 通常の作成経路を通すため、`users` だけでなく HOME メンバーシップ・ログイン識別子の登録簿
/// （AP8）も本番と同じ形で埋まる。
pub async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) {
    let payload = serde_json::json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
        "name": "Integration Tester",
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::CREATED,
        "user registration"
    );
}

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
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, NULL, 'public', 'ACTIVE', 'Integration Test App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'none')",
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
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration Confidential App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'client_secret_basic')",
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

/// `client_credentials` grant を許可した confidential client を登録して
/// `(client_id, client_secret)` を返す（G4）。`grant_types` に `client_credentials` を含める点だけが
/// [`insert_confidential_client`] と異なる。
pub async fn insert_m2m_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String) {
    insert_m2m_client_with_auth_method(pool, tenant_id, scopes, "client_secret_basic").await
}

/// [`insert_m2m_client`] と同じだが、クライアント認証方式を指定する（G3）。
pub async fn insert_m2m_client_with_auth_method(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
    auth_method: &str,
) -> (String, String) {
    let client_id = format!("it-m2m-{}", unique());
    let secret = "e2e-super-secret-value";
    let secret_hash = Argon2PasswordHasher::new()
        .hash(secret)
        .expect("hash secret");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration M2M App', ?, \
         '[\"authorization_code\", \"client_credentials\"]', '[\"code\"]', ?, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .bind(auth_method)
    .execute(pool)
    .await
    .expect("insert m2m client");
    (client_id, secret.to_string())
}

/// `private_key_jwt` の M2M クライアントを作り、`(client_id, 秘密鍵 PEM, kid)` を返す（ADR-0030）。
///
/// secret は発行しない（この方式のクライアントは共有秘密を持たない）。鍵ペアはテストごとに
/// 生成し、公開鍵だけを `clients.jwks` へ登録する。
pub async fn insert_private_key_jwt_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String, String) {
    let client_id = format!("it-pkjwt-{}", unique());
    let kid = format!("kid-{}", unique());
    let (private_pem, public_pem) =
        idp_api::domain::jwt::generate_rsa_keypair().expect("generate keypair");
    let jwk = idp_api::domain::jwt::rsa_public_jwk(&kid, &public_pem).expect("build jwk");
    let jwks = serde_json::to_string(&idp_api::domain::jwt::Jwks { keys: vec![jwk] })
        .expect("serialize jwks");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method, jwks) \
         VALUES (?, ?, ?, NULL, 'confidential', 'ACTIVE', 'Integration Machine App', ?, \
         '[\"authorization_code\", \"client_credentials\"]', '[\"code\"]', ?, \
         'private_key_jwt', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .bind(jwks)
    .execute(pool)
    .await
    .expect("insert private_key_jwt client");
    (client_id, private_pem, kid)
}

/// ランダムな識別子片（メール・名前の一意化に使う。12 文字の hex）。
pub fn unique() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

// ── リクエスト・レスポンスヘルパー ───────────────────────────────────────────

pub async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

/// 本文をそのまま文字列で読む（JSON でない応答—— Prometheus のテキスト形式など）。
pub async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
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

/// 本文を取らない POST（`/unlock`・`/mfa-reset` のようなコマンド系エンドポイント）。
pub fn post_empty(cookie: &str, uri: &str) -> Request<Body> {
    request(Method::POST, cookie, uri, None)
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

/// `/authorize` のハンドオフ 302 から単回ハンドル（`?auth_session=`）を取り出す（ADR-0018 決定 2）。
/// 併せて「api がブラウザ Cookie を一切発行しない」ことも検証する。
pub fn handoff_handle(response: &axum::response::Response) -> String {
    assert!(
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none(),
        "the api must not set browser cookies on /authorize (ADR-0018)"
    );
    query_param(&location(response), "auth_session").expect("auth_session handle in Location")
}

/// `/internal/authorize/resume` を呼ぶ（web の代わり）。`sso_session_id` は `Some` で SSO 判定を伴う。
/// 応答は `result` タグ付き JSON。
pub async fn resume_authorize(
    app: &axum::Router,
    tenant: &str,
    handle: &str,
    sso_session_id: Option<&str>,
) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/resume",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "handle": handle,
                "sso_session_id": sso_session_id,
            }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "authorize resume"
    );
    body_json(response).await
}

/// `/authorize` → resume（SSO なし）で `auth_session_id` を得るショートカット（旧 Set-Cookie 相当）。
pub async fn begin_login(app: &axum::Router, tenant: &str, authorize_uri: &str) -> String {
    let response = send(
        app,
        Request::builder()
            .uri(authorize_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::FOUND,
        "handoff to web /login"
    );
    let handle = handoff_handle(&response);
    let body = resume_authorize(app, tenant, &handle, None).await;
    assert_eq!(body["result"], "login_required", "no SSO yet: {body}");
    body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string()
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
