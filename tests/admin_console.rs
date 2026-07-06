//! 管理コンソール（A2）のサーバレンダリング画面の E2E 統合テスト（ADR-0006 §6）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_console
//!
//! ログインはクライアント不要（鶏卵問題の回避）。初期管理者（seed 0002 + 0004 で idp.admin 付与済み）の
//! 資格情報で `/admin/login` にサインインし、SSO Cookie でホーム `/admin` を表示できることを検証する。
//! 権限の無い利用者は Forbidden、未認証はログイン画面へ 302 することも検証する。

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Request, StatusCode};
use idp::config::Config;
use idp::domain::clock::Clock;
use idp::domain::password::PasswordHasher;
use idp::infrastructure::crypto;
use idp::infrastructure::password::Argon2PasswordHasher;
use idp::presentation::router;
use idp::presentation::state::AppState;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// この 1 バイナリ内の複数テストが `MIGRATOR.run` を同時に呼ぶと、空の DB では作成が競合して
/// 失敗し得る。マイグレーション適用だけを直列化する（テスト本体は並列のまま）。
static MIGRATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// seed 0002 の初期管理者（seed 0004 で idp.admin を付与済み）。
const ADMIN_EMAIL: &str = "admin@example.com";

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
        eprintln!("TEST_DATABASE_URL not set; skipping admin console integration test");
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

async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `Set-Cookie` 群から `name=value` の value を取り出す（属性は落とす）。
fn cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response.headers().get_all(SET_COOKIE).iter().find_map(|v| {
        let raw = v.to_str().ok()?;
        let first = raw.split(';').next()?;
        let (k, val) = first.split_once('=')?;
        (k.trim() == name).then(|| val.trim().to_string())
    })
}

/// パスワード既知の管理ユーザーを用意する（seed の既定パスワードに依存しないため作り直す）。
/// email は seed の初期管理者を使い、idp.admin 付与済みの前提を流用する。
async fn set_admin_password(pool: &MySqlPool, password: &str) {
    let hash = Argon2PasswordHasher::new()
        .hash(password)
        .expect("hash password");
    sqlx::query("UPDATE users SET password_hash = ?, failed_login_count = 0, locked_until = NULL WHERE email = ?")
        .bind(&hash)
        .bind(ADMIN_EMAIL)
        .execute(pool)
        .await
        .expect("update admin password");
}

#[tokio::test]
async fn admin_can_sign_in_and_view_console() {
    let Some(env) = setup().await else {
        return;
    };
    let password = "admin-console-test-pw-123";
    set_admin_password(&env.pool, password).await;

    // 1. ログイン画面 → 200・CSRF Cookie 発行・フォームに csrf_token 埋め込み。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console/login")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let csrf_id = cookie_value(&res, "admin_csrf_id").expect("csrf cookie set");
    assert!(!csrf_id.is_empty());
    let form_html = body_text(res).await;
    assert!(form_html.contains("name=\"csrf_token\""));

    // 2. 未認証でホームへ → ログイン画面へ 302。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers().get(LOCATION).unwrap(), "/admin/console/login");

    // 3. CSRF 不一致 → 400。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/admin/console/login")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, format!("admin_csrf_id={csrf_id}"))
            .body(Body::from(format!(
                "username={ADMIN_EMAIL}&password={password}&csrf_token=wrong"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "csrf mismatch -> 400"
    );

    // 4. 正しい資格情報＋CSRF → 302 /admin・SSO Cookie 発行。
    let csrf_token = crypto::sha256_hex(&format!("admin-csrf:{csrf_id}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/admin/console/login")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, format!("admin_csrf_id={csrf_id}"))
            .body(Body::from(format!(
                "username={ADMIN_EMAIL}&password={password}&csrf_token={csrf_token}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND, "valid login -> 302");
    assert_eq!(res.headers().get(LOCATION).unwrap(), "/admin/console");
    let sso = cookie_value(&res, "sso_session_id").expect("sso cookie set");
    assert!(!sso.is_empty());

    // 5. SSO Cookie でホーム → 200・コンソール本文。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console")
            .header(COOKIE, format!("sso_session_id={sso}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "authenticated home -> 200");
    let home = body_text(res).await;
    assert!(home.contains("Admin console"));
    assert!(home.contains("/admin/console/logout"));

    // 6. ログアウト → 302 ログイン画面・SSO Cookie 失効。以降ホームは 302。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/admin/console/logout")
            .header(COOKIE, format!("sso_session_id={sso}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(res.headers().get(LOCATION).unwrap(), "/admin/console/login");

    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console")
            .header(COOKIE, format!("sso_session_id={sso}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FOUND,
        "session terminated -> redirect to login"
    );
}

#[tokio::test]
async fn non_admin_is_forbidden_on_login_and_console() {
    let Some(env) = setup().await else {
        return;
    };

    // idp.admin を持たない一般利用者を作成（パスワード既知）。
    let password = "plain-user-pw-123";
    let hash = Argon2PasswordHasher::new().hash(password).expect("hash");
    let user_id = uuid::Uuid::new_v4().to_string();
    let email = format!("plain-{}@example.com", &user_id[..8]);
    sqlx::query(
        "INSERT INTO users (id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, 1, ?, 'ACTIVE')",
    )
    .bind(&user_id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&email)
    .bind(&hash)
    .execute(&env.pool)
    .await
    .expect("insert plain user");

    // ログイン画面で CSRF を得る。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console/login")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let csrf_id = cookie_value(&res, "admin_csrf_id").expect("csrf cookie");
    let csrf_token = crypto::sha256_hex(&format!("admin-csrf:{csrf_id}"));

    // 正しい資格情報だが idp.admin 非保有 → 403・SSO Cookie は発行しない。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/admin/console/login")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(COOKIE, format!("admin_csrf_id={csrf_id}"))
            .body(Body::from(format!(
                "username={email}&password={password}&csrf_token={csrf_token}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "non-admin -> 403");
    assert!(
        cookie_value(&res, "sso_session_id").is_none(),
        "no SSO cookie for non-admin"
    );
}
