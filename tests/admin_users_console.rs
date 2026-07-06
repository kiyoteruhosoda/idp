//! 利用者権限の付与・剥奪画面（A2、ADR-0006）の E2E 統合テスト。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_users_console
//!
//! 画面は `/admin/console/users*`（JSON API `/admin/users/*` とは経路を分離）。初期管理者
//! （seed 0002 + 0004 で idp.admin 付与済み）の SSO セッションを直接作成し、その Cookie で画面を操作する。
//! CSRF は SSO セッション id 由来の同期トークン（sha256("console-csrf:" + sso_session_id)）。付与・剥奪の
//! POST は Post/Redirect/Get で権限画面へ 302 し、失敗は `error` クエリで伝える。

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION};
use axum::http::{Request, StatusCode};
use idp::config::Config;
use idp::domain::clock::Clock;
use idp::infrastructure::crypto;
use idp::presentation::router;
use idp::presentation::state::AppState;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
static MIGRATE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

const ADMIN_ID: &str = "00000000-0000-0000-0000-000000000001";
const ADMIN_PERM: &str = "idp.admin";

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
        eprintln!("TEST_DATABASE_URL not set; skipping admin users console integration test");
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

/// 権限を持たない利用者（メール・ユーザー名付き）を作成し、内部 id とメール・ユーザー名を返す。
async fn create_plain_user(pool: &MySqlPool) -> (String, String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let email = format!("plain-{}@example.com", &id[..8]);
    let username = format!("plain-{}", &id[..8]);
    sqlx::query(
        "INSERT INTO users (id, sub, email, email_verified, preferred_username, password_hash, status) \
         VALUES (?, ?, ?, 1, ?, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&email)
    .bind(&username)
    .execute(pool)
    .await
    .expect("insert plain user");
    (id, email, username)
}

async fn count_audit(pool: &MySqlPool, event_type: &str, user_id: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log WHERE event_type = ? AND user_id = ? AND result = 'success'",
    )
    .bind(event_type)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count audit")
    .get::<i64, _>("c")
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

fn location(res: &axum::response::Response) -> String {
    res.headers()
        .get(LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn admin_grants_and_revokes_permissions_through_console() {
    let Some(env) = setup().await else {
        return;
    };
    let cookie = create_sso_session(&env.pool, ADMIN_ID).await;
    let csrf = console_csrf(&cookie);
    let (target, email, username) = create_plain_user(&env.pool).await;
    let perms_path = format!("/admin/console/users/{target}/permissions");

    // 未認証で検索 → ログイン画面へ 302。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri("/admin/console/users")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(location(&res), "/admin/console/login");

    // メールで検索 → 200・権限画面への導線。
    let res = send(
        &env.app,
        get_authed(&cookie, &format!("/admin/console/users?q={email}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains(&email), "search result shows email");
    assert!(text.contains(&perms_path), "links to permissions page");

    // ユーザー名でも検索できる。
    let res = send(
        &env.app,
        get_authed(&cookie, &format!("/admin/console/users?q={username}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains(&perms_path));

    // 該当なし → 200・見つからない文言。
    let res = send(
        &env.app,
        get_authed(&cookie, "/admin/console/users?q=nobody@example.com"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("No user matches"));

    // 権限画面（初期状態）→ 200・権限なし・付与フォーム。
    let res = send(&env.app, get_authed(&cookie, &perms_path)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains("has no permissions"));
    assert!(text.contains(&csrf), "grant form carries csrf token");

    // CSRF 不一致で付与 → 302・error=csrf・実際には付与されない。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("{perms_path}/grant"),
            format!("permission_code={ADMIN_PERM}&csrf_token=wrong"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(location(&res), format!("{perms_path}?error=csrf"));

    // 未知の権限コードで付与 → 302・error=code。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("{perms_path}/grant"),
            format!("permission_code=idp.does-not-exist&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(location(&res), format!("{perms_path}?error=code"));

    // 正当な付与 → 302・権限画面へ（error なし）・監査 granted 記録。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("{perms_path}/grant"),
            format!("permission_code={ADMIN_PERM}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(location(&res), perms_path);
    assert_eq!(
        count_audit(&env.pool, "user_permission.granted", ADMIN_ID).await,
        1,
        "granted audit recorded (actor = admin)"
    );

    // 権限画面で idp.admin が保有権限として表示される。
    let res = send(&env.app, get_authed(&cookie, &perms_path)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains(ADMIN_PERM));
    assert!(
        text.contains(&format!("{perms_path}/revoke")),
        "revoke form present"
    );

    // 剥奪 → 302・権限画面へ・監査 revoked 記録。
    let res = send(
        &env.app,
        form_post(
            &cookie,
            &format!("{perms_path}/revoke"),
            format!("permission_code={ADMIN_PERM}&csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(location(&res), perms_path);
    assert_eq!(
        count_audit(&env.pool, "user_permission.revoked", ADMIN_ID).await,
        1,
        "revoked audit recorded"
    );

    // 剥奪後は権限なしに戻る。
    let res = send(&env.app, get_authed(&cookie, &perms_path)).await;
    assert!(body_text(res).await.contains("has no permissions"));

    // 不存在の利用者の権限画面 → 404。
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        get_authed(
            &cookie,
            &format!("/admin/console/users/{ghost}/permissions"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // UUID でない ID の権限画面 → 404。
    let res = send(
        &env.app,
        get_authed(&cookie, "/admin/console/users/not-a-uuid/permissions"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn non_admin_is_forbidden_on_console_users() {
    let Some(env) = setup().await else {
        return;
    };
    let (user_id, _email, _username) = create_plain_user(&env.pool).await;
    let cookie = create_sso_session(&env.pool, &user_id).await;

    // 権限の無い利用者 → 403 HTML（未認証の 302 とは区別）。
    let res = send(&env.app, get_authed(&cookie, "/admin/console/users")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
