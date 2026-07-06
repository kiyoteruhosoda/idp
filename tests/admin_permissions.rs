//! 利用者権限の付与・剥奪 API の E2E 統合テスト（Progress A2、ADR-0006、設計仕様 §7）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_permissions
//!
//! 認可は `RequirePerms<IdpAdmin>`。初期管理者（seed 0002 + 0004 で idp.admin 付与済み）の
//! SSO セッションを直接作成し、その Cookie で管理 API を叩く。権限の無い利用者は 403 になること、
//! 付与・剥奪が `audit_log` に記録されることを検証する。

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Request, StatusCode};
use idp::config::Config;
use idp::domain::clock::Clock;
use idp::infrastructure::crypto;
use idp::presentation::router;
use idp::presentation::state::AppState;
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// seed 0002 の初期管理者 id（seed 0004 で idp.admin を付与済み）。
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
        eprintln!("TEST_DATABASE_URL not set; skipping admin permissions integration test");
        return None;
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    Some(TestEnv {
        app: router::build(state),
        pool,
    })
}

/// 指定ユーザーの有効な SSO セッションを作成し、Cookie 用の平文 session_id を返す。
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

/// 権限を持たない利用者を作成し、その内部 id を返す。
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

fn admin_get(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::empty())
        .unwrap()
}

fn admin_delete(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn admin_can_grant_and_revoke_permissions() {
    let Some(env) = setup().await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, ADMIN_ID).await;
    let target = create_plain_user(&env.pool).await;
    let perms_uri = format!("/admin/users/{target}/permissions");

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(&perms_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain_cookie = create_sso_session(&env.pool, &target).await;
    let res = send(&env.app, admin_get(&plain_cookie, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // user_id が UUID でない → 400。
    let res = send(
        &env.app,
        admin_get(&admin_cookie, "/admin/users/not-a-uuid/permissions"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad user_id -> 400");

    // 不存在の利用者への付与 → 404。
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &format!("/admin/users/{ghost}/permissions"),
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown user -> 404");

    // 未知の権限コード → 400。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": "idp.does-not-exist" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown code -> 400");

    // 初期状態: 権限なし。
    let res = send(&env.app, admin_get(&admin_cookie, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    assert!(listed["permission_codes"].as_array().unwrap().is_empty());

    // 付与 → 200・一覧に idp.admin・監査 granted 記録。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant -> 200");
    let granted = body_json(res).await;
    assert_eq!(
        granted["permission_codes"].as_array().unwrap(),
        &vec![json!(ADMIN_PERM)]
    );
    assert_eq!(
        count_audit(&env.pool, "user_permission.granted", ADMIN_ID).await,
        1,
        "granted audit recorded (actor = admin)"
    );

    // 冪等: 再付与しても重複しない。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted = body_json(res).await;
    assert_eq!(granted["permission_codes"].as_array().unwrap().len(), 1);

    // 付与された利用者は管理 API へアクセスできる（自分の権限一覧を取得）。
    let res = send(&env.app, admin_get(&plain_cookie, &perms_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "granted user can now access admin"
    );

    // 剥奪 → 200・一覧空・監査 revoked 記録。
    let res = send(
        &env.app,
        admin_delete(&admin_cookie, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke -> 200");
    let revoked = body_json(res).await;
    assert!(revoked["permission_codes"].as_array().unwrap().is_empty());
    assert_eq!(
        count_audit(&env.pool, "user_permission.revoked", ADMIN_ID).await,
        1,
        "revoked audit recorded"
    );

    // 剥奪は冪等（未保有でも 200）。
    let res = send(
        &env.app,
        admin_delete(&admin_cookie, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke again -> 200");
}
