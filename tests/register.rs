//! ユーザー登録エンドポイントの統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test register

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use idp::application::register::RegisterService;
use idp::domain::clock::Clock;
use idp::infrastructure::password::Argon2PasswordHasher;
use idp::infrastructure::repositories::user::SqlxUserRepository;
use idp::presentation::router;
use idp::presentation::state::AppState;
use serde_json::Value;
use sqlx::mysql::MySqlPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

async fn post_register(app: &axum::Router, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn register_creates_user_and_rejects_duplicates_and_invalid_input() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping register integration test");
        return;
    };

    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect");
    MIGRATOR.run(&pool).await.expect("migrate");

    let users = Arc::new(SqlxUserRepository::new(pool.clone()));
    let hasher = Arc::new(Argon2PasswordHasher::new());
    let clock = Arc::new(SystemClock);
    let register = Arc::new(RegisterService::new(users, hasher, clock));
    let app = router::build(AppState {
        pool: pool.clone(),
        register,
    });

    // 一意なメールで登録 → 201。
    let email = format!("user-{}@example.com", uuid::Uuid::new_v4());
    let (status, body) = post_register(
        &app,
        serde_json::json!({
            "email": email,
            "preferred_username": null,
            "password": "password123",
            "name": "Test User"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert_eq!(body["status"], "ACTIVE");
    assert!(!body["sub"].as_str().unwrap().is_empty());

    // 実際に DB へ保存されている。
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // 同一メールの再登録 → 409。
    let (status, _) = post_register(
        &app,
        serde_json::json!({ "email": email, "password": "password123" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 短いパスワード → 400。
    let (status, _) = post_register(
        &app,
        serde_json::json!({
            "email": format!("x-{}@example.com", uuid::Uuid::new_v4()),
            "password": "short"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
