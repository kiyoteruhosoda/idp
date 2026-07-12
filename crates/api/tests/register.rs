//! ユーザー登録エンドポイントの統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test register

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

async fn post_register(app: &axum::Router, tenant: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/{tenant}/auth/register"))
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
    let Some(env) = support::setup("register").await else {
        return;
    };
    let (app, pool, root_id) = (env.app, env.pool, env.root_tenant_id);

    // 一意なメールで登録 → 201。
    let email = format!("user-{}@example.com", uuid::Uuid::new_v4());
    let (status, body) = post_register(
        &app,
        &root_id,
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

    // 実際に DB へ保存されている（所属元 = root テナント）。
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ? AND tenant_id = ?")
            .bind(&email)
            .bind(&root_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // HOME メンバーシップも同時に作成される（ADR-0009 §3）。
    let memberships: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenant_memberships tm \
         JOIN users u ON u.id = tm.user_id \
         WHERE u.email = ? AND tm.tenant_id = ? \
         AND tm.membership_type = 'HOME' AND tm.status = 'ACTIVE'",
    )
    .bind(&email)
    .bind(&root_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(memberships, 1, "HOME membership must be auto-created");

    // 同一メールの再登録 → 409。
    let (status, _) = post_register(
        &app,
        &root_id,
        serde_json::json!({ "email": email, "password": "password123" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 短いパスワード → 400。
    let (status, _) = post_register(
        &app,
        &root_id,
        serde_json::json!({
            "email": format!("x-{}@example.com", uuid::Uuid::new_v4()),
            "password": "short"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
