//! リフレッシュトークンの内省（introspection）が返す `sub` は公開の値（task #593）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test introspection_public_sub
//!
//! 以前はリフレッシュトークンの経路だけ内部の利用者 ID を返していた（アクセストークンの経路は公開の
//! `sub`）。内部 ID が RP へ漏れ、同じ人が経路によって違う `sub` に見えていた。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use support::{body_json, create_plain_user, send};

#[tokio::test]
async fn refresh_token_introspection_returns_the_public_subject() {
    let Some(env) = support::setup("introspection public sub").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let public_sub: String = sqlx::query_scalar("SELECT sub FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .expect("public sub");
    let plain = format!("rt-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, client_id, scope, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(assay_api::infrastructure::crypto::sha256_hex(&plain))
    .bind(&env.root_tenant_id)
    .bind(&user_id)
    .bind(&client_id)
    .execute(&env.pool)
    .await
    .expect("insert refresh token");

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/introspect", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(format!(
                "token={}&token_type_hint=refresh_token",
                utf8_percent_encode(&plain, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["active"], true, "{body}");
    assert_eq!(body["sub"].as_str(), Some(public_sub.as_str()), "{body}");
    assert_ne!(body["sub"].as_str(), Some(user_id.as_str()), "{body}");
}
