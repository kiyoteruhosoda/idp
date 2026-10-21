//! リフレッシュで出す ID Token の `auth_time` は、元のログインの時刻のまま（task #584）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test refresh_keeps_auth_time
//!
//! 以前は refresh のたびに「今」になっていたので、RP が `auth_time` で課す「N 分以内に再認証」を、
//! 更新を繰り返すだけですり抜けられた。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::Value;
use support::{body_json, create_plain_user, send, TestEnv};

async fn refresh(env: &TestEnv, client_id: &str, secret: &str, token: &str) -> Value {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "refresh");
    body_json(res).await
}

/// ID Token の本文（署名は見ない。値の中身だけを読む）。
fn id_token_claims(tokens: &Value) -> Value {
    let id_token = tokens["id_token"].as_str().expect("id_token");
    let payload = id_token.split('.').nth(1).expect("payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("claims")
}

#[tokio::test]
async fn refreshing_does_not_move_the_time_of_the_last_sign_in() {
    let Some(env) = support::setup("refresh keeps auth_time").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;

    // 3 時間前にログインして出たリフレッシュトークン。
    let plain = format!("rt-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (token_hash, tenant_id, user_id, client_id, scope, auth_time, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 3 HOUR), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(assay_api::infrastructure::crypto::sha256_hex(&plain))
    .bind(&env.root_tenant_id)
    .bind(&user_id)
    .bind(&client_id)
    .execute(&env.pool)
    .await
    .expect("insert refresh token");
    // 列は UTC の DATETIME。秒へは Rust 側で直す（DB の UNIX_TIMESTAMP はセッションのタイムゾーンに依る）。
    let signed_in: chrono::NaiveDateTime =
        sqlx::query_scalar("SELECT auth_time FROM refresh_tokens WHERE token_hash = ?")
            .bind(assay_api::infrastructure::crypto::sha256_hex(&plain))
            .fetch_one(&env.pool)
            .await
            .expect("auth_time");
    let signed_in = signed_in.and_utc().timestamp();

    let first = refresh(&env, &client_id, &secret, &plain).await;
    let claims = id_token_claims(&first);
    assert_eq!(claims["auth_time"].as_i64(), Some(signed_in), "{claims}");
    assert!(
        claims["iat"].as_i64().unwrap() - signed_in >= 3 * 3600 - 5,
        "the token is issued now, the sign-in was 3 hours ago: {claims}"
    );

    // 更新を重ねても動かない（rotation で引き継ぐ）。
    let rotated = first["refresh_token"].as_str().expect("rotated");
    let second = refresh(&env, &client_id, &secret, rotated).await;
    assert_eq!(
        id_token_claims(&second)["auth_time"].as_i64(),
        Some(signed_in)
    );
}
