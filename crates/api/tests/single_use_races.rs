//! 同時に送っても 1 回しか通らないこと（task #586。脆弱性確認 2026-10-20 の低-1・低-2）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test single_use_races
//!
//! 以前は「消せたか（失効させられたか）」の件数を見ていなかったので、同じパスキーのチャレンジ・
//! 同じリフレッシュトークンを同時に 2 本送ると、どちらも確認を通って両方が成功していた。

mod support;

use assay_api::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use assay_api::domain::repositories::PasskeyChallengeRepository;
use assay_api::infrastructure::repositories::passkey_challenge::SqlxPasskeyChallengeRepository;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use chrono::{Duration, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use support::{create_plain_user, send};

/// チャレンジの消費は 1 回だけ成功する。2 回目（同時に来たもう一方）は「消せなかった」と分かる。
#[tokio::test]
async fn a_passkey_challenge_can_be_consumed_only_once() {
    let Some(env) = support::setup("single use passkey challenge").await else {
        return;
    };
    let repo = SqlxPasskeyChallengeRepository::new(env.pool.clone());
    let now = Utc::now();
    let challenge = PasskeyChallenge {
        id: uuid::Uuid::now_v7(),
        user_id: None,
        challenge_type: PasskeyChallengeType::Authenticate,
        state_json: "{}".to_string(),
        auth_session_id_hash: None,
        expires_at: now + Duration::minutes(5),
        created_at: now,
    };
    repo.create(&challenge).await.expect("create challenge");

    let (first, second) = tokio::join!(repo.delete(challenge.id), repo.delete(challenge.id));
    let consumed = [first.expect("delete"), second.expect("delete")];
    assert_eq!(
        consumed.iter().filter(|c| **c).count(),
        1,
        "exactly one of the concurrent consumers wins: {consumed:?}"
    );
    assert!(!repo.delete(challenge.id).await.expect("delete again"));
}

/// 同じリフレッシュトークンを同時に何本送っても、新しいトークンが出るのは 1 本だけ。
#[tokio::test]
async fn concurrent_refreshes_with_one_token_issue_at_most_once() {
    let Some(env) = support::setup("single use refresh").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
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
    let request = || {
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(&plain, NON_ALPHANUMERIC)
            )))
            .unwrap()
    };
    let (a, b, c, d) = tokio::join!(
        send(&env.app, request()),
        send(&env.app, request()),
        send(&env.app, request()),
        send(&env.app, request()),
    );
    let responses = [a, b, c, d];
    let succeeded = responses
        .iter()
        .filter(|r| r.status() == StatusCode::OK)
        .count();
    assert!(
        succeeded <= 1,
        "a refresh token must not be rotated twice: {succeeded} succeeded"
    );
}
