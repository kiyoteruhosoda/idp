//! `/revoke` は、トークンの持ち主クライアントからの要求だけを受ける（ADR-0046。RFC 7009 §2.1）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test revocation_is_bound_to_the_owning_client
//!
//! 以前は認証済みクライアントを `_client` として捨てており、リポジトリ側も `token_hash` だけで
//! 消していたため、**登録さえされていれば他のクライアントに発行されたトークンを消せた**。
//!
//! 分けているものが 2 つある。
//!
//! - **持ち主違いは断る**（`unauthorized_client`）。§2.1 が「トークンがそのクライアントへ
//!   発行されたものか検証し、失敗したら要求を拒む」と定めている。
//! - **不存在は 200 のまま**（§2.2: 無効なトークンはエラーにしない）。ここを一緒くたに
//!   エラーへ倒すと、**存在するかどうかを問い合わせる口**になる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("rv{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

async fn register_user(app: &axum::Router, tenant: &str, username: &str) {
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "preferred_username": username,
                    "password": PASSWORD,
                    "name": "Revocation Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// `offline_access` でログインして refresh token を得る。
async fn refresh_token_for(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> String {
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid offline_access", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    let auth_session = body["auth_session_id"].as_str().unwrap().to_string();
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": PASSWORD,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    let callback = match body["result"].as_str() {
        Some("consent_required") => {
            let consent_session = body["auth_session_id"].as_str().unwrap().to_string();
            let response = send(
                &env.app,
                post_internal(
                    "/internal/consent/approve",
                    Some(SERVICE_TOKEN),
                    json!({
                        "tenant_id": env.root_tenant_id,
                        "auth_session_id": consent_session,
                    }),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            body_json(response).await["redirect_to"]
                .as_str()
                .unwrap()
                .to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    body_json(response).await["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string()
}

async fn revoke_as(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/revoke", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "token={}&token_type_hint=refresh_token",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = response.status();
    (status, body_json(response).await)
}

async fn refresh_works(env: &TestEnv, client_id: &str, secret: &str, token: &str) -> bool {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    response.status() == StatusCode::OK
}

/// **他のクライアントのトークンは消せない。**
#[tokio::test]
async fn another_client_cannot_revoke_a_token_it_was_not_issued() {
    let Some(env) = support::setup("revocation client binding").await else {
        return;
    };
    let (owner_id, owner_secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let (other_id, other_secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    register_user(&env.app, &env.root_tenant_id, &username).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let token = refresh_token_for(&env, &owner_id, &owner_secret, &username).await;

    // 別のクライアント（正しく認証はできる）が消しにくる。
    let (status, body) = revoke_as(&env, &other_id, &other_secret, &token).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "他のクライアントのトークンを消せてしまっている"
    );
    assert_eq!(body["error"], "unauthorized_client");

    // 消えていないこと（断ったのに消していたら意味が無い）。
    assert!(
        refresh_works(&env, &owner_id, &owner_secret, &token).await,
        "断ったのにトークンが失効している"
    );
}

/// 持ち主からの要求はこれまでどおり通る。
#[tokio::test]
async fn the_owning_client_can_still_revoke() {
    let Some(env) = support::setup("revocation by the owner").await else {
        return;
    };
    let (owner_id, owner_secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    register_user(&env.app, &env.root_tenant_id, &username).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let token = refresh_token_for(&env, &owner_id, &owner_secret, &username).await;

    let (status, _) = revoke_as(&env, &owner_id, &owner_secret, &token).await;
    assert_eq!(status, StatusCode::OK, "持ち主の失効要求");
    assert!(
        !refresh_works(&env, &owner_id, &owner_secret, &token).await,
        "失効させたのにまだ使える"
    );
}

/// **存在しないトークンは 200 のまま**（RFC 7009 §2.2）。
///
/// ここを `unauthorized_client` に倒すと、「エラーが返る＝そのトークンは実在して他人のもの」と
/// いう情報が漏れる。持ち主違いと不存在は別の扱いにする。
#[tokio::test]
async fn an_unknown_token_is_still_accepted_silently() {
    let Some(env) = support::setup("revocation of an unknown token").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;

    let (status, _) = revoke_as(&env, &client_id, &secret, "not-a-real-token").await;
    assert_eq!(status, StatusCode::OK, "不存在のトークンはエラーにしない");
}
