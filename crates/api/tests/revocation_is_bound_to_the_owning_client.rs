//! `/revoke` accepts requests only from the client owning the token (ADR-0046; RFC 7009 §2.1).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test revocation_is_bound_to_the_owning_client
//!
//! The authenticated client used to be discarded as `_client`, and the repository deleted by `token_hash` alone,
//! so **any registered client could delete tokens issued to other clients**.
//!
//! Two things are kept apart.
//!
//! - **A different owner is refused** (`unauthorized_client`). §2.1 says to "verify the token was issued to that
//!   client and refuse the request if it fails".
//! - **Nonexistent stays 200** (§2.2: invalid tokens are not errors). Lumping it into an error
//!   would create **an endpoint for asking whether a token exists**.

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

/// Signs in with `offline_access` and gets a refresh token.
async fn refresh_token_for(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> String {
    tokens_for(env, client_id, secret, username).await.1
}

/// Signs in with `offline_access` and gets `(access_token, refresh_token)`.
async fn tokens_for(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    username: &str,
) -> (String, String) {
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
    let tokens = body_json(response).await;
    (
        tokens["access_token"]
            .as_str()
            .expect("access_token")
            .to_string(),
        tokens["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_string(),
    )
}

async fn revoke_as(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    revoke_with_hint(env, client_id, secret, token, "refresh_token").await
}

async fn revoke_with_hint(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    token: &str,
    hint: &str,
) -> (StatusCode, serde_json::Value) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/revoke", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "token={}&token_type_hint={hint}",
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

/// **Other clients' tokens cannot be deleted.**
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

    // Another client (that can authenticate correctly) tries to delete it.
    let (status, body) = revoke_as(&env, &other_id, &other_secret, &token).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another client's token could be deleted"
    );
    assert_eq!(body["error"], "unauthorized_client");

    // It is not deleted (refusing while deleting anyway would be pointless).
    assert!(
        refresh_works(&env, &owner_id, &owner_secret, &token).await,
        "refused, yet the token was revoked"
    );
}

/// Requests from the owner pass as before.
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
    assert_eq!(status, StatusCode::OK, "revocation request by the owner");
    assert!(
        !refresh_works(&env, &owner_id, &owner_secret, &token).await,
        "revoked but still usable"
    );
}

/// **Nonexistent tokens stay 200** (RFC 7009 §2.2).
///
/// Turning this into `unauthorized_client` would leak "an error means that token exists and belongs to someone else".
/// A different owner and nonexistence are handled differently.
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
    assert_eq!(status, StatusCode::OK, "nonexistent tokens are not errors");
}

async fn userinfo_status(env: &TestEnv, access_token: &str) -> StatusCode {
    send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", env.root_tenant_id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .status()
}

async fn revoked_jti_count(env: &TestEnv, jti: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM revoked_access_tokens WHERE jti = ?")
        .bind(jti)
        .fetch_one(&env.pool)
        .await
        .expect("count revoked jti")
}

/// The `jti` of a JWT payload (the signature is not checked; only reads a token the test itself issued).
fn jti_of(access_token: &str) -> String {
    let payload = access_token.split('.').nth(1).expect("payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("claims json");
    claims["jti"].as_str().expect("jti").to_string()
}

/// **Unsigned JWTs cannot inflate the revocation list** (T41). A merely well-shaped value returns 200
/// like a nonexistent one (RFC 7009 §2.2) and puts nothing into `revoked_access_tokens`.
#[tokio::test]
async fn a_forged_access_token_is_not_added_to_the_revocation_list() {
    let Some(env) = support::setup("revocation of a forged access token").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let jti = format!("forged-{}", uuid::Uuid::new_v4());
    let encode = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    let forged = format!(
        "{}.{}.{}",
        encode(json!({ "alg": "RS256", "typ": "at+jwt", "kid": "nope" })),
        encode(json!({ "jti": jti, "exp": 4_102_444_800_i64, "client_id": client_id })),
        "c2lnbmF0dXJl"
    );

    let (status, _) = revoke_with_hint(&env, &client_id, &secret, &forged, "access_token").await;
    assert_eq!(status, StatusCode::OK, "invalid tokens are not errors");
    assert_eq!(
        revoked_jti_count(&env, &jti).await,
        0,
        "it is put into the revocation list without checking the signature"
    );
}

/// The owning client can revoke access tokens (they become unusable at `/userinfo`).
#[tokio::test]
async fn the_owning_client_can_revoke_an_access_token() {
    let Some(env) = support::setup("revocation of an access token by the owner").await else {
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
    let (access_token, _) = tokens_for(&env, &owner_id, &owner_secret, &username).await;
    assert_eq!(userinfo_status(&env, &access_token).await, StatusCode::OK);

    let (status, _) = revoke_with_hint(
        &env,
        &owner_id,
        &owner_secret,
        &access_token,
        "access_token",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revocation request by the owner");
    assert_eq!(revoked_jti_count(&env, &jti_of(&access_token)).await, 1);
    assert_eq!(
        userinfo_status(&env, &access_token).await,
        StatusCode::UNAUTHORIZED,
        "revoked but still usable"
    );
}

/// **Other clients' access tokens cannot be deleted** (same as for refresh tokens; ADR-0046).
#[tokio::test]
async fn another_client_cannot_revoke_an_access_token_it_was_not_issued() {
    let Some(env) = support::setup("revocation of another client's access token").await else {
        return;
    };
    let (owner_id, owner_secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let (other_id, other_secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = unique_username();
    register_user(&env.app, &env.root_tenant_id, &username).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;
    let (access_token, _) = tokens_for(&env, &owner_id, &owner_secret, &username).await;

    // Even without a hint (looked up as a refresh token and missed), it is refused the same way.
    for hint in ["access_token", ""] {
        let (status, body) =
            revoke_with_hint(&env, &other_id, &other_secret, &access_token, hint).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "hint={hint}: {body}");
        assert_eq!(body["error"], "unauthorized_client", "hint={hint}");
    }
    assert_eq!(revoked_jti_count(&env, &jti_of(&access_token)).await, 0);
    assert_eq!(
        userinfo_status(&env, &access_token).await,
        StatusCode::OK,
        "refused, yet the token was revoked"
    );
}
