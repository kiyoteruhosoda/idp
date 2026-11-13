//! Integration tests for `id_token_hint` in RP-initiated Logout (G12; OIDC RP-Initiated Logout 1.0 §2).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test rp_logout_id_token_hint
//!
//! Key points checked:
//! - The `aud` of a verified hint is what `post_logout_redirect_uri` is matched against (even without a `client_id`
//!   parameter, only URIs registered to that RP pass).
//! - With a hint whose signature / issuer cannot be verified, **no redirect is returned** (the browser is not sent back
//!   to a counterpart that cannot be verified). Ending the session itself continues (logout is idempotent).
//! - If the hint's `sub` differs from the currently signed-in user, that session is **not ended**.
//! - Logging out does **not enqueue** back-channel logout notifications (ADR-0055; RPs are notified only
//!   when an admin stops a user).

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const POST_LOGOUT_URI: &str = "https://app.example.com/after-logout";

/// What one login produces (the ID Token and the SSO cookie issued by that login).
struct LoggedIn {
    id_token: String,
    sso_cookie: String,
}

/// Sets `post_logout_redirect_uris` on a client (the support insert helpers do not have it).
async fn set_post_logout_uri(pool: &MySqlPool, client_id: &str, uri: &str) {
    sqlx::query("UPDATE clients SET post_logout_redirect_uris = ? WHERE client_id = ?")
        .bind(json!([uri]).to_string())
        .bind(client_id)
        .execute(pool)
        .await
        .expect("set post_logout_redirect_uris");
}

async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) {
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
                    "password": password,
                    "name": "Logout Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// Goes through `/authorize` → login → consent → `/token` and gets the ID Token and SSO cookie.
async fn log_in(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> LoggedIn {
    let password = "correct-horse-battery";
    register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, username).await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);

    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
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
                "password": password,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let sso_cookie = body["sso_session_id"].as_str().unwrap().to_string();

    // The first login may include a consent step (depending on scope configuration). Accept it if so.
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
            let body = body_json(response).await;
            assert_eq!(body["result"], "success");
            body["redirect_to"].as_str().unwrap().to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    assert!(callback.starts_with(REDIRECT_URI));
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{secret}"))
                ),
            )
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    let tokens = body_json(response).await;
    LoggedIn {
        id_token: tokens["id_token"].as_str().expect("id_token").to_string(),
        sso_cookie,
    }
}

/// Calls `POST /internal/logout/rp`.
async fn rp_logout(env: &TestEnv, payload: Value) -> Value {
    let response = send(
        &env.app,
        post_internal("/internal/logout/rp", Some(SERVICE_TOKEN), payload),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "rp logout");
    body_json(response).await
}

async fn sso_session_exists(pool: &MySqlPool, sso_cookie: &str) -> bool {
    let hash = assay_api::infrastructure::crypto::sha256_hex(sso_cookie);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE session_hash = ?")
        .bind(hash)
        .fetch_one(pool)
        .await
        .expect("count sso sessions");
    count > 0
}

fn unique_username() -> String {
    format!("lo{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// The `aud` of a verified hint is what `post_logout_redirect_uri` is matched against (no `client_id` needed).
#[tokio::test]
async fn a_verified_id_token_hint_authorizes_the_post_logout_redirect() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
            "state": "xyz",
        }),
    )
    .await;

    assert_eq!(result["result"], "ok");
    let redirect = result["redirect_to"].as_str().expect("redirect_to");
    assert!(redirect.starts_with(POST_LOGOUT_URI), "{redirect}");
    assert_eq!(query_param(redirect, "state").as_deref(), Some("xyz"));
    assert!(
        !sso_session_exists(&env.pool, &session.sso_cookie).await,
        "the sso session must be terminated"
    );
}

/// A hint that fails verification returns no redirect. Ending the session itself continues.
#[tokio::test]
async fn an_unverifiable_id_token_hint_suppresses_the_redirect_but_still_logs_out() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    // An ID Token with the signature part replaced (header and payload are genuine).
    let mut parts: Vec<&str> = session.id_token.split('.').collect();
    parts[2] = "AAAA";
    let tampered = parts.join(".");

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": tampered,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert_eq!(result["result"], "ok");
    assert!(
        result["redirect_to"].is_null(),
        "an unverifiable hint must not produce a redirect: {result}"
    );
    assert!(
        !sso_session_exists(&env.pool, &session.sso_cookie).await,
        "logout itself is idempotent and must still happen"
    );
}

/// Access Tokens (`typ=at+jwt`) are not accepted as hints.
#[tokio::test]
async fn an_access_token_is_not_accepted_as_an_id_token_hint() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{secret}"))
                ),
            )
            .body(Body::from("grant_type=client_credentials"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let access_token = body_json(response).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "id_token_hint": access_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;
    assert!(
        result["redirect_to"].is_null(),
        "an access token must not authorize the redirect: {result}"
    );
}

/// If the hint's `sub` differs from the currently signed-in user, the session is not ended.
#[tokio::test]
async fn a_hint_for_another_user_does_not_terminate_the_current_session() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    // Get user A's ID Token, then create the situation where user B signs in in the same browser.
    let first = log_in(&env, &client_id, &secret, &unique_username()).await;
    let second = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": second.sso_cookie,
            "id_token_hint": first.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    // Returns `subject_mismatch` rather than `ok`. Seeing this, web **does not delete the cookie**
    // (deleting it would leave a dangling state where the session lives only in the DB).
    assert_eq!(result["result"], "subject_mismatch", "{result}");
    assert!(
        result["redirect_to"].is_null(),
        "a mismatched hint must not produce a redirect: {result}"
    );
    assert!(
        sso_session_exists(&env.pool, &second.sso_cookie).await,
        "another user's session must survive"
    );
}

/// If the `client_id` parameter and the hint's `aud` disagree, neither is trusted.
#[tokio::test]
async fn a_client_id_that_contradicts_the_hint_suppresses_the_redirect() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;
    let (other_client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &other_client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "client_id": other_client_id,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert!(
        result["redirect_to"].is_null(),
        "contradicting client_id and aud must not produce a redirect: {result}"
    );
}

/// URIs not registered to the hint's `aud` do not pass (even if registered to another RP).
#[tokio::test]
async fn the_redirect_must_be_registered_for_the_client_named_by_the_hint() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    // Register a different URI for the RP issuing the hint, and register the requested URI only to **another RP**.
    set_post_logout_uri(&env.pool, &client_id, "https://app.example.com/own").await;
    let (other_client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &other_client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert!(
        result["redirect_to"].is_null(),
        "a URI registered for another RP must not be honoured: {result}"
    );
}

/// Old-style requests with neither hint nor `client_id` pass with URIs registered in the tenant as before.
#[tokio::test]
async fn a_request_without_any_hint_keeps_the_previous_behaviour() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    let redirect = result["redirect_to"].as_str().expect("redirect_to");
    assert!(redirect.starts_with(POST_LOGOUT_URI), "{redirect}");
}

/// Sets `backchannel_logout_uri` on a client (the support insert helpers do not have it).
async fn set_backchannel_logout_uri(pool: &MySqlPool, client_id: &str, uri: &str) {
    sqlx::query("UPDATE clients SET backchannel_logout_uri = ? WHERE client_id = ?")
        .bind(uri)
        .bind(client_id)
        .execute(pool)
        .await
        .expect("set backchannel_logout_uri");
}

async fn deliveries_for(pool: &MySqlPool, client_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM backchannel_logout_deliveries WHERE client_id = ?")
        .bind(client_id)
        .fetch_one(pool)
        .await
        .expect("count back-channel logout deliveries")
}

/// ⚠ **Logging out does not notify RPs** (ADR-0055).
///
/// An SSO session is shared by several RPs. Signing out from one RP must not close the sessions of other RPs
/// that registered an endpoint. RPs are notified only when an admin stops a user (ADR-0053).
#[tokio::test]
async fn logging_out_does_not_notify_the_relying_parties() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_backchannel_logout_uri(
        &env.pool,
        &client_id,
        "https://app.example.com/backchannel-logout",
    )
    .await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": session.id_token,
        }),
    )
    .await;

    assert_eq!(result["result"], "ok");
    assert!(
        !sso_session_exists(&env.pool, &session.sso_cookie).await,
        "the sso session must still be terminated"
    );
    assert_eq!(
        deliveries_for(&env.pool, &client_id).await,
        0,
        "a logout must not enqueue back-channel notifications"
    );
}
