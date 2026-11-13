//! Ending a session also makes that session's refresh tokens unusable (ADR-0044).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test session_end_revokes_refresh_tokens
//!
//! This **cannot be proven by unit tests**. `sid` is carried along at issuance and inherited on rotation,
//! and revocation is one UPDATE against that `sid`. So without running "issue -> refresh -> end session
//! -> refresh refused" against a real DB, there is no proof the path is wired up.
//!
//! What this protects:
//!
//! Access tokens expire after 15 minutes by default. But if logout does not drop refresh tokens,
//! **that device can re-obtain a new access token every 15 minutes** (rotation does not extend the limit,
//! so 30 days from the first issuance is the cap, but a logged-out device working for 30 days is not
//! "logged out"). Short-lived access tokens only make sense on the premise that revocation works.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

/// Artifacts of one login.
struct LoggedIn {
    refresh_token: String,
    sso_cookie: String,
}

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("sr{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
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
                    "name": "Session Revoke Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// Runs through once with `offline_access` and obtains a refresh token and the SSO cookie.
async fn log_in_with_offline_access(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    username: &str,
) -> LoggedIn {
    let password = "correct-horse-battery";
    register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, username).await;

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

    // `offline_access` interposes consent. Accept it if interposed.
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
    assert!(callback.starts_with(REDIRECT_URI));
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
    LoggedIn {
        refresh_token: tokens["refresh_token"]
            .as_str()
            .expect("refresh_token (offline_access was requested)")
            .to_string(),
        sso_cookie,
    }
}

/// Calls the refresh grant once. On success returns the rotated refresh token.
async fn refresh(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    refresh_token: &str,
) -> (StatusCode, Option<String>) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(refresh_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let rotated = body["refresh_token"].as_str().map(|s| s.to_string());
    (status, rotated)
}

/// **Logging out makes that session's refresh tokens unusable.**
#[tokio::test]
async fn logging_out_stops_the_refresh_grant() {
    let Some(env) = support::setup("logout revokes refresh tokens").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let logged_in = log_in_with_offline_access(&env, &client_id, &secret, &unique_username()).await;

    // Before logout refresh succeeds (if this premise breaks, the following asserts prove nothing).
    let (status, rotated) = refresh(&env, &client_id, &secret, &logged_in.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "refresh before logout succeeds");
    let rotated = rotated.expect("rotated refresh token");

    let response = send(
        &env.app,
        post_internal(
            "/internal/logout/rp",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": logged_in.sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "rp logout");

    // Try with **the rotated token**. Unless children inherited through rotation are dropped too,
    // only "devices that refreshed once right before logout" would survive.
    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh after logout is refused (otherwise that device keeps working for up to 30 days)"
    );
}

/// **Cutting off another device via self-service also makes that device's refresh tokens unusable.**
///
/// The screen asks "Sign this device out of the account?". Merely deleting the `sso_sessions`
/// row does not answer that question.
#[tokio::test]
async fn revoking_a_session_from_the_security_screen_stops_its_refresh_grant() {
    let Some(env) = support::setup("self-service revoke revokes refresh tokens").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();

    // Device A: the one being cut off (holds a refresh token).
    let device_a = log_in_with_offline_access(&env, &client_id, &secret, &username).await;
    // Device B: the one operating. Create another session for the same user.
    let device_b = log_in_again(&env, &client_id, &secret, &username).await;

    let (status, rotated) = refresh(&env, &client_id, &secret, &device_a.refresh_token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "refresh before cutting off succeeds"
    );
    let rotated = rotated.expect("rotated refresh token");

    // From device B, cut off device A's session.
    let overview = send(
        &env.app,
        post_internal(
            "/internal/account/security",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": device_b,
            }),
        ),
    )
    .await;
    assert_eq!(overview.status(), StatusCode::OK, "security overview");
    let body = body_json(overview).await;
    let target = body["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .find(|s| s["current"] == false)
        .expect("device A's session appears in the list")["id"]
        .as_str()
        .expect("session id")
        .to_string();

    let response = send(
        &env.app,
        post_internal(
            "/internal/account/security/revoke-session",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": device_b,
                "session_id": target,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "revoke session");

    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh from the cut-off device is refused"
    );
}

/// Logs in again as an already registered user and obtains only the SSO cookie.
async fn log_in_again(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> String {
    let password = "correct-horse-battery";
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st2&nonce=nc2&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid", NON_ALPHANUMERIC)
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
                "password": password,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let _ = (client_id, secret);
    body["sso_session_id"].as_str().unwrap().to_string()
}
