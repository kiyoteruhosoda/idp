//! Runs guest invitation acceptance **through the router** (api replaced by wiremock).
//!
//! ⚠ **The invitee is not yet a member of the target tenant.** So the acceptance route
//! **cannot assume that tenant's admin token** -- accepting is the operation of becoming a member.
//!
//! ⚠ **Until 2026-09-16 this went through the admin token exchange (`POST /internal/admin/token`).**
//! The exchange only succeeds for "users with permissions in that tenant", so it always gave 401 for invitees, and
//! the screen went back to "please sign in to your home tenant first" -- **even though they were signed in.**
//! Per-layer tests (api integration tests, core unit tests) both passed, so
//! **only this test, running web -> api with an invitee, catches it.**
//!
//! So each test calls accept ⚠ **after setting up the exchange to return 401**. If it comes to depend on the exchange again,
//! this fails.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, mount_unauthenticated_management_token, post_form, send, setup, WebEnv,
    TEST_CSRF_SECRET,
};
use wiremock::matchers::{body_json, header, method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "test-sso-session-id";
const TOKEN: &str = "test-invitation-token";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// Mounts the api's accept endpoint. ⚠ **The credential is the Cookie** (`AuthenticatedUser`), not Bearer.
async fn mount_accept(env: &WebEnv, status: u16, body: Option<serde_json::Value>) {
    let cookie = cookies();
    let response = match body {
        Some(json) => ResponseTemplate::new(status).set_body_json(json),
        None => ResponseTemplate::new(status),
    };
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/invitations/accept$"))
        .and(header("cookie", cookie.as_str()))
        .and(body_json(json!({ "token": TOKEN })))
        .respond_with(response)
        .mount(&env.api)
        .await;
}

fn accept_request(env: &WebEnv) -> axum::http::Request<axum::body::Body> {
    let csrf = console_csrf_token(SSO, TEST_CSRF_SECRET);
    post_form(
        &format!("{}/invitations/accept", env.prefix()),
        Some(&cookies()),
        &[("token", TOKEN), ("csrf_token", &csrf)],
    )
}

#[tokio::test]
async fn accepting_forwards_the_session_cookie_without_a_management_token() {
    let env = setup().await;
    // ⚠ Make the exchange fail (the invitee is not a member yet, so this is reality).
    mount_unauthenticated_management_token(&env).await;
    mount_accept(&env, 204, None).await;

    let response = send(&env.app, accept_request(&env)).await;

    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("alert-success"),
        "acceptance success is not shown: {html}"
    );
    // If the form remains after accepting, users read it as "not done yet".
    assert!(
        !html.contains(r#"name="token""#),
        "form remains after success"
    );
}

#[tokio::test]
async fn unauthorized_from_the_api_asks_the_user_to_sign_in() {
    let env = setup().await;
    mount_unauthenticated_management_token(&env).await;
    mount_accept(&env, 401, Some(json!({ "error": "unauthorized" }))).await;

    let response = send(&env.app, accept_request(&env)).await;

    // This guidance appears only when the session is really invalid.
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        !html.contains("alert-success"),
        "success shown despite failure: {html}"
    );
    assert!(
        !html.contains(r#"name="token""#),
        "no form on the not-logged-in guidance"
    );
}

#[tokio::test]
async fn an_invalid_token_is_reported_as_invalid_not_as_a_sign_in_problem() {
    let env = setup().await;
    mount_unauthenticated_management_token(&env).await;
    mount_accept(
        &env,
        400,
        Some(json!({ "error": "invalid_request", "message": "invalid or expired" })),
    )
    .await;

    let response = send(&env.app, accept_request(&env)).await;

    // ⚠ **Do not use the same screen for token problems and session problems.** If they look the same,
    //   users and operators keep trying "sign in again" endlessly (that was the 2026-09-16 diagnosis).
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let html = body_text(response).await;
    assert!(
        html.contains("alert-danger"),
        "invalid notice is not shown: {html}"
    );
    assert!(
        html.contains(r#"name="token""#),
        "keep the form so it can be retried"
    );
}
