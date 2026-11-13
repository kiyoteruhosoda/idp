//! Checks passkey verification (step-up; AP5, T38) through the router.
//!
//! Without this route, users who signed in with a passkey **cannot enter authenticator management** (management is
//! a step-up target, and that step-up accepted only passwords). What we want to see is when the entry is shown and
//! where to return after completion -- neither shows up in the handler's pure functions.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(COOKIE, cookies())
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn stub_check(env: &WebEnv, passkey_available: bool) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "challenge_required",
            "second_factor_required": true,
            "passkey_available": passkey_available,
        })))
        .mount(&env.api)
        .await;
}

async fn stub_verify(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/passkey/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

async fn challenge_page(env: &WebEnv) -> String {
    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/settings/verify?operation=manage_authenticators&next={}%2Faccount%2Fpasskey",
                env.prefix(),
                env.prefix()
            ),
            &cookies(),
        ),
    )
    .await;
    body_text(response).await
}

/// Users with a usable passkey get the passkey entry next to the password. **Even operations demanding multi-factor
/// (authenticator management) are satisfied by one passkey**, so it is the only path for users without TOTP.
#[tokio::test]
async fn the_challenge_offers_the_passkey_route_to_a_user_who_has_one() {
    let env = setup().await;
    stub_check(&env, true).await;

    let html = challenge_page(&env).await;

    assert!(html.contains(r#"id="btn-passkey-login""#), "{html}");
    assert!(
        html.contains(r#"data-complete-path="/settings/verify/passkey/complete""#),
        "{html}"
    );
    // The screen passes the values for the completion API (which operation, where to return).
    assert!(
        html.contains(r#"data-operation="manage_authenticators""#),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"data-next="{}/account/passkey""#, env.prefix())),
        "{html}"
    );
}

/// Not shown to users without passkeys (pressing it would just fail after the browser dialog).
#[tokio::test]
async fn the_challenge_hides_the_passkey_route_without_a_usable_passkey() {
    let env = setup().await;
    stub_check(&env, false).await;

    let html = challenge_page(&env).await;

    assert!(!html.contains(r#"id="btn-passkey-login""#), "{html}");
    assert!(!html.contains("/settings/verify/passkey/"), "{html}");
}

/// After verification passes, return to the original screen (returns the JSON equivalent of the form route's 303).
#[tokio::test]
async fn a_verified_passkey_sends_the_user_back_to_the_operation() {
    let env = setup().await;
    stub_verify(&env, "ok").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/account/passkey", env.prefix()))
    );
}

/// `next` comes from the browser, so this route also restricts it to same-tenant paths
/// (no open redirect via the JSON response).
#[tokio::test]
async fn a_foreign_next_is_replaced_with_the_settings_page() {
    let env = setup().await;
    stub_verify(&env, "ok").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": "https://evil.example.com/",
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/settings", env.prefix()))
    );
}

/// If the session expired, send to login without a message (retrying on this screen would not pass).
#[tokio::test]
async fn an_expired_session_is_sent_to_the_login_page() {
    let env = setup().await;
    stub_verify(&env, "session_expired").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/login", env.prefix()))
    );
}

/// When the assertion fails, return a code that maps to translated text (the screen holds the text).
#[tokio::test]
async fn a_rejected_passkey_is_reported_as_a_code_the_screen_can_translate() {
    let env = setup().await;
    stub_verify(&env, "invalid_credential").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(body["error"], json!("invalid_credential"));
    assert!(body["redirect_to"].is_null());
}

/// If not signed in, no challenge is issued (nothing to step up).
#[tokio::test]
async fn beginning_without_a_session_is_unauthorized() {
    let env = setup().await;

    let response = send(
        &env.app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("{}/settings/verify/passkey/begin", env.prefix()))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
