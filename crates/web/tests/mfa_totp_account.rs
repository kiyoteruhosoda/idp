//! Checks TOTP self-enrollment (`/{tenant_id}/account/mfa/totp/setup`; AP9) through the router.
//!
//! This route had not a single test, and the 500 in production was only noticed from the screen.
//! What we want to check is not the handler's pure functions but the outside -- whether the screen actually
//! renders after passing the step-up gate.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use serde_json::json;
use support::{
    assert_status, body_text, get_with_cookies, location, post_form, send, setup, WebEnv,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// CSRF token embedded in this SSO session's forms (task #118).
fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

/// Step-up is already satisfied (right after verifying on another screen).
async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

async fn stub_totp_setup_ok(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "totp_uri": "otpauth://totp/assay:?secret=JBSWY3DPEHPK3PXP&issuer=assay",
            "secret_base32": "JBSWY3DPEHPK3PXP",
        })))
        .mount(&env.api)
        .await;
}

/// Users who have verified get the setup screen (QR and raw secret) directly.
#[tokio::test]
async fn the_setup_page_renders_for_a_stepped_up_user() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup_ok(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(&response, axum::http::StatusCode::OK, "setup page");
    let html = body_text(response).await;
    assert!(html.contains("JBSWY3DPEHPK3PXP"), "{html}");
    assert!(html.contains("<svg"), "{html}");
}

/// If not verified yet, send to verification instead of the setup screen (not a 500).
#[tokio::test]
async fn a_user_who_has_not_verified_recently_is_sent_to_the_challenge() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "challenge_required",
            "second_factor_required": false,
            "passkey_available": true,
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::FOUND,
        "challenge redirect",
    );
    assert!(
        location(&response).starts_with(&format!("{}/settings/verify?", env.prefix())),
        "{}",
        location(&response)
    );
}

/// **Users can go back even when the api returns an internal error.** Without an exit on screen,
/// they have nothing but the browser's back (which actually happened).
#[tokio::test]
async fn the_error_page_lets_the_user_get_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "internal" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "api internal error",
    );
    let prefix = env.prefix();
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(r#"href="{prefix}/settings""#)),
        "no link back: {html}"
    );
}

/// **The setup screen has a way back.** Give users who want to abort an exit other than the browser's back
/// (task #82). As on the passkey screens, both the "Back" at the top of the body and the top-left label
/// link to account settings.
#[tokio::test]
async fn the_setup_page_links_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup_ok(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(&response, axum::http::StatusCode::OK, "setup page");
    let prefix = env.prefix();
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(
            r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="{prefix}/settings""#
        )),
        "top-left label is not a link: {html}"
    );
    assert!(
        html.contains(&format!(r#"<a href="{prefix}/settings">"#)),
        "no way back in the body: {html}"
    );
}

/// **After setup, return to the authenticator screen and report the result in a banner.** Announcing completion on a
/// dead-end screen leaves nowhere obvious to go next (task #82). It is PRG, so
/// reloading does not resend the confirmation code.
#[tokio::test]
async fn a_confirmed_setup_returns_to_the_authenticators_page() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/confirm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            Some(&cookies()),
            &[("code", "123456"), ("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::SEE_OTHER,
        "confirm redirect",
    );
    assert_eq!(
        location(&response),
        format!("{}/settings/authenticators?saved=totp", env.prefix())
    );
}

/// **After removal, return to the authenticator screen and report the result in a banner.** Previously a minimal
/// page only announced completion, with no link back to account settings (found in task #119, fixed in #121).
/// PRG like setup completion (task #82).
#[tokio::test]
async fn a_deleted_totp_returns_to_the_authenticators_page() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/delete", env.prefix()),
            Some(&cookies()),
            &[("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::SEE_OTHER,
        "delete redirect",
    );
    assert_eq!(
        location(&response),
        format!(
            "{}/settings/authenticators?saved=totp-deleted",
            env.prefix()
        )
    );
}

/// **The authenticator screen returned to after removal also has exits** (check for task #121). It shows the notice
/// (`?saved=totp-deleted`), and account settings can be reached both from the top-left label and the "Basics" tab of the
/// account settings tabs (task #251; shared by 3 screens).
#[tokio::test]
async fn the_authenticators_page_after_deletion_links_back_to_settings() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/account/authenticators"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "authenticators": [],
            "recovery_codes_remaining": 0,
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/settings/authenticators?saved=totp-deleted",
                env.prefix()
            ),
            &cookies(),
        ),
    )
    .await;

    assert_status(&response, axum::http::StatusCode::OK, "authenticators page");
    let prefix = env.prefix();
    let html = body_text(response).await;
    assert!(
        html.contains(r#"<div class="alert alert-success" role="status">"#),
        "removal notice is not shown: {html}"
    );
    assert!(
        html.contains(&format!(
            r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="{prefix}/settings""#
        )),
        "top-left label is not a link: {html}"
    );
    assert!(
        html.contains(&format!(r#"<a class="nav-link" href="{prefix}/settings">"#)),
        "tabs have no link to account settings (basics): {html}"
    );
    // The currently open tab (authenticator app and passkeys) is marked.
    assert!(
        html.contains(&format!(
            r#"href="{prefix}/settings/authenticators" aria-current="page""#
        )),
        "{html}"
    );
}

// ── Exits of failure screens (task #119) ────────────────────────────────────────
//
// The minimal page that only reports failure had no way back, so already set up (409), session expired (401),
// and failing to regenerate the QR after a wrong code (422) were dead ends. As on the setup screen,
// the top-left label and the "Back" at the top of the body link to account settings. If the session
// expired account settings cannot be opened, so the body link points to sign-in.

async fn stub_totp_setup(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

async fn stub_totp_confirm(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/confirm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

/// The failure screen shows both the top-left label and "Back to account settings" at the top of the body.
fn assert_links_back_to_settings(prefix: &str, html: &str) {
    assert!(
        html.contains(&format!(
            r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="{prefix}/settings""#
        )),
        "top-left label is not a link: {html}"
    );
    assert!(
        html.contains(&format!(r#"<a href="{prefix}/settings">"#)),
        "no way back in the body: {html}"
    );
}

/// A session-expired screen points the body link to sign-in (account settings cannot be opened).
fn assert_links_to_sign_in(prefix: &str, html: &str) {
    assert!(
        html.contains(&format!(r#"<a href="{prefix}/login">"#)),
        "no link to sign-in: {html}"
    );
    assert!(
        !html.contains(&format!(r#"<a href="{prefix}/settings">"#)),
        "points to account settings, which cannot be opened: {html}"
    );
}

/// **The already-set-up screen has a way back.** Reconfiguring requires removing first, so it returns to
/// account settings, where removal lives.
#[tokio::test]
async fn the_already_configured_page_links_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup(&env, "already_configured").await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::CONFLICT,
        "already configured",
    );
    let html = body_text(response).await;
    assert_links_back_to_settings(&env.prefix(), &html);
}

/// When submitting the confirmation reveals it is already set up (done first in another tab), show the same exit.
#[tokio::test]
async fn the_already_configured_page_after_confirm_links_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_confirm(&env, "already_configured").await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            Some(&cookies()),
            &[("code", "123456"), ("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::CONFLICT,
        "already configured",
    );
    let html = body_text(response).await;
    assert_links_back_to_settings(&env.prefix(), &html);
}

/// **When the code is wrong and the QR cannot be regenerated either** (setup completed meanwhile, the api went down),
/// the setup screen cannot be redrawn, so report the failure and return to account settings.
#[tokio::test]
async fn an_invalid_code_without_a_fresh_qr_links_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_confirm(&env, "invalid_code").await;
    stub_totp_setup(&env, "internal").await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            Some(&cookies()),
            &[("code", "000000"), ("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "invalid code",
    );
    let html = body_text(response).await;
    assert_links_back_to_settings(&env.prefix(), &html);
}

/// **A session-expired screen invites sign-in.** Returning to account settings would just ask for
/// sign-in again there, a needless detour.
#[tokio::test]
async fn the_session_expired_page_links_to_sign_in() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup(&env, "session_expired").await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::UNAUTHORIZED,
        "session expired",
    );
    let html = body_text(response).await;
    assert_links_to_sign_in(&env.prefix(), &html);
}

/// Same when submitting the confirmation reveals the session expired.
#[tokio::test]
async fn the_session_expired_page_after_confirm_links_to_sign_in() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_confirm(&env, "session_expired").await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            Some(&cookies()),
            &[("code", "123456"), ("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::UNAUTHORIZED,
        "session expired",
    );
    let html = body_text(response).await;
    assert_links_to_sign_in(&env.prefix(), &html);
}

/// Also invite sign-in when the confirmation is submitted without being signed in (no SSO Cookie).
#[tokio::test]
async fn confirming_without_signing_in_links_to_sign_in() {
    let env = setup().await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            None,
            &[("code", "123456"), ("csrf_token", &csrf())],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::UNAUTHORIZED,
        "not signed in",
    );
    let html = body_text(response).await;
    assert_links_to_sign_in(&env.prefix(), &html);
}
