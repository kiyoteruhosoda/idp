//! The settings screen fetches the profile once per request (task #80).
//!
//! `GET /{tenant_id}/settings` needs the profile in both the display preference middleware (language, scheme) and the screen
//! (display name, login identifier). Previously each called `/internal/account/profile`, fetching
//! the same response twice. The middleware's response is passed to the screen via a request extension, so only
//! one call reaches the api. Here this is checked by counting requests received by the api stub.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, location, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PROFILE_PATH: &str = "/internal/account/profile";

/// Stub returning the logged-in user's profile (dark scheme saved).
async fn mount_profile(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "name": "設定 太郎",
            "preferred_username": "settings-taro",
            "email": "taro@example.com",
            "language": "ja",
            "theme": "dark"
        })))
        .mount(&env.api)
        .await;
}

/// Stub receiving display preference saves. GET `?lang=` / `?theme=` are temporary switches that do not save
/// (task #79), so it is mounted to count that it was "not called".
async fn mount_preference_updates(env: &WebEnv) {
    for update in [
        "/internal/account/update-language",
        "/internal/account/update-theme",
    ] {
        Mock::given(method("POST"))
            .and(path(update))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
            .mount(&env.api)
            .await;
    }
}

/// Number of requests to the given path received by the api stub.
async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

fn sso_cookie() -> String {
    format!("{SSO_SESSION_COOKIE}={}", "s".repeat(64))
}

#[tokio::test]
async fn the_settings_page_reads_the_profile_once() {
    let env = setup().await;
    mount_profile(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    // The screen renders display name, login identifier and saved scheme from the middleware's response.
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert!(
        html.contains(r#"value="settings-taro""#),
        "login identifier: {html}"
    );
    assert!(
        html.contains(r#"<option value="dark" selected>"#),
        "stored theme is selected: {html}"
    );
    assert_eq!(
        calls_to(&env, PROFILE_PATH).await,
        1,
        "the middleware and the page must share one profile lookup"
    );
}

/// Even when only `?theme=` is explicit, the screen uses the single fetch the middleware made for the language.
/// The selector shows the explicit value (temporary switch) on this request too.
#[tokio::test]
async fn choosing_a_theme_still_reads_the_profile_once() {
    let env = setup().await;
    mount_profile(&env).await;
    mount_preference_updates(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?theme=light", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(r#"<option value="light" selected>"#),
        "the explicit choice is selected: {html}"
    );
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 1);
    assert_eq!(
        calls_to(&env, "/internal/account/update-theme").await,
        0,
        "a GET ?theme= is a temporary switch and must not be saved (task #79)"
    );
}

/// When both `?lang=` and `?theme=` decide the display preferences, the middleware does not fetch the profile.
/// Then the screen fetches it itself, once (so the display name is not empty).
#[tokio::test]
async fn the_page_reads_the_profile_itself_when_the_middleware_did_not() {
    let env = setup().await;
    mount_profile(&env).await;
    mount_preference_updates(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?lang=en&theme=light", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 1);
    // Temporary switches are not saved (task #79).
    assert_eq!(calls_to(&env, "/internal/account/update-language").await, 0);
    assert_eq!(calls_to(&env, "/internal/account/update-theme").await, 0);
}

/// **When logged out, send to the login screen** (task #121). Previously it rendered an empty settings screen
/// with 200. Like other account screens such as authenticators and sessions, it 302s to `{tenant}/login`
/// and does not fetch the profile.
#[tokio::test]
async fn the_settings_page_sends_a_visitor_without_a_session_to_sign_in() {
    let env = setup().await;
    mount_profile(&env).await;

    let response = send(
        &env.app,
        support::get(&format!("{}/settings", env.prefix())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 0);
}

/// Same when opened from the admin console (`?from=admin`).
#[tokio::test]
async fn the_settings_page_from_the_console_also_requires_sign_in() {
    let env = setup().await;

    let response = send(
        &env.app,
        support::get(&format!("{}/settings?from=admin", env.prefix())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// Even with a Cookie, if the session expired send to the login screen like other account screens.
#[tokio::test]
async fn the_settings_page_sends_an_expired_session_to_sign_in() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "session_expired" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// If only the profile could not be fetched (api internal error), render with empty fields as before
/// (do not fail the screen for display reasons; signing in again would not fix it).
#[tokio::test]
async fn the_settings_page_still_renders_when_the_profile_lookup_fails() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "internal" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
