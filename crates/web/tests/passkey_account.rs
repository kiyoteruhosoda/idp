//! Checks the flow of the passkey self-management screens (`/{tenant_id}/account/passkey*`) through the router.
//!
//! What we want to see is "where the user stands after an operation". Reporting removal on a dedicated page
//! leaves a page with no way back, and reporting session expiry with a 401 message leaves users no way out.
//! Both still render fine, so breakage goes unnoticed unless the redirect target is checked.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, get_with_cookies, location, post_form, send, setup, WebEnv, TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// CSRF token embedded in the delete form (task #587).
fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, TEST_CSRF_SECRET)
}

/// The gate for sensitive operations (AP5) is set to satisfied.
async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

async fn stub_list(env: &WebEnv, credentials: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "credentials": credentials,
        })))
        .mount(&env.api)
        .await;
}

async fn stub_delete(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

/// Removal returns to the list and reports the result in a banner (no completion page without a way back).
#[tokio::test]
async fn deleting_a_passkey_returns_to_the_list_with_a_banner() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_delete(&env, "ok").await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/passkey/delete", env.prefix()),
            Some(&cookies()),
            &[
                ("credential_id", "00000000-0000-7000-8000-000000000001"),
                ("csrf_token", csrf().as_str()),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/account/passkey?saved=deleted", env.prefix())
    );

    let list = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/passkey?saved=deleted", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    let html = body_text(list).await;
    assert!(html.contains("パスキーを削除しました"), "{html}");
}

/// Do not say "removed" for something not removed (the api's `not_found` is reported as a failure).
#[tokio::test]
async fn a_passkey_that_was_not_there_is_reported_as_a_failure() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_delete(&env, "not_found").await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/passkey/delete", env.prefix()),
            Some(&cookies()),
            &[
                ("credential_id", "00000000-0000-7000-8000-000000000009"),
                ("csrf_token", csrf().as_str()),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/account/passkey?error=not-found", env.prefix())
    );
}

/// If not signed in, send to the login screen (same as other screens under settings).
#[tokio::test]
async fn the_list_sends_a_signed_out_visitor_to_the_login_page() {
    let env = setup().await;

    let response = send(
        &env.app,
        support::get(&format!("{}/account/passkey", env.prefix())),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// Do not show a dead-end 401 page even when the session expired.
#[tokio::test]
async fn an_expired_session_sends_the_visitor_to_the_login_page() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/passkey/list"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "session_expired" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// Suspended passkeys appear in the list (the key lookup only drops revoked rows). **They appear but
/// cannot be used**, so the screen shows the state and how to remove them.
#[tokio::test]
async fn a_suspended_passkey_is_marked_and_points_at_where_to_resume_it() {
    let env = setup().await;
    stub_list(
        &env,
        json!([{
            "id": "00000000-0000-7000-8000-000000000001",
            "name": "MacBook",
            "created_at": "2026-09-01T00:00:00+00:00",
            "last_used_at": null,
            "suspended": true,
        }]),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;
    let html = body_text(response).await;

    assert!(html.contains("一時停止中"), "{html}");
    assert!(
        html.contains(&format!(
            r#"href="{}/settings/authenticators""#,
            env.prefix()
        )),
        "{html}"
    );
}

/// The removal confirmation uses the form's `data-confirm` (`console.js`). `onclick` is inline JS
/// blocked by the CSP (`script-src 'self'`), so it would **submit without confirmation**.
#[tokio::test]
async fn the_delete_button_asks_for_confirmation_without_inline_script() {
    let env = setup().await;
    stub_list(
        &env,
        json!([{
            "id": "00000000-0000-7000-8000-000000000001",
            "name": "MacBook",
            "created_at": "2026-09-01T00:00:00+00:00",
            "last_used_at": null,
            "suspended": false,
        }]),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;
    let html = body_text(response).await;

    assert!(html.contains("data-confirm="), "{html}");
    assert!(!html.contains("onclick="), "{html}");
    assert!(html.contains("/assets/console.js?v="), "{html}");
}
