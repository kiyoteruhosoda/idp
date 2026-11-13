//! Changing the display name and password on the settings screen, and TOTP setup/removal, require a CSRF token (task #118).
//!
//! Previously none had a token and they were protected only by the SSO Cookie's `SameSite=Lax`. The form now embeds
//! the same `console_csrf_token` (derived from the SSO session id) as other user-facing screens (session list,
//! authenticators); on mismatch nothing is sent to the api and the user is sent back.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, get_with_cookies, location, post_form, send, setup, WebEnv, TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "account-forms-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, TEST_CSRF_SECRET)
}

/// Missing, empty, garbage, or another session's. All of them "do not match".
fn wrong_tokens() -> Vec<Option<String>> {
    vec![
        None,
        Some(String::new()),
        Some("0".repeat(64)),
        Some(assay_web::csrf::console_csrf_token(
            "someone-else",
            TEST_CSRF_SECRET,
        )),
    ]
}

/// POST with the token (if any) added to `fields`.
async fn post_with_token(
    env: &WebEnv,
    target: &str,
    fields: &[(&str, &str)],
    token: Option<&str>,
) -> axum::http::Response<axum::body::Body> {
    let mut all: Vec<(&str, &str)> = fields.to_vec();
    if let Some(token) = token {
        all.push(("csrf_token", token));
    }
    send(
        &env.app,
        post_form(&format!("{}{target}", env.prefix()), Some(&cookies()), &all),
    )
    .await
}

async fn mount_ok(env: &WebEnv, target: &str) {
    Mock::given(method("POST"))
        .and(path(target))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .mount(&env.api)
        .await;
}

async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

// ── Display name ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_display_name_is_changed_only_with_the_right_token() {
    let env = setup().await;
    mount_ok(&env, "/internal/account/update-name").await;
    let fields = [("name", "新しい 名前")];

    for token in wrong_tokens() {
        let response = post_with_token(&env, "/settings/name", &fields, token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(
        calls_to(&env, "/internal/account/update-name").await,
        0,
        "a mismatched token must not reach the api"
    );

    let response = post_with_token(&env, "/settings/name", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?saved=name", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/account/update-name").await, 1);
}

/// The context of being opened from the admin console is kept even when sent back on token mismatch.
#[tokio::test]
async fn a_rejected_change_keeps_the_console_context() {
    let env = setup().await;
    let response = post_with_token(
        &env,
        "/settings/name",
        &[("name", "x"), ("from", "admin")],
        None,
    )
    .await;
    assert_eq!(
        location(&response),
        format!("{}/settings?error=csrf&from=admin", env.prefix())
    );
}

// ── Password ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_password_is_changed_only_with_the_right_token() {
    let env = setup().await;
    mount_ok(&env, "/internal/account/change-password").await;
    let fields = [
        ("current_password", "current-password"),
        ("new_password", "a-brand-new-password"),
        ("new_password_confirm", "a-brand-new-password"),
    ];

    for token in wrong_tokens() {
        let response = post_with_token(&env, "/settings/password", &fields, token.as_deref()).await;
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(
        calls_to(&env, "/internal/account/change-password").await,
        0,
        "a mismatched token must not reach the api"
    );

    let response = post_with_token(&env, "/settings/password", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?saved=password", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/account/change-password").await, 1);
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

/// Submitting the confirmation code (enabling) is not sent to the api on token mismatch; the settings screen is fetched again.
#[tokio::test]
async fn the_totp_setup_is_confirmed_only_with_the_right_token() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    mount_ok(&env, "/internal/mfa/totp/confirm").await;
    let fields = [("code", "123456")];

    for token in wrong_tokens() {
        let response =
            post_with_token(&env, "/account/mfa/totp/setup", &fields, token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/account/mfa/totp/setup?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, "/internal/mfa/totp/confirm").await, 0);

    let response = post_with_token(&env, "/account/mfa/totp/setup", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings/authenticators?saved=totp", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/mfa/totp/confirm").await, 1);
}

/// The settings screen embeds the token and shows a banner when returned with `?error=csrf`.
#[tokio::test]
async fn the_totp_setup_page_carries_the_token_and_shows_the_banner() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "totp_uri": "otpauth://totp/assay:?secret=JBSWY3DPEHPK3PXP&issuer=assay",
            "secret_base32": "JBSWY3DPEHPK3PXP",
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup?error=csrf", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        )),
        "{html}"
    );
    assert!(html.contains(r#"class="alert alert-danger""#), "{html}");
}

/// Removal (turning MFA off) too. On token mismatch, back to the authenticator screen with a banner.
#[tokio::test]
async fn the_totp_is_deleted_only_with_the_right_token() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    mount_ok(&env, "/internal/mfa/totp/delete").await;

    for token in wrong_tokens() {
        let response =
            post_with_token(&env, "/account/mfa/totp/delete", &[], token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings/authenticators?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, "/internal/mfa/totp/delete").await, 0);

    let response = post_with_token(&env, "/account/mfa/totp/delete", &[], Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!(
            "{}/settings/authenticators?saved=totp-deleted",
            env.prefix()
        )
    );
    assert_eq!(calls_to(&env, "/internal/mfa/totp/delete").await, 1);
}

/// Passkey removal too (task #587). On token mismatch, back to the list with a banner, without calling the api.
#[tokio::test]
async fn a_passkey_is_deleted_only_with_the_right_token() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    mount_ok(&env, "/internal/passkey/delete").await;
    let fields = [("credential_id", "00000000-0000-7000-8000-000000000001")];

    for token in wrong_tokens() {
        let response =
            post_with_token(&env, "/account/passkey/delete", &fields, token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/account/passkey?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, "/internal/passkey/delete").await, 0);

    let response = post_with_token(&env, "/account/passkey/delete", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/account/passkey?saved=deleted", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/passkey/delete").await, 1);
}
