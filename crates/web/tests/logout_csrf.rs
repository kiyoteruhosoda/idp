//! Logout (POST) from account settings and the admin console requires a CSRF token (task #143).
//!
//! Previously neither had a token and they were protected only by the SSO Cookie's `SameSite=Lax`. To prevent forced
//! logout from external pages, the same `console_csrf_token` (derived from the SSO session id) as other post-login forms
//! is embedded; on mismatch nothing is sent to the api and the SSO Cookie is not cleared.
//!
//! Logout from RPs (OIDC end_session_endpoint = `GET /logout`) is a different endpoint and not covered here.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::body::Body;
use axum::http::header::COOKIE;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::{
    body_text, get_with_cookies, location, post_form, send, set_cookie, setup, WebEnv,
    TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "logout-csrf-session";
const LOGOUT: &str = "/internal/logout";

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

async fn mount_logout(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(LOGOUT))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;
}

async fn logout_calls(env: &WebEnv) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == LOGOUT)
        .count()
}

async fn post_logout(
    env: &WebEnv,
    target: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> axum::http::Response<Body> {
    send(
        &env.app,
        post_form(&format!("{}{target}", env.prefix()), cookie, fields),
    )
    .await
}

fn with_token<'a>(
    fields: &[(&'a str, &'a str)],
    token: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut all = fields.to_vec();
    if let Some(token) = token {
        all.push(("csrf_token", token));
    }
    all
}

// ── Account settings logout (`POST /{tenant_id}/logout`) ─────────────────────

/// On token mismatch, do not log out (SSO is not revoked in the api and the Cookie is not cleared).
/// Return to the settings screen with `?error=csrf` and show a banner.
#[tokio::test]
async fn the_account_logout_keeps_the_session_without_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    for token in wrong_tokens() {
        let response = post_logout(
            &env,
            "/logout",
            Some(&cookies()),
            &with_token(&[], token.as_deref()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
        assert_eq!(
            set_cookie(&response, SSO_SESSION_COOKIE),
            None,
            "the sso cookie must survive a mismatched token: {token:?}"
        );
    }
    assert_eq!(
        logout_calls(&env).await,
        0,
        "a mismatched token must not reach the api"
    );
}

/// With the correct token, log out (revoke SSO in the api, clear the Cookie, go to the login screen).
#[tokio::test]
async fn the_account_logout_signs_out_with_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    let token = csrf();
    let response = post_logout(
        &env,
        "/logout",
        Some(&cookies()),
        &with_token(&[], Some(&token)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some(""),
        "the sso cookie is expired"
    );
    assert_eq!(logout_calls(&env).await, 1);
}

/// The context of a settings screen opened from the admin console is kept even when sent back on token mismatch.
#[tokio::test]
async fn a_rejected_account_logout_keeps_the_console_context() {
    let env = setup().await;
    let response = post_logout(&env, "/logout", Some(&cookies()), &[("from", "admin")]).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?error=csrf&from=admin", env.prefix())
    );
}

/// When logged out (no SSO Cookie) there is nothing to revoke. Send to the login screen without checking the token,
/// and do not call the api.
#[tokio::test]
async fn a_signed_out_logout_just_goes_to_the_login_page() {
    let env = setup().await;
    let response = post_logout(&env, "/logout", None, &[]).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(logout_calls(&env).await, 0);
}

/// A POST not readable as a form (no Content-Type, no body) is not 4xx either; it is treated as no token
/// (if logged in, sent back without logging out).
#[tokio::test]
async fn a_bodyless_logout_is_treated_as_a_missing_token() {
    let env = setup().await;
    mount_logout(&env).await;
    for target in ["/logout", "/admin/logout"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{target}", env.prefix()))
            .header(COOKIE, cookies())
            .body(Body::empty())
            .unwrap();
        let response = send(&env.app, request).await;
        assert_eq!(response.status(), StatusCode::FOUND, "{target}");
        assert!(
            location(&response).ends_with("?error=csrf"),
            "{target}: {}",
            location(&response)
        );
        assert_eq!(set_cookie(&response, SSO_SESSION_COOKIE), None, "{target}");
    }
    assert_eq!(logout_calls(&env).await, 0);
}

// ── Admin console logout (`POST /{tenant_id}/admin/logout`) ──────────────

#[tokio::test]
async fn the_console_logout_keeps_the_session_without_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    for token in wrong_tokens() {
        let response = post_logout(
            &env,
            "/admin/logout",
            Some(&cookies()),
            &with_token(&[], token.as_deref()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/admin?error=csrf", env.prefix()),
            "{token:?}"
        );
        assert_eq!(
            set_cookie(&response, SSO_SESSION_COOKIE),
            None,
            "the sso cookie must survive a mismatched token: {token:?}"
        );
    }
    assert_eq!(
        logout_calls(&env).await,
        0,
        "a mismatched token must not reach the api"
    );
}

#[tokio::test]
async fn the_console_logout_signs_out_with_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    let token = csrf();
    let response = post_logout(
        &env,
        "/admin/logout",
        Some(&cookies()),
        &with_token(&[], Some(&token)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some(""),
        "the sso cookie is expired"
    );
    assert_eq!(logout_calls(&env).await, 1);
}

#[tokio::test]
async fn a_signed_out_console_logout_just_goes_to_the_login_page() {
    let env = setup().await;
    let response = post_logout(&env, "/admin/logout", None, &[]).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
    assert_eq!(logout_calls(&env).await, 0);
}

/// The home returned to shows a banner for `?error=csrf`, and the header logout has the token embedded
/// (pressing again without reloading succeeds).
#[tokio::test]
async fn the_console_home_shows_the_banner_and_carries_the_logout_token() {
    let env = setup().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin?error=csrf", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains(r#"class="alert alert-danger""#), "{html}");
    let form = html
        .split(&format!(
            r#"<form method="post" action="{}/admin/logout">"#,
            env.prefix()
        ))
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .unwrap_or_else(|| panic!("no logout form: {html}"));
    assert!(
        form.contains(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        )),
        "{form}"
    );
}
