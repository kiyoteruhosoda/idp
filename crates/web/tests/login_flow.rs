//! Router-level integration tests of the login screen (G11).
//!
//! The api is stubbed with `wiremock` (no DB needed). What is checked is not the handler internals but the outside --
//! issuing and reading Cookies, the CSRF synchronizer token round trip, redirect targets and statuses,
//! and handling when the api is down.

mod support;

use assay_contracts::cookies::{AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};
use assay_contracts::csrf::login_csrf_token;
use assay_web::cookies::PORTAL_CSRF_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, get, get_with_cookies, location, post_form, send, set_cookie, set_cookie_raw, setup,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn portal_login_page_issues_a_csrf_seed_cookie_and_renders_the_form() {
    let env = setup().await;
    // Fetching external IdP buttons (password login still appears on failure = fail-soft).
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;

    let response = send(&env.app, get(&format!("{}/login", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::OK);

    // The CSRF seed appears in both the Cookie and the form (with only one it would always mismatch).
    let seed = set_cookie(&response, PORTAL_CSRF_COOKIE).expect("csrf seed cookie");
    assert!(!seed.is_empty(), "csrf seed must not be empty");
    let raw = set_cookie_raw(&response, PORTAL_CSRF_COOKIE).expect("raw cookie");
    assert!(
        raw.contains("HttpOnly"),
        "csrf seed must be HttpOnly: {raw}"
    );
    assert!(raw.contains("SameSite=Lax"), "unexpected attributes: {raw}");

    let html = body_text(response).await;
    assert!(html.contains("csrf_token"), "form must carry a csrf token");
    assert!(html.contains(r#"name="password""#), "password field");
}

#[tokio::test]
async fn portal_login_page_reuses_an_existing_seed_so_open_tabs_keep_working() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;

    let existing = "0123456789abcdef0123456789abcdef";
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/login", env.prefix()),
            &format!("{PORTAL_CSRF_COOKIE}={existing}"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        set_cookie(&response, PORTAL_CSRF_COOKIE).as_deref(),
        Some(existing),
        "an existing seed must be reused, not rotated (open tabs would break)"
    );
}

#[tokio::test]
async fn oidc_login_success_sets_the_sso_cookie_and_redirects_to_the_rp() {
    let env = setup().await;
    let auth_session = "a".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "success",
            "redirect_to": "https://rp.example.com/cb?code=abc&state=xyz",
            "sso_session_id": "sso-value",
            "sso_absolute_ttl_secs": 3600,
            "user_language": null
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        "https://rp.example.com/cb?code=abc&state=xyz"
    );
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some("sso-value"),
        "the SSO cookie must be issued by web, not by api"
    );
    // The flow is over, so the temporary session Cookie is cleaned up.
    assert_eq!(
        set_cookie(&response, AUTH_SESSION_COOKIE).as_deref(),
        Some(""),
        "the auth session cookie must be expired after the flow completes"
    );
}

#[tokio::test]
async fn invalid_credentials_reshow_the_form_without_issuing_a_session() {
    let env = setup().await;
    let auth_session = "b".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "invalid_credentials" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "wrong"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        set_cookie(&response, SSO_SESSION_COOKIE).is_none(),
        "a failed login must not issue an SSO cookie"
    );
    let html = body_text(response).await;
    assert!(html.contains("csrf_token"), "the form must be re-rendered");
}

#[tokio::test]
async fn a_csrf_mismatch_redirects_back_to_a_fresh_form() {
    let env = setup().await;
    let auth_session = "c".repeat(64);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "csrf_mismatch" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", "not-the-right-token"),
            ],
        ),
    )
    .await;

    // PRG: switch to GET with 303 (returning an error to the POST makes reload resubmit, with no way to recover).
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/login?error=csrf", env.prefix())
    );
}

#[tokio::test]
async fn an_unreachable_api_does_not_leak_a_panic_or_a_session() {
    let auth_session = "d".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);
    let prefix = support::tenant_prefix();
    let app = support::unreachable_api_app();

    let response = send(
        &app,
        post_form(
            &format!("{prefix}/login"),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert!(
        response.status().is_server_error(),
        "an unreachable api must surface as a server error, got {}",
        response.status()
    );
    assert!(
        set_cookie(&response, SSO_SESSION_COOKIE).is_none(),
        "no session may be issued when the api never answered"
    );
}

#[tokio::test]
async fn a_non_uuid_tenant_segment_is_not_a_screen() {
    let env = setup().await;
    let response = send(&env.app, get("/not-a-uuid/login")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// A submission with a nonexistent (or `DISABLED`) tenant ID typed in the URL becomes **404** (MT28).
///
/// `/internal/*` has no tenant prefix and does not go through the api's `TenantResolver`; the tenant's
/// existence and state are judged by the api from `tenant_id` in the body and rejected with 400. When web did not
/// distinguish that 400 from other failures, **merely mistyping the tenant ID in the URL gave a bare 502** --
/// a user input error, not a web implementation/configuration error.
#[tokio::test]
async fn an_unknown_tenant_renders_the_404_page_instead_of_a_bad_gateway() {
    let env = setup().await;
    let auth_session = "d".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": assay_contracts::auth::UNKNOWN_TENANT_ERROR_CODE,
            "error_description": "unknown or disabled tenant"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // The body is filled in by the shared error page middleware (never returned empty).
    let html = body_text(response).await;
    assert!(html.contains("404"), "404 page not rendered: {html}");
}

/// Other api failures stay 502 as before (web implementation/configuration error, api outage). MT28 only distinguished
/// "cannot resolve the tenant"; nothing else changed.
#[tokio::test]
async fn other_api_failures_still_render_a_bad_gateway() {
    let env = setup().await;
    let auth_session = "e".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
