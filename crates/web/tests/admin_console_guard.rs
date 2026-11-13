//! Router-level integration tests of the admin console entry guard and shared header (G11).
//!
//! Each admin console screen "forwards the SSO Cookie to the api's `/admin/whoami` and passes or rejects
//! based on the response". **The rejection differs per api response** (not logged in -> login screen,
//! insufficient permission -> 403, api unreachable -> 502), so if this breaks it shows up as "redirected to login despite
//! lacking permission, looping forever" or "api outage shown as missing permission". Unit tests
//! only checked the status mapping; Cookie forwarding and router wiring were not exercised.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get, get_with_cookies, location, send, setup};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

/// Stub of `/admin/whoami` (the api receives it at `/{tenant_id}/admin/whoami`).
async fn stub_whoami(env: &support::WebEnv, status: u16, body: Option<serde_json::Value>) {
    let template = match body {
        Some(json) => ResponseTemplate::new(status).set_body_json(json),
        None => ResponseTemplate::new(status),
    };
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(template)
        .mount(&env.api)
        .await;
}

#[tokio::test]
async fn without_a_session_cookie_the_console_sends_you_to_the_admin_login() {
    let env = setup().await;
    // With no Cookie the api is not expected to be called, but return 401 even if it is.
    stub_whoami(&env, 401, None).await;

    let response = send(&env.app, get(&format!("{}/admin", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        format!("{}/admin/login", env.prefix()),
        "an anonymous visitor must land on the admin login, not on an error page"
    );
}

#[tokio::test]
async fn an_expired_session_sends_you_to_the_admin_login() {
    let env = setup().await;
    stub_whoami(&env, 401, None).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=stale-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
}

#[tokio::test]
async fn a_signed_in_user_without_admin_permission_gets_403_not_a_login_loop() {
    let env = setup().await;
    stub_whoami(&env, 403, None).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "sending an already signed-in user back to the login screen would loop forever"
    );
}

#[tokio::test]
async fn an_unreachable_api_is_reported_as_a_gateway_error_not_as_a_permission_problem() {
    let prefix = support::tenant_prefix();
    let app = support::unreachable_api_app();

    let response = send(
        &app,
        get_with_cookies(
            &format!("{prefix}/admin"),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an api outage must not be shown as a permission problem"
    );
}

#[tokio::test]
async fn an_authenticated_admin_sees_the_console() {
    let env = setup().await;
    stub_whoami(
        &env,
        200,
        Some(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The endpoint returning the running build (`/admin/version/current`) answers only logged-in admins.
///
/// A screen left open compares this value with the build it was rendered by (`data-build`) and
/// shows "a new version is available". ⚠ **If the value disagrees with screens rendered by the same process,
/// the notice keeps showing though nothing was deployed**, so check end to end that the two are the same string.
#[tokio::test]
async fn the_running_build_is_answered_only_to_a_signed_in_admin() {
    let env = setup().await;
    stub_whoami(
        &env,
        200,
        Some(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })),
    )
    .await;
    let cookie = format!("{SSO_SESSION_COOKIE}=valid-session");

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/version/current", env.prefix()), &cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "the comparison target is \"the process answering now\", so it must not be cached"
    );
    let running = body_text(response).await;
    assert!(!running.trim().is_empty());

    let page = body_text(
        send(
            &env.app,
            get_with_cookies(&format!("{}/admin", env.prefix()), &cookie),
        )
        .await,
    )
    .await;
    assert!(
        page.contains(&format!(r#"data-build="{running}""#)),
        "the build on the page and the build the endpoint returns disagree ({running}): {page}"
    );

    // Not answered when logged out (sent to the login screen; the running build is not exposed on unauthenticated surfaces).
    // The api checks the session, so this is checked in another environment where whoami returns 401.
    let env = setup().await;
    stub_whoami(&env, 401, None).await;
    let anonymous = send(
        &env.app,
        get(&format!("{}/admin/version/current", env.prefix())),
    )
    .await;
    assert_eq!(anonymous.status(), StatusCode::FOUND);
    assert_eq!(
        location(&anonymous),
        format!("{}/admin/login", env.prefix())
    );
}

#[tokio::test]
async fn every_response_carries_the_shared_security_headers() {
    let env = setup().await;
    stub_whoami(&env, 401, None).await;

    let response = send(&env.app, get(&format!("{}/admin", env.prefix()))).await;
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(
        headers.get("x-frame-options").is_some(),
        "clickjacking protection must be present even on redirects"
    );
    assert!(headers.get("referrer-policy").is_some());
    // HSTS defaults to 0 (disabled). Regression guard against accidentally pinning it in local http deployments.
    assert!(
        headers.get("strict-transport-security").is_none(),
        "HSTS must stay off until HSTS_MAX_AGE is configured"
    );
}

#[tokio::test]
async fn liveness_is_answered_without_touching_the_api() {
    // Liveness answers even without an api (regression guard that no dependency was introduced).
    let app = support::unreachable_api_app();

    let response = send(&app, get("/healthz")).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "liveness must not depend on the api being up"
    );
}

/// ADR-0037: web **does not forward** the SSO Cookie to the api's admin API. It always exchanges it for an admin token
/// and calls with `Authorization: Bearer`.
///
/// If it went back to forwarding, the api does not read the Cookie as a credential, so everything would be 401 -- i.e. breakage
/// would be noticed. What we want to pin here is one step before that: **the Cookie does not leak to the api**.
/// A leak still works, so functional checks cannot detect it.
#[tokio::test]
async fn the_console_sends_a_bearer_token_and_never_forwards_the_session_cookie() {
    let env = setup().await;
    stub_whoami(
        &env,
        200,
        Some(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin",
            "tenant_name": "Root",
        })),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=live-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let requests = env
        .api
        .received_requests()
        .await
        .expect("recorded requests");

    // The exchange is `/internal/*`, so it needs the service auth token (if forgotten the api returns 401 and
    // the whole console is treated as logged out).
    let exchange = requests
        .iter()
        .find(|r| r.url.path() == "/internal/admin/token")
        .expect("the console must exchange the session for a management token");
    assert_eq!(
        exchange
            .headers
            .get("x-internal-auth-token")
            .map(|v| v.to_str().unwrap_or_default()),
        Some(support::TEST_INTERNAL_SERVICE_TOKEN),
        "the exchange must carry the internal service token"
    );

    let whoami = requests
        .into_iter()
        .find(|r| r.url.path().ends_with("/admin/whoami"))
        .expect("the console must call whoami");

    assert_eq!(
        whoami
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap_or_default()),
        Some("Bearer test-management-token"),
        "the admin API must be called with the exchanged management token"
    );
    assert!(
        whoami.headers.get(axum::http::header::COOKIE).is_none(),
        "the browser session cookie must not reach the api"
    );
}

/// If the exchange returns 401 (invalid session), go back to the login screen before calling the api's admin API.
#[tokio::test]
async fn a_rejected_token_exchange_sends_you_to_the_admin_login() {
    let env = setup().await;
    support::mount_unauthenticated_management_token(&env).await;
    // whoami is set to return 200 (also checks it is not called because the exchange stops first).
    stub_whoami(
        &env,
        200,
        Some(json!({ "user_id": "00000000-0000-7000-8000-000000000001" })),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=stale-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));

    let called_whoami = env
        .api
        .received_requests()
        .await
        .expect("recorded requests")
        .into_iter()
        .any(|r| r.url.path().ends_with("/admin/whoami"));
    assert!(
        !called_whoami,
        "a failed exchange must stop before the admin API is called"
    );
}
