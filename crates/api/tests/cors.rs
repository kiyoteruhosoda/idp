//! G1: cross-origin access from browsers (CORS).
//!
//! In the default topology (`domain-split`) calls from an SPA to api are always cross-origin.
//! What is pinned here is the boundary of "how far it is open to whom":
//!
//!   * Public metadata is readable by anyone (`*`)
//!   * `/token`, `/userinfo` etc. only for **origins of public clients registered in the tenant**
//!   * Not open for the admin API
//!   * `Access-Control-Allow-Credentials` is never attached on any path
//!
//! Run the same way as `schema.rs` (`TEST_DATABASE_URL` is required).

mod support;

use axum::body::Body;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
};
use axum::http::{Method, Request, StatusCode};

const SPA_ORIGIN: &str = "http://localhost:3000";
const OTHER_ORIGIN: &str = "https://evil.example.com";

fn with_origin(method: Method, uri: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(ORIGIN, origin)
        .body(Body::empty())
        .expect("build request")
}

fn allow_origin(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get(ACCESS_CONTROL_ALLOW_ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Public metadata carries no client_id or token and identifies nobody. It is content anyone can fetch without
/// auth, so it is opened with `*`.
#[tokio::test]
async fn public_metadata_is_readable_from_any_origin() {
    let Some(env) = support::setup("cors_public_metadata").await else {
        return;
    };
    let tenant = &env.root_tenant_id;

    for path in [
        format!("/{tenant}/.well-known/openid-configuration"),
        format!("/{tenant}/.well-known/jwks.json"),
        format!("/{tenant}/saml/metadata"),
    ] {
        let response = support::send(&env.app, with_origin(Method::GET, &path, OTHER_ORIGIN)).await;
        assert_eq!(
            allow_origin(&response).as_deref(),
            Some("*"),
            "{path} must be readable cross-origin"
        );
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "{path}: api does not read browser cookies (ADR-0018), so credentials are not allowed"
        );
    }
}

/// `/token` is open only to origins derived from the `redirect_uris` of public clients registered in the tenant.
#[tokio::test]
async fn the_token_endpoint_opens_only_to_registered_public_client_origins() {
    let Some(env) = support::setup("cors_token_endpoint").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    // `REDIRECT_URI` is `http://localhost:3000/callback` (= SPA_ORIGIN).
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    // Registered origin: can read the response of the actual request.
    let uri = format!("/{tenant}/token");
    let allowed = support::send(&env.app, with_origin(Method::POST, &uri, SPA_ORIGIN)).await;
    assert_eq!(allow_origin(&allowed).as_deref(), Some(SPA_ORIGIN));
    assert!(
        allowed
            .headers()
            .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentials are not allowed"
    );

    // Unregistered origin: no headers attached (the browser refuses the read).
    let denied = support::send(&env.app, with_origin(Method::POST, &uri, OTHER_ORIGIN)).await;
    assert_eq!(allow_origin(&denied), None);
}

/// `/userinfo` is always preflighted because `Authorization: Bearer` is not safelisted.
/// OPTIONS carries no token, so it answers with the per-tenant allowed set.
#[tokio::test]
async fn the_userinfo_preflight_is_answered_without_hitting_the_handler() {
    let Some(env) = support::setup("cors_userinfo_preflight").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri(format!("/{tenant}/userinfo"))
        .header(ORIGIN, SPA_ORIGIN)
        .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .expect("build preflight");
    let response = support::send(&env.app, preflight).await;

    // The router has no OPTIONS, so unless the middleware catches it, it would be 405.
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(allow_origin(&response).as_deref(), Some(SPA_ORIGIN));
    let methods = response
        .headers()
        .get(ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(methods.contains("GET"), "GET is allowed: {methods}");
}

/// Preflights from unregistered origins return without CORS headers (the actual request is not sent).
#[tokio::test]
async fn a_preflight_from_an_unknown_origin_gets_no_cors_headers() {
    let Some(env) = support::setup("cors_unknown_preflight").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri(format!("/{tenant}/userinfo"))
        .header(ORIGIN, OTHER_ORIGIN)
        .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("build preflight");
    let response = support::send(&env.app, preflight).await;
    assert_eq!(allow_origin(&response), None);
}

/// The admin API is not a path to call cross-origin from browser JS. Opening it would leave room for admin
/// operations to be read from another origin, so no headers are attached even for registered origins.
#[tokio::test]
async fn admin_endpoints_are_never_opened_cross_origin() {
    let Some(env) = support::setup("cors_admin_closed").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let uri = format!("/{tenant}/admin/clients");
    let response = support::send(&env.app, with_origin(Method::GET, &uri, SPA_ORIGIN)).await;
    assert_eq!(allow_origin(&response), None);
}
