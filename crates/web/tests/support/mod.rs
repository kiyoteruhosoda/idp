//! Shared foundation for web integration tests (G11).
//!
//! web has no DB; all data operations are HTTP calls to the api (ADR-0007). So
//! **stubbing the api over HTTP lets router-level behaviour be verified without a DB**. What we want to see is
//! not the handler's pure functions but the outside -- issuing and reading Cookies, the CSRF synchronizer token,
//! redirect targets and statuses, and handling when the api is down. None of these
//! are covered by `#[test]` unit checks; until now only the `scripts/e2e.sh` shell script
//! exercised them.
//!
//! # How configuration is passed (why env vars are locked)
//!
//! `Config::from_env()` reads from environment variables. The stub server's URL is unknown until it starts
//! (dynamic port), so `API_BASE_URL` must be set before building the config. Environment variables are shared
//! process-wide, so **"set -> build config" is wrapped in one lock**. The built
//! `Config` holds its own copy, so other tests rewriting the same variable afterwards do not affect it.
//!
//! # Secrets are not taken from the runtime environment
//!
//! `CSRF_SECRET` is **fixed on the test side** ([`TEST_CSRF_SECRET`]). CI passes its own `CSRF_SECRET` as a job
//! environment variable, so letting `Config::from_env()` pick it up would make the router verify tokens with CI's key,
//! always mismatching the tokens tests build with their local key -- passing locally and failing only in CI,
//! the hardest kind of failure to decipher. For the same reason `INTERNAL_SERVICE_TOKEN` is fixed too.

#![allow(dead_code)]

use assay_web::config::Config;
use assay_web::router;
use assay_web::state::WebState;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Method, Request, Response, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The api stub and a web router pointed at it.
pub struct WebEnv {
    pub app: axum::Router,
    pub api: MockServer,
    pub tenant: String,
}

impl WebEnv {
    /// `/{tenant_id}` prefix.
    pub fn prefix(&self) -> String {
        format!("/{}", self.tenant)
    }
}

/// CSRF key used by tests (exactly 32 bytes). Must be the same value as the router's so tests can derive
/// the tokens that appear in forms. The runtime environment's value is not used (see the module comment).
pub const TEST_CSRF_SECRET: &[u8; 32] = b"assay-web-integration-tests-csrf";

/// Service-to-service token used by tests (the minimum length is set by the `assay_contracts::deployment` contract).
pub const TEST_INTERNAL_SERVICE_TOKEN: &str = "assay-web-integration-test-service-token";

/// Critical section from rewriting env vars to building the config (see the module comment).
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Starts the api stub and builds a web router pointed at it.
///
/// The admin token exchange (`POST /internal/admin/token`; ADR-0037) is mounted to **succeed by default**.
/// web always goes through it before calling the admin API, so making each test mount it would have every test
/// write the same line. Tests that want to see the exchange fail (not logged in) override it with
/// [`mount_unauthenticated_management_token`].
pub async fn setup() -> WebEnv {
    setup_with_env(&[]).await
}

/// `setup()` plus env vars added only while starting web (to test env-only settings; removed after startup).
pub async fn setup_with_env(extra: &[(&str, &str)]) -> WebEnv {
    let api = MockServer::start().await;
    let uri = api.uri();
    let app = build_app_with(&uri, extra);
    let env = WebEnv {
        app,
        api,
        tenant: uuid::Uuid::now_v7().to_string(),
    };
    Mock::given(method("POST"))
        .and(path("/internal/admin/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-management-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "permission_codes": ["idp.tenant.admin"],
            "name": "Admin",
            "preferred_username": "admin",
        })))
        // The default gets the lowest priority so tests can override it (with equal priority wiremock
        // lets **the one mounted first** win, so overrides must be expressed by priority).
        .with_priority(10)
        .mount(&env.api)
        .await;
    // The entry check (task #887) asks every time "is the SSO session bound to a device key". The default is
    // "not bound" (passes with the long Cookie alone, as before). Tests of the bound case override it.
    Mock::given(method("POST"))
        .and(path("/internal/sso/key-binding"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "result": "unbound" })),
        )
        .with_priority(10)
        .mount(&env.api)
        .await;
    env
}

/// Mounts a stub where the admin token exchange returns 401 (= not logged in).
///
/// Overrides by mounting with higher priority than `setup()`'s default stub (priority 10).
pub async fn mount_unauthenticated_management_token(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/admin/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "unauthorized"
        })))
        .with_priority(1)
        .mount(&env.api)
        .await;
}

/// A web router pointed at a destination **nobody listens on** (for testing api outages).
///
/// Dropping the stub server to take it down is not used. Requests arriving before shutdown completes get 404,
/// treated as "no tenant" rather than "api unreachable", a false negative. A closed port refuses connections
/// immediately and always takes the same path (api call failure).
pub fn unreachable_api_app() -> axum::Router {
    build_app("http://127.0.0.1:1")
}

fn build_app(api_base_url: &str) -> axum::Router {
    build_app_with(api_base_url, &[])
}

fn build_app_with(api_base_url: &str, extra: &[(&str, &str)]) -> axum::Router {
    let config = {
        let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("API_BASE_URL", api_base_url);
        // Secrets are not taken from the runtime environment (picking up CI's value would mismatch the test key).
        std::env::set_var("CSRF_SECRET", STANDARD.encode(TEST_CSRF_SECRET));
        std::env::set_var("INTERNAL_SERVICE_TOKEN", TEST_INTERNAL_SERVICE_TOKEN);
        // Keep the public origin on loopback so it can start with the development default secret
        //(fails fast with a production-like origin; SEC11).
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");
        for (key, value) in extra {
            std::env::set_var(key, value);
        }
        let config = Config::from_env();
        for (key, _) in extra {
            std::env::remove_var(key);
        }
        config.expect("load web config")
    };
    router::build(WebState::build(Arc::new(config)))
}

/// Building tenant routes (`unreachable_api_app` has no `WebEnv`, so used standalone).
pub fn tenant_prefix() -> String {
    format!("/{}", uuid::Uuid::now_v7())
}

pub async fn send(app: &axum::Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("send request")
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

pub fn get_with_cookies(uri: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(COOKIE, cookies)
        .body(Body::empty())
        .unwrap()
}

/// `application/x-www-form-urlencoded` POST (same shape as the screen's form submission).
pub fn post_form(uri: &str, cookies: Option<&str>, fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookies) = cookies {
        builder = builder.header(COOKIE, cookies);
    }
    builder.body(Body::from(body)).unwrap()
}

fn urlencode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub async fn body_text(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn location(response: &Response<Body>) -> String {
    response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Extracts the named value from the response's `Set-Cookie` (a delete instruction = empty value is also returned as value).
pub fn set_cookie(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|raw| {
            let (pair, _) = raw.split_once(';').unwrap_or((raw, ""));
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
}

/// The raw string of one `Set-Cookie` in the response (when attributes must be verified too).
pub fn set_cookie_raw(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|raw| raw.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

pub fn assert_status(response: &Response<Body>, expected: StatusCode, context: &str) {
    assert_eq!(response.status(), expected, "{context}");
}
