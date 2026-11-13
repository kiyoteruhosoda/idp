//! web side of binding SSO sessions to the device key (Chrome DBSC; task #887, ADR-0074).
//!
//! - Entry: for a bound sign-in state without a matching short Cookie, strip the long Cookie (not passed to the api)
//! - Entry: with a matching short Cookie, pass without asking the api
//! - Shape of the `/dbsc/register` and `/dbsc/refresh` responses
//! - `allowed_refresh_initiators` in the register/refresh responses so requests started from each app can refresh too (task #934)

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_contracts::session_key as contract;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::{
    body_text, get_with_cookies, send, set_cookie, setup, setup_with_env, WebEnv, TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "session-bound-to-a-key";
const PROFILE: &str = "/internal/account/profile";
const BINDING: &str = "/internal/sso/key-binding";
const IDENTIFIER: &str = "0123456789abcdef0123456789abcdef";

async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

/// Requests passed to the api whose body contains this SSO session's value.
async fn calls_carrying_the_session(env: &WebEnv) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() != BINDING && String::from_utf8_lossy(&r.body).contains(SSO))
        .count()
}

async fn mount_bound(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(BINDING))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "bound",
            "session_identifier": IDENTIFIER,
        })))
        .with_priority(1)
        .mount(&env.api)
        .await;
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn valid_short_cookie() -> String {
    contract::bound_cookie(TEST_CSRF_SECRET, SSO, now() + 300)
}

fn post(uri: &str, cookies: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("cookie", cookies);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn a_bound_session_without_the_short_cookie_does_not_reach_the_api() {
    let env = setup().await;
    mount_bound(&env).await;
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
        ),
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK);
    assert_eq!(calls_to(&env, BINDING).await, 1);
    assert_eq!(calls_carrying_the_session(&env).await, 0);
}

#[tokio::test]
async fn a_short_cookie_for_another_session_or_expired_does_not_help() {
    let env = setup().await;
    mount_bound(&env).await;
    for short in [
        contract::bound_cookie(TEST_CSRF_SECRET, "someone-else", now() + 300),
        contract::bound_cookie(TEST_CSRF_SECRET, SSO, now() - 1),
        contract::bound_cookie(b"another-secret-for-the-test-32b!", SSO, now() + 300),
    ] {
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/settings", env.prefix()),
                &format!(
                    "{SSO_SESSION_COOKIE}={SSO}; {}={short}",
                    contract::BOUND_COOKIE
                ),
            ),
        )
        .await;
    }
    assert_eq!(calls_carrying_the_session(&env).await, 0);
}

#[tokio::test]
async fn a_valid_short_cookie_passes_without_asking_the_api() {
    let env = setup().await;
    mount_bound(&env).await;
    send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings", env.prefix()),
            &format!(
                "{SSO_SESSION_COOKIE}={SSO}; {}={}",
                contract::BOUND_COOKIE,
                valid_short_cookie()
            ),
        ),
    )
    .await;
    assert_eq!(calls_to(&env, BINDING).await, 0);
    assert!(calls_to(&env, PROFILE).await > 0);
}

#[tokio::test]
async fn an_unbound_session_passes_as_before() {
    let env = setup().await;
    send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
        ),
    )
    .await;
    assert_eq!(calls_to(&env, BINDING).await, 1);
    assert!(calls_to(&env, PROFILE).await > 0);
}

#[tokio::test]
async fn registration_answers_the_session_config_and_sets_the_short_cookie() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/sso/key-binding/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "bound",
            "session_identifier": IDENTIFIER,
            "remaining_secs": 2_592_000u64,
        })))
        .mount(&env.api)
        .await;
    let response = send(
        &env.app,
        post(
            "/dbsc/register",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[(contract::RESPONSE_HEADER, "a.b.c")],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let short = set_cookie(&response, contract::BOUND_COOKIE).expect("short cookie");
    assert!(contract::bound_cookie_is_valid(
        TEST_CSRF_SECRET,
        SSO,
        &short,
        now()
    ));
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some(SSO)
    );
    // The binding endpoint is not a login (does not ask for binding again).
    assert!(response
        .headers()
        .get(contract::REGISTRATION_HEADER)
        .is_none());
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(body["session_identifier"], IDENTIFIER);
    assert_eq!(body["refresh_url"], contract::REFRESH_PATH);
    assert_eq!(body["scope"]["include_site"], false);
    assert_eq!(body["credentials"][0]["type"], "cookie");
    assert_eq!(body["credentials"][0]["name"], contract::BOUND_COOKIE);
    // Without configuration, only assay itself (empty list).
    assert_eq!(body["allowed_refresh_initiators"], json!([]));
}

const INITIATORS: &str = "*.nolumia.com";

async fn mount_refresh_bound(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/sso/key-binding/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "bound",
            "session_identifier": IDENTIFIER,
            "remaining_secs": 2_592_000u64,
        })))
        .mount(&env.api)
        .await;
}

#[tokio::test]
async fn registration_allows_refreshes_started_by_the_configured_hosts() {
    let env = setup_with_env(&[("DBSC_ALLOWED_REFRESH_INITIATORS", INITIATORS)]).await;
    Mock::given(method("POST"))
        .and(path("/internal/sso/key-binding/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "bound",
            "session_identifier": IDENTIFIER,
            "remaining_secs": 2_592_000u64,
        })))
        .mount(&env.api)
        .await;
    let response = send(
        &env.app,
        post(
            "/dbsc/register",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[(contract::RESPONSE_HEADER, "a.b.c")],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    // Draft §9.6: placed at the outermost level, not inside the scope.
    assert_eq!(body["allowed_refresh_initiators"], json!([INITIATORS]));
    assert!(body["scope"].get("allowed_refresh_initiators").is_none());
}

/// Return the same setting in the refresh response too, so it reaches sign-in states bound before the setting was added (draft §8.8, §8.9).
#[tokio::test]
async fn a_signed_refresh_answers_the_same_session_config() {
    let env = setup_with_env(&[("DBSC_ALLOWED_REFRESH_INITIATORS", INITIATORS)]).await;
    mount_refresh_bound(&env).await;
    let response = send(
        &env.app,
        post(
            "/dbsc/refresh",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[
                (contract::SESSION_ID_HEADER, IDENTIFIER),
                (contract::RESPONSE_HEADER, "a.b.c"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let short = set_cookie(&response, contract::BOUND_COOKIE).expect("short cookie");
    assert!(contract::bound_cookie_is_valid(
        TEST_CSRF_SECRET,
        SSO,
        &short,
        now()
    ));
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    // Draft §8.9: on refresh, binding ends unless the identifier is the same as now.
    assert_eq!(body["session_identifier"], IDENTIFIER);
    assert_eq!(body["refresh_url"], contract::REFRESH_PATH);
    assert_eq!(body["scope"]["include_site"], false);
    assert_eq!(body["credentials"][0]["name"], contract::BOUND_COOKIE);
    assert_eq!(body["allowed_refresh_initiators"], json!([INITIATORS]));
}

#[tokio::test]
async fn registration_without_a_proof_or_session_is_refused() {
    let env = setup().await;
    let no_proof = send(
        &env.app,
        post(
            "/dbsc/register",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[],
        ),
    )
    .await;
    assert_eq!(no_proof.status(), StatusCode::BAD_REQUEST);
    let no_session = send(
        &env.app,
        post(
            "/dbsc/register",
            "lang=ja",
            &[(contract::RESPONSE_HEADER, "a.b.c")],
        ),
    )
    .await;
    assert_eq!(no_session.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        calls_to(&env, "/internal/sso/key-binding/register").await,
        0
    );
}

#[tokio::test]
async fn a_refresh_without_a_proof_gets_a_challenge_for_this_session() {
    let env = setup().await;
    mount_bound(&env).await;
    let response = send(
        &env.app,
        post(
            "/dbsc/refresh",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[(contract::SESSION_ID_HEADER, IDENTIFIER)],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let header = response
        .headers()
        .get(contract::CHALLENGE_HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("challenge header")
        .to_string();
    let challenge = header.split('"').nth(1).unwrap();
    assert!(contract::challenge_is_fresh(
        TEST_CSRF_SECRET,
        SSO,
        challenge,
        now()
    ));
    assert!(header.ends_with(&format!(";id=\"{IDENTIFIER}\"")));
}

#[tokio::test]
async fn a_refresh_for_another_identifier_ends_the_binding() {
    let env = setup().await;
    mount_bound(&env).await;
    let response = send(
        &env.app,
        post(
            "/dbsc/refresh",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[(contract::SESSION_ID_HEADER, &"f".repeat(32))],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(body["continue"], false);
}

#[tokio::test]
async fn a_refresh_signed_by_another_key_ends_the_session_and_its_cookies() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/sso/key-binding/refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "key_mismatch" })))
        .mount(&env.api)
        .await;
    let response = send(
        &env.app,
        post(
            "/dbsc/refresh",
            &format!("{SSO_SESSION_COOKIE}={SSO}"),
            &[
                (contract::SESSION_ID_HEADER, IDENTIFIER),
                (contract::RESPONSE_HEADER, "a.b.c"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some("")
    );
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(body["continue"], false);
}
