//! Checks responses of passkey login completion (3 routes) through the router.
//!
//! What we want to see is "whether the result the api returned reaches the browser **in a form the screen can map to text**".
//! The script reads messages only from `#passkey-error` data attributes, so a code without a matching attribute
//! on screen falls back to the default text -- neither the response alone nor the screen alone reveals it.

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_text, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn stub_complete(env: &WebEnv, result: Value) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/login/complete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(result))
        .mount(&env.api)
        .await;
}

async fn complete(env: &WebEnv) -> Value {
    let response = send(
        &env.app,
        post_json(
            &format!("{}/passkey/login/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_str(&body_text(response).await).expect("json")
}

/// Passkey login in the authorization flow is also rate-limited (T39; consumes the same budget as direct login).
#[tokio::test]
async fn a_rate_limited_passkey_login_reports_a_code_the_screen_can_translate() {
    let env = setup().await;
    stub_complete(&env, json!({ "result": "rate_limited" })).await;

    let body = complete(&env).await;

    assert_eq!(body["error"], json!("rate_limited"));
    assert!(body["redirect_to"].is_null());
}
