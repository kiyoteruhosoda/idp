//! Integration tests for `client_secret_post` client authentication (G3; RFC 6749 §2.3.1).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test client_secret_post
//!
//! Key points checked:
//! - Authentication passes only with the registered method (a client registered for Basic must not pass via the body,
//!   and vice versa). Letting any method through would make `token_endpoint_auth_method` "a value that can be set
//!   but has no effect".
//! - Presenting both in one request is rejected with `invalid_request` (§2.3.1).
//! - Not only `/token` but also `/introspect` and `/revoke` pass with the same method
//!   (RFC 7009 §2.1, RFC 7662 §2.1).

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use support::{body_json, send};

const POST: &str = "client_secret_post";
const BASIC: &str = "client_secret_basic";

fn basic_header(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn encode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Sends a form-urlencoded `POST` (attaches the Authorization header only when `basic` is passed).
async fn post_form(
    app: &axum::Router,
    uri: String,
    body: String,
    basic: Option<(&str, &str)>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some((id, secret)) = basic {
        builder = builder.header(AUTHORIZATION, basic_header(id, secret));
    }
    send(app, builder.body(Body::from(body)).unwrap()).await
}

/// Calls `/token` with the `client_credentials` grant (the goal is only to verify client authentication,
/// and this grant needs no user).
async fn token_with_body_credentials(
    env: &support::TestEnv,
    client_id: &str,
    secret: &str,
) -> axum::response::Response {
    post_form(
        &env.app,
        format!("/{}/token", env.root_tenant_id),
        format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            encode(client_id),
            encode(secret)
        ),
        None,
    )
    .await
}

#[tokio::test]
async fn a_client_secret_post_client_authenticates_with_body_credentials() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        POST,
    )
    .await;

    let response = token_with_body_credentials(&env, &client_id, &secret).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));
}

/// A wrong secret naturally fails (confirms verification works on the body path too).
#[tokio::test]
async fn a_wrong_body_secret_is_rejected() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, _) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        POST,
    )
    .await;

    let response = token_with_body_credentials(&env, &client_id, "wrong-secret").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}

/// A client registered with `client_secret_post` does not pass with a Basic header.
#[tokio::test]
async fn a_client_secret_post_client_cannot_use_the_basic_header() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        POST,
    )
    .await;

    let response = post_form(
        &env.app,
        format!("/{}/token", env.root_tenant_id),
        "grant_type=client_credentials".to_string(),
        Some((&client_id, &secret)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}

/// The reverse: a client registered with `client_secret_basic` does not pass with a secret in the body.
#[tokio::test]
async fn a_client_secret_basic_client_cannot_use_body_credentials() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        BASIC,
    )
    .await;

    let response = token_with_body_credentials(&env, &client_id, &secret).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}

/// RFC 6749 §2.3.1: a request must not use more than one authentication method.
#[tokio::test]
async fn presenting_both_methods_is_an_invalid_request() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        POST,
    )
    .await;

    let response = post_form(
        &env.app,
        format!("/{}/token", env.root_tenant_id),
        format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            encode(&client_id),
            encode(&secret)
        ),
        Some((&client_id, &secret)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_request");
}

/// `/introspect` and `/revoke` can authenticate with the same method as `/token`.
#[tokio::test]
async fn introspection_and_revocation_accept_body_credentials() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client_with_auth_method(
        &env.pool,
        &env.root_tenant_id,
        &["openid"],
        POST,
    )
    .await;

    let issued = body_json(token_with_body_credentials(&env, &client_id, &secret).await).await;
    let access_token = issued["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let credentials = format!(
        "client_id={}&client_secret={}",
        encode(&client_id),
        encode(&secret)
    );

    let introspected = post_form(
        &env.app,
        format!("/{}/introspect", env.root_tenant_id),
        format!("token={}&{credentials}", encode(&access_token)),
        None,
    )
    .await;
    assert_eq!(introspected.status(), StatusCode::OK);
    assert_eq!(body_json(introspected).await["active"], true);

    let revoked = post_form(
        &env.app,
        format!("/{}/revoke", env.root_tenant_id),
        format!("token={}&{credentials}", encode(&access_token)),
        None,
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);

    // After revocation it is inactive (confirms `/revoke` passed authentication and actually took effect).
    let after = post_form(
        &env.app,
        format!("/{}/introspect", env.root_tenant_id),
        format!("token={}&{credentials}", encode(&access_token)),
        None,
    )
    .await;
    assert_eq!(body_json(after).await["active"], false);
}

/// `/introspect` without credentials is 401 (public clients cannot use it either; RFC 7662 §2.1).
#[tokio::test]
async fn introspection_without_credentials_is_unauthorized() {
    let Some(env) = support::setup("client_secret_post").await else {
        return;
    };
    let response = post_form(
        &env.app,
        format!("/{}/introspect", env.root_tenant_id),
        "token=whatever".to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}
