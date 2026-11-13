//! Integration tests for the `client_credentials` grant (G4).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test client_credentials
//!
//! Key points checked:
//! - With no user, **neither an ID Token nor a Refresh Token is returned**.
//! - Clients not allowed (grant not registered, public) cannot use it.
//! - `/userinfo` rejects tokens from this grant, and `/introspect` treats them as active.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::Value;
use support::{body_json, send};

/// Builds the `Authorization: Basic` header value.
fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Sends `client_credentials` to `/token`.
async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
    scope: Option<&str>,
) -> axum::response::Response {
    let mut body = "grant_type=client_credentials".to_string();
    if let Some(s) = scope {
        body.push_str(&format!(
            "&scope={}",
            percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
        ));
    }
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn issues_an_access_token_without_an_id_token_or_refresh_token() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;

    assert_eq!(tokens["token_type"], "Bearer");
    // The only registrable scopes are the 4 OIDC values, all of which assume a user or are offline_access, so
    // no scope is carried by this token. Business permissions are decided by the app by `sub` (= client_id)
    // (ADR-0033).
    assert_eq!(
        tokens["scope"], "",
        "a token without a user carries no scope"
    );
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));
    // There is no user, so these two **must not exist** (it would violate the OIDC Core ID Token definition).
    assert_eq!(
        tokens["id_token"],
        Value::Null,
        "client_credentials does not return an ID Token"
    );
    assert_eq!(
        tokens["refresh_token"],
        Value::Null,
        "client_credentials does not return a Refresh Token"
    );
}

/// User-oriented scopes (`openid` / `profile` / `email`) are rejected for this grant even if registered.
/// Dropping them when omitted but accepting explicit requests would allow **tokens claiming user claims
/// without any user** (ADR-0033).
#[tokio::test]
async fn rejects_a_user_bound_scope_request() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("openid profile"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// `offline_access` is rejected for this grant even if registered (credentials can be presented again, so it is unnecessary).
#[tokio::test]
async fn rejects_offline_access() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;

    let response = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("offline_access"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// A confidential client that has not registered `client_credentials` cannot use it (disabled by default).
#[tokio::test]
async fn rejects_a_client_without_the_grant_registered() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "unauthorized_client");
}

/// Public clients cannot keep credentials secret, so they cannot use this grant.
#[tokio::test]
async fn rejects_a_public_client() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=client_credentials&client_id={client_id}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "unauthorized_client");
}

/// `/userinfo` accepts only user-subject tokens. `/introspect` treats it as active and
/// returns the client itself as `sub`.
#[tokio::test]
async fn the_token_is_rejected_by_userinfo_but_accepted_by_introspection() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let tokens =
        body_json(request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await)
            .await;
    let access_token = tokens["access_token"].as_str().expect("access token");

    // /userinfo: not a user subject, so 401 (tokens of this grant also have no scope).
    let response = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!("/{}/userinfo", env.root_tenant_id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "/userinfo cannot be fetched with a client_credentials token"
    );

    // /introspect: active. The subject is the client itself.
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/introspect", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(&client_id, &secret))
            .body(Body::from(format!("token={access_token}")))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let introspection = body_json(response).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["sub"], client_id);
    assert_eq!(introspection["client_id"], client_id);
}

/// Discovery advertises this grant (so RP metadata validation passes).
#[tokio::test]
async fn discovery_advertises_the_grant() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!(
                "/{}/.well-known/openid-configuration",
                env.root_tenant_id
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let doc = body_json(response).await;
    assert!(doc["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported")
        .iter()
        .any(|v| v == "client_credentials"));
}
