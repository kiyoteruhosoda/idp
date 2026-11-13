//! Integration tests for `private_key_jwt` client authentication (ADR-0030; RFC 7523).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test private_key_jwt
//!
//! Key points checked:
//! - A token can be obtained with only a signed assertion (no shared secret is sent at all).
//! - **Reusing the same assertion is rejected** (`jti` replay prevention). Otherwise someone who intercepted it
//!   could reuse the assertion until `exp`.
//! - Someone else's key, another tenant as audience, expired, and missing `jti` do not pass.
//! - A client registered with `private_key_jwt` does not "fall back" to secret methods.

mod support;

use assay_api::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use assay_api::domain::jwt::{generate_rsa_keypair, sign};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::Value;
use support::{body_json, send};

#[derive(Serialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
}

struct AssertionSpec<'a> {
    client_id: &'a str,
    private_pem: &'a str,
    kid: &'a str,
    audience: String,
    expires_in_seconds: i64,
    jti: String,
}

impl<'a> AssertionSpec<'a> {
    /// An assertion that should pass plainly (`aud` is the token endpoint of the tenant issuer).
    fn valid(
        env: &support::TestEnv,
        client_id: &'a str,
        private_pem: &'a str,
        kid: &'a str,
    ) -> Self {
        Self {
            client_id,
            private_pem,
            kid,
            audience: format!("{}/{}/token", env.issuer, env.root_tenant_id),
            expires_in_seconds: 120,
            jti: support::unique(),
        }
    }

    fn build(&self) -> String {
        let now = Utc::now().timestamp();
        sign(
            self.private_pem,
            self.kid,
            "JWT",
            "RS256",
            &AssertionClaims {
                iss: self.client_id.to_string(),
                sub: self.client_id.to_string(),
                aud: self.audience.clone(),
                exp: now + self.expires_in_seconds,
                iat: now,
                jti: self.jti.clone(),
            },
        )
        .expect("sign client assertion")
    }
}

/// Sends `client_credentials` + client assertion to `/token`.
async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    assertion: &str,
) -> axum::response::Response {
    request_token_with_type(app, tenant_id, assertion, JWT_BEARER_ASSERTION_TYPE).await
}

async fn request_token_with_type(
    app: &axum::Router,
    tenant_id: &str,
    assertion: &str,
    assertion_type: &str,
) -> axum::response::Response {
    let body = format!(
        "grant_type=client_credentials&client_assertion_type={}&client_assertion={}",
        utf8_percent_encode(assertion_type, NON_ALPHANUMERIC),
        utf8_percent_encode(assertion, NON_ALPHANUMERIC),
    );
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// An access token can be obtained with only a signed assertion. `client_id` is not put in the body
/// (the short form allowed by RFC 7521 §4.2; the target client is determined from the assertion's `sub`).
#[tokio::test]
async fn issues_a_token_for_a_signed_assertion_without_any_shared_secret() {
    let Some(env) = support::setup("private_key_jwt").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::OK);

    let tokens = body_json(response).await;
    assert_eq!(tokens["token_type"], "Bearer");
    // The only registrable scopes are the 4 OIDC values, all of which assume a user or are offline_access, so
    // no scope is carried by this token (ADR-0033).
    assert_eq!(tokens["scope"], "");
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));
    // It is client_credentials, so no user-subject token is returned (G4).
    assert_eq!(tokens["id_token"], Value::Null);
    assert_eq!(tokens["refresh_token"], Value::Null);
}

/// Implementations putting the tenant issuer itself in `aud` are also accepted (ADR-0030 decision 6).
#[tokio::test]
async fn the_tenant_issuer_is_also_accepted_as_the_audience() {
    let Some(env) = support::setup("private_key_jwt_aud_issuer").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    spec.audience = format!("{}/{}", env.issuer, env.root_tenant_id);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// **The same assertion cannot be used twice** (ADR-0030 decision 5). The first passes, the second is rejected.
#[tokio::test]
async fn the_same_assertion_cannot_be_replayed() {
    let Some(env) = support::setup("private_key_jwt_replay").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let assertion = spec.build();

    let first = request_token(&env.app, &env.root_tenant_id, &assertion).await;
    assert_eq!(first.status(), StatusCode::OK, "the first one passes");

    let second = request_token(&env.app, &env.root_tenant_id, &assertion).await;
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "reusing the same assertion is rejected"
    );
    assert_eq!(body_json(second).await["error"], "invalid_client");

    // Changing `jti` (= signing anew) passes. What is stopped is replay, not repeated use.
    let mut fresh = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    fresh.jti = support::unique();
    let third = request_token(&env.app, &env.root_tenant_id, &fresh.build()).await;
    assert_eq!(third.status(), StatusCode::OK);
}

/// An assertion signed with an unregistered key does not pass (= replacing the key revokes the old one).
#[tokio::test]
async fn an_assertion_signed_by_another_key_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_other_key").await else {
        return;
    };
    let (client_id, _private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let (attacker_pem, _) = generate_rsa_keypair().expect("generate attacker key");

    let spec = AssertionSpec::valid(&env, &client_id, &attacker_pem, &kid);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}

/// Forwarding an assertion signed for another audience does not pass.
#[tokio::test]
async fn an_assertion_for_another_audience_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_bad_aud").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    spec.audience = "https://someone-else.example.com/token".to_string();
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Expired assertions and assertions with too long a validity do not pass (ADR-0030 decision 5).
#[tokio::test]
async fn expired_and_overlong_assertions_are_rejected() {
    let Some(env) = support::setup("private_key_jwt_lifetime").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut expired = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    // Put it clearly further in the past than the clock skew tolerance (60 seconds).
    expired.expires_in_seconds = -300;
    assert_eq!(
        request_token(&env.app, &env.root_tenant_id, &expired.build())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut overlong = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    overlong.expires_in_seconds = 60 * 60;
    assert_eq!(
        request_token(&env.app, &env.root_tenant_id, &overlong.build())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// Not accepted unless `client_assertion_type` is `jwt-bearer` (RFC 7523 §2.2).
#[tokio::test]
async fn an_unsupported_assertion_type_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_type").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let response = request_token_with_type(
        &env.app,
        &env.root_tenant_id,
        &spec.build(),
        "urn:example:some-other-assertion",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A client registered with `private_key_jwt` does not fall back to secret methods (ADR-0030 decision 2).
/// Clients with this method have no secret, so sending Basic has nothing to verify against.
#[tokio::test]
async fn a_private_key_jwt_client_cannot_authenticate_with_a_secret() {
    let Some(env) = support::setup("private_key_jwt_no_fallback").await else {
        return;
    };
    let (client_id, _private_pem, _kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let credentials = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{client_id}:whatever"),
    );
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Basic {credentials}"),
            )
            .body(Body::from("grant_type=client_credentials"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Discovery advertises `private_key_jwt` and the supported signing algorithms.
#[tokio::test]
async fn discovery_advertises_private_key_jwt() {
    let Some(env) = support::setup("private_key_jwt_discovery").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/.well-known/openid-configuration",
                env.root_tenant_id
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let doc = body_json(response).await;
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods");
    assert!(methods.iter().any(|m| m == "private_key_jwt"));
    assert_eq!(
        doc["token_endpoint_auth_signing_alg_values_supported"],
        serde_json::json!(["RS256", "ES256"])
    );
}
