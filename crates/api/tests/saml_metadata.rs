//! Integration tests (with DB) for SAML IdP metadata output (public).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_metadata

mod support;

use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, StatusCode};
use support::{anonymous, send};

/// IdP metadata is published without authentication, uses the tenant issuer as entityID, and returns
/// well-formed XML containing the ACTIVE signing key.
#[tokio::test]
async fn idp_metadata_is_public_and_tenant_scoped() {
    let Some(env) = support::setup("saml idp metadata").await else {
        return;
    };
    let uri = format!("/{}/saml/metadata", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/xml; charset=utf-8"),
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let xml = String::from_utf8(bytes.to_vec()).expect("utf8");
    let tenant_issuer = format!("{}/{}", env.issuer, env.root_tenant_id);
    assert!(
        xml.contains(&format!("entityID=\"{tenant_issuer}\"")),
        "entityID must be the tenant issuer: {xml}"
    );
    // It is IdP metadata (IDPSSODescriptor + SSO), not SP metadata.
    assert!(xml.contains("IDPSSODescriptor"), "IDPSSODescriptor: {xml}");
    assert!(!xml.contains("SPSSODescriptor"));
    assert!(
        xml.contains(&format!("{tenant_issuer}/saml/sso")),
        "SSO URL"
    );
    // The bootstrapped ACTIVE signing key is embedded as RSAKeyValue.
    assert!(
        xml.contains("<md:KeyDescriptor use=\"signing\">"),
        "signing KeyDescriptor: {xml}"
    );
    assert!(xml.contains("<ds:RSAKeyValue>"));
}

/// Lists every published key as a `KeyDescriptor` (ADR-0039 / T33).
///
/// ADR-0039 removed the JWKS-side gap with "publish, then sign", but SAML metadata was emitting
/// only one `KeyDescriptor`. **To SPs the certificate appeared to swap at the moment signing switched,
/// and verification failed until they re-imported.**
///
/// Checks it is the same set as JWKS (= neither side goes stale alone).
#[tokio::test]
async fn idp_metadata_publishes_every_key_the_jwks_does() {
    let Some(env) = support::setup("saml idp metadata key window").await else {
        return;
    };

    let jwks_uri = format!("/{}/.well-known/jwks.json", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &jwks_uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let jwks: serde_json::Value = serde_json::from_slice(&bytes).expect("jwks json");
    let published = jwks["keys"].as_array().expect("keys").len();
    assert!(published >= 1, "at least one key is published");

    let uri = format!("/{}/saml/metadata", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let xml = String::from_utf8(bytes.to_vec()).expect("utf8");

    let descriptors = xml.matches("<md:KeyDescriptor use=\"signing\">").count();
    assert_eq!(
        descriptors, published,
        "lists as many as JWKS (JWKS {published} / metadata {descriptors}): {xml}"
    );
}
