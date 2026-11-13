//! Integration tests (with DB) for external OIDC IdP discovery import
//! (`POST /{tenant}/admin/external-idps/import-discovery`; task #77).
//!
//! The fetch rules (no redirect following, size cap) are pinned by unit tests of `infrastructure::external_oidc`
//! with wiremock. Here, as an admin API, we check:
//!
//! - No credentials → 401, no external IdP write permission → 403
//! - For an issuer that fails the destination check, **not a single outbound request is made**
//! - If the document's `issuer` differs from the input, it is refused (OIDC Discovery §4.3)
//! - **Import is not registration** (not a single provider is added)
//!
//! The component that makes outbound HTTP is replaced by a fake (wiremock listens on `http://127.0.0.1`, so it
//! would fail the real destination check. No endpoint to loosen the check is created).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test external_oidc_discovery_import

mod support;

use assay_api::application::external_idp_discovery::ExternalIdpDiscoveryService;
use assay_api::domain::error::Result as DomainResult;
use assay_api::domain::external_oidc_port::OidcDiscoveryClient;
use assay_api::domain::oidc_discovery::{DiscoveryUrl, OidcDiscoveryDocument};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use std::sync::{Arc, Mutex};
use support::{admin_token, body_json, create_plain_user, post, send, unique, TestEnv};

/// When the counterpart's issuer is this value, the fake returns a document claiming **a different issuer** (to check §4.3).
const MISMATCHING_ISSUER: &str = "https://mismatch.idp.example.com";

/// A fake that records the requested URL and returns the document for that issuer.
#[derive(Default)]
struct FakeDiscovery {
    fetched: Mutex<Vec<String>>,
}

#[async_trait]
impl OidcDiscoveryClient for FakeDiscovery {
    async fn fetch_discovery(&self, url: &DiscoveryUrl) -> DomainResult<OidcDiscoveryDocument> {
        self.fetched.lock().unwrap().push(url.as_str().to_string());
        let base = url.issuer().trim_end_matches('/').to_string();
        let issuer = if url.issuer() == MISMATCHING_ISSUER {
            "https://someone-else.example.com".to_string()
        } else {
            url.issuer().to_string()
        };
        Ok(OidcDiscoveryDocument {
            issuer: Some(issuer),
            authorization_endpoint: Some(format!("{base}/authorize")),
            token_endpoint: Some(format!("{base}/token")),
            jwks_uri: Some(format!("{base}/jwks")),
        })
    }
}

async fn setup(test_name: &str) -> Option<(TestEnv, Arc<FakeDiscovery>)> {
    let fake = Arc::new(FakeDiscovery::default());
    let client = fake.clone();
    let env = support::setup_with(test_name, move |state| {
        state.external_idp_discovery = Arc::new(ExternalIdpDiscoveryService::new(client));
    })
    .await?;
    Some((env, fake))
}

fn uri(env: &TestEnv) -> String {
    format!(
        "/{}/admin/external-idps/import-discovery",
        env.root_tenant_id
    )
}

/// Number of providers with that issuer. Not counted across the whole tenant (another test binary registers
/// into the same root tenant in parallel).
async fn providers_with_issuer(env: &TestEnv, issuer: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_identity_providers WHERE tenant_id = ? AND issuer = ?",
    )
    .bind(&env.root_tenant_id)
    .bind(issuer)
    .fetch_one(&env.pool)
    .await
    .expect("count providers")
}

/// No credentials gives 401, no external IdP write permission gives 403. Neither goes outbound.
#[tokio::test]
async fn the_import_requires_the_external_idp_write_permission() {
    let Some((env, fake)) = setup("oidc discovery import auth").await else {
        return;
    };
    let body = json!({ "issuer": "https://idp.example.com" });

    let anonymous = Request::builder()
        .method(Method::POST)
        .uri(uri(&env))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        send(&env.app, anonymous).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(&env.app, post(&plain_token, &uri(&env), body)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no perms -> 403");

    assert!(
        fake.fetched.lock().unwrap().is_empty(),
        "an unauthorized request must not reach out"
    );
}

/// Endpoints are filled from the discovery document under the issuer. **It does not register.**
#[tokio::test]
async fn the_document_fills_the_endpoints_without_registering_anything() {
    let Some((env, fake)) = setup("oidc discovery import ok").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let issuer = format!("https://idp-{}.example.com/realms/corp", unique());

    let res = send(
        &env.app,
        post(&admin_tok, &uri(&env), json!({ "issuer": issuer })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let imported = body_json(res).await;
    assert_eq!(imported["issuer"], json!(issuer));
    assert_eq!(
        imported["authorization_endpoint"],
        json!(format!("{issuer}/authorize"))
    );
    assert_eq!(imported["token_endpoint"], json!(format!("{issuer}/token")));
    assert_eq!(imported["jwks_uri"], json!(format!("{issuer}/jwks")));
    assert_eq!(
        *fake.fetched.lock().unwrap(),
        vec![format!("{issuer}/.well-known/openid-configuration")]
    );

    // Import is not registration.
    assert_eq!(
        providers_with_issuer(&env, &issuer).await,
        0,
        "importing a discovery document must not register a provider"
    );
}

/// Issuers failing the destination check (http, loopback, private, link-local) get 400, and
/// **not a single outbound request is made** (no SSRF; ADR-0023 decision 5).
#[tokio::test]
async fn internal_or_plain_http_issuers_are_rejected_before_reaching_out() {
    let Some((env, fake)) = setup("oidc discovery import ssrf").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    for issuer in [
        "http://idp.example.com",
        "https://127.0.0.1",
        "https://localhost:8443",
        "https://10.0.0.5",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]",
        "not a url",
    ] {
        let res = send(
            &env.app,
            post(&admin_tok, &uri(&env), json!({ "issuer": issuer })),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{issuer}");
    }
    assert!(
        fake.fetched.lock().unwrap().is_empty(),
        "rejected issuers must never be fetched"
    );
}

/// If the document's `issuer` differs from the input it is refused (OIDC Discovery §4.3). Nothing is registered either.
#[tokio::test]
async fn a_document_for_another_issuer_is_rejected() {
    let Some((env, _fake)) = setup("oidc discovery import mismatch").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri(&env),
            json!({ "issuer": MISMATCHING_ISSUER }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = body_json(res).await;
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("does not match")),
        "{body}"
    );
    assert_eq!(providers_with_issuer(&env, MISMATCHING_ISSUER).await, 0);
}
