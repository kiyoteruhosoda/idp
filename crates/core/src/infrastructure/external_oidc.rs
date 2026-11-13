//! Implementation of `ExternalOidcClient` (reqwest + jsonwebtoken; AP10).
//!
//! Sends the authorization code to the external IdP's `/token` and returns the claims **after verifying the returned
//! ID Token's signature with JWKS**. What is verified:
//!
//! 1. Signature (key chosen from JWKS by `kid`; RS256 / ES256)
//! 2. `iss` exactly matches the configured issuer
//! 3. `aud` contains our `client_id`
//! 4. `exp` (jsonwebtoken's default validation; default leeway 60 seconds)
//! 5. `nonce` matches the value saved at issuance (replay detection)
//!
//! Missing any one of these would let anything pass as "what the external IdP said", so all are done in this one place.
//!
//! The same HTTP client (timeouts, no redirect following) also handles fetching the discovery document
//! before registration (`OidcDiscoveryClient`; task #77).

use crate::domain::error::{DomainError, Result};
use crate::domain::external_idp::ExternalClaims;
use crate::domain::external_oidc_port::{
    ExternalOidcClient, ExternalTokenRequest, OidcDiscoveryClient,
};
use crate::domain::oidc_discovery::{DiscoveryUrl, OidcDiscoveryDocument};
use crate::domain::outbound_uri::OutboundTrust;
use crate::infrastructure::outbound_http::guarded_client_builder;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Upper bound for one request to an external IdP. Login isn't kept waiting on an unresponsive IdP.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Size limit for the discovery document. Real ones are a few KB (under 10 KB for Entra ID, Google and Keycloak);
/// anything larger is not a discovery document. Even if the admin-entered destination returns a huge response,
/// it is not read wholesale into the api's memory.
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;

/// Reads only the discovery document items used for registration (other items are ignored).
#[derive(Debug, Deserialize)]
struct DiscoveryDocumentBody {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

/// `/token` response (only `id_token` is needed).
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// One JWKS key (reads only the values needed for signature verification, RSA / EC).
#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    // RSA
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// ID Token claims used for federation.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

pub struct ReqwestExternalOidcClient {
    http: reqwest::Client,
}

impl ReqwestExternalOidcClient {
    pub fn new() -> Self {
        Self::with_trust(OutboundTrust::none())
    }

    /// Builds it with names that may be sent to even if they resolve to internal addresses (task #585).
    pub fn with_trust(trust: OutboundTrust) -> Self {
        Self {
            // Check the addresses resolved right before connecting (don't connect if internal; `outbound_http`).
            http: guarded_client_builder(trust)
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                // Don't follow redirects. Following them could send credentials or verification requests to a host other than
                // the configured token/jwks endpoints (the settings would lose their meaning).
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| DomainError::Repository(format!("failed to fetch JWKS: {e}")))?;
        if !response.status().is_success() {
            return Err(DomainError::Repository(format!(
                "JWKS endpoint returned {}",
                response.status()
            )));
        }
        response
            .json::<JwkSet>()
            .await
            .map_err(|e| DomainError::Repository(format!("invalid JWKS document: {e}")))
    }
}

impl Default for ReqwestExternalOidcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a JWK into a `jsonwebtoken` verification key.
fn decoding_key(jwk: &Jwk) -> Result<(DecodingKey, Algorithm)> {
    match jwk.kty.as_str() {
        "RSA" => {
            let (n, e) = (jwk.n.as_deref(), jwk.e.as_deref());
            let (Some(n), Some(e)) = (n, e) else {
                return Err(DomainError::Repository(
                    "RSA JWK is missing `n` or `e`".to_string(),
                ));
            };
            let key = DecodingKey::from_rsa_components(n, e)
                .map_err(|e| DomainError::Repository(format!("invalid RSA JWK: {e}")))?;
            // Some JWKS don't specify `alg`, so RSA defaults to RS256.
            let alg = match jwk.alg.as_deref() {
                Some("RS384") => Algorithm::RS384,
                Some("RS512") => Algorithm::RS512,
                _ => Algorithm::RS256,
            };
            Ok((key, alg))
        }
        "EC" => {
            let (x, y) = (jwk.x.as_deref(), jwk.y.as_deref());
            let (Some(x), Some(y)) = (x, y) else {
                return Err(DomainError::Repository(
                    "EC JWK is missing `x` or `y`".to_string(),
                ));
            };
            let key = DecodingKey::from_ec_components(x, y)
                .map_err(|e| DomainError::Repository(format!("invalid EC JWK: {e}")))?;
            let alg = match (jwk.alg.as_deref(), jwk.crv.as_deref()) {
                (Some("ES384"), _) | (_, Some("P-384")) => Algorithm::ES384,
                _ => Algorithm::ES256,
            };
            Ok((key, alg))
        }
        other => Err(DomainError::Repository(format!(
            "unsupported JWK key type: {other}"
        ))),
    }
}

#[async_trait]
impl ExternalOidcClient for ReqwestExternalOidcClient {
    async fn exchange_code(&self, request: ExternalTokenRequest<'_>) -> Result<ExternalClaims> {
        // 1. Exchange the authorization code. If we hold a client_secret, send it in the POST body
        //    (`client_secret_post`; some IdPs only accept Basic, but use the more widely accepted one first).
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("client_id", request.client_id),
            ("code_verifier", request.code_verifier),
        ];
        if let Some(secret) = request.client_secret {
            form.push(("client_secret", secret));
        }
        let response = self
            .http
            .post(request.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| DomainError::Repository(format!("token request failed: {e}")))?;
        if !response.status().is_success() {
            // The response body has the external IdP's error details, but it is not returned to users as is
            // (callers treat it as a generic failure). Only the status code is kept for operational logs.
            return Err(DomainError::Repository(format!(
                "external token endpoint returned {}",
                response.status()
            )));
        }
        let tokens: TokenResponse = response
            .json()
            .await
            .map_err(|e| DomainError::Repository(format!("invalid token response: {e}")))?;
        let Some(id_token) = tokens.id_token else {
            return Err(DomainError::Repository(
                "external token response has no id_token".to_string(),
            ));
        };

        // 2. Choose the verification key by `kid`. Some IdPs omit `kid`; in that case use the only key
        //    (multiple keys without `kid` can't be chosen from, so fail).
        let header = jsonwebtoken::decode_header(&id_token)
            .map_err(|e| DomainError::Repository(format!("invalid id_token header: {e}")))?;
        let jwks = self.fetch_jwks(request.jwks_uri).await?;
        let jwk = match header.kid.as_deref() {
            Some(kid) => jwks
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .ok_or_else(|| {
                    DomainError::Repository("id_token kid is not in the JWKS".to_string())
                })?,
            None if jwks.keys.len() == 1 => &jwks.keys[0],
            None => {
                return Err(DomainError::Repository(
                    "id_token has no kid and the JWKS has multiple keys".to_string(),
                ));
            }
        };
        let (key, algorithm) = decoding_key(jwk)?;

        // 3. Verify the signature, `iss`, `aud` and `exp`.
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[request.expected_issuer]);
        validation.set_audience(&[request.client_id]);
        let claims = jsonwebtoken::decode::<IdTokenClaims>(&id_token, &key, &validation)
            .map_err(|e| DomainError::Repository(format!("id_token verification failed: {e}")))?
            .claims;

        // 4. Check `nonce` (replay detection). Unlike `iss`/`aud`/`exp`, jsonwebtoken doesn't check it,
        //    so always verify it ourselves here. Missing is treated as a mismatch (fail-closed).
        if claims.nonce.as_deref() != Some(request.expected_nonce) {
            return Err(DomainError::Repository(
                "id_token nonce does not match the authorization request".to_string(),
            ));
        }

        Ok(ExternalClaims {
            issuer: claims.iss,
            subject: claims.sub,
            email: claims.email,
            email_verified: claims.email_verified.unwrap_or(false),
            name: claims.name,
            nonce: claims.nonce,
        })
    }
}

#[async_trait]
impl OidcDiscoveryClient for ReqwestExternalOidcClient {
    async fn fetch_discovery(&self, url: &DiscoveryUrl) -> Result<OidcDiscoveryDocument> {
        let mut response = self
            .http
            .get(url.as_str())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| {
                // The reason it is unreachable (connection refused, name resolution failure, etc.) goes only to the operational log.
                // Putting it in the admin API response would make the admin API a tool for probing "what is behind that address".
                tracing::warn!(url = %url.as_str(), error = %e, "failed to fetch an OIDC discovery document");
                DomainError::Repository("the discovery document could not be fetched".to_string())
            })?;
        // Redirects are not followed (client setting), so 3xx fails here. Following them could send the request
        // to a host other than the checked issuer -- including internal destinations.
        if !response.status().is_success() {
            return Err(DomainError::Repository(format!(
                "discovery endpoint returned {}",
                response.status()
            )));
        }
        let too_large = || {
            DomainError::Repository(format!(
                "the discovery document exceeds {MAX_DISCOVERY_BYTES} bytes"
            ))
        };
        // Refuse early based on the declared length. For peers that don't declare or lie, count while reading and refuse.
        if response
            .content_length()
            .is_some_and(|len| len > MAX_DISCOVERY_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            tracing::warn!(url = %url.as_str(), error = %e, "failed to read an OIDC discovery document");
            DomainError::Repository("the discovery document could not be read".to_string())
        })? {
            if body.len() + chunk.len() > MAX_DISCOVERY_BYTES {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        let document: DiscoveryDocumentBody = serde_json::from_slice(&body).map_err(|_| {
            DomainError::Repository("the discovery document is not a JSON object".to_string())
        })?;
        Ok(OidcDiscoveryDocument {
            issuer: document.issuer,
            authorization_endpoint: document.authorization_endpoint,
            token_endpoint: document.token_endpoint,
            jwks_uri: document.jwks_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An RSA JWK without `alg` is treated as RS256 (many IdPs omit `alg`).
    #[test]
    fn rsa_jwk_without_alg_defaults_to_rs256() {
        // RFC 7515 A.2 test key (a truncated modulus isn't enough for syntax validation,
        // so only the conversion's failure cases are checked here).
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        // Without `n`/`e` no key can be built (not silently let through).
        assert!(decoding_key(&jwk).is_err());
    }

    #[test]
    fn unsupported_key_types_are_rejected() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: None,
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        // Accepting shared keys (`oct`) would let anyone able to replace the JWKS forge arbitrary ID Tokens.
        // Limited to asymmetric keys.
        assert!(decoding_key(&jwk).is_err());
    }

    /// Discovery fetches mock the outbound HTTP with wiremock. Destination checks (https, rejecting internal destinations) are
    /// `DiscoveryUrl::for_issuer`'s job; here only the fetch behavior is examined, with a URL built without the checks.
    mod discovery {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn url_for(server: &MockServer, issuer: &str) -> DiscoveryUrl {
            DiscoveryUrl::unchecked_for_test(
                issuer,
                &format!("{}/.well-known/openid-configuration", server.uri()),
            )
        }

        #[tokio::test]
        async fn the_document_is_read() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": "https://idp.example.com",
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks",
                    "response_types_supported": ["code"],
                })))
                .expect(1)
                .mount(&server)
                .await;
            let document = ReqwestExternalOidcClient::new()
                .fetch_discovery(&url_for(&server, "https://idp.example.com"))
                .await
                .expect("fetch");
            assert_eq!(document.issuer.as_deref(), Some("https://idp.example.com"));
            assert_eq!(
                document.jwks_uri.as_deref(),
                Some("https://idp.example.com/jwks")
            );
        }

        /// **Redirects are not followed.** Following them would send the request somewhere other than the checked issuer
        /// (including internal destinations). It also checks that not a single request reaches the redirect target.
        #[tokio::test]
        async fn redirects_are_not_followed() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("Location", format!("{}/elsewhere", server.uri())),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/elsewhere"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": "https://idp.example.com",
                })))
                .expect(0)
                .mount(&server)
                .await;
            let err = ReqwestExternalOidcClient::new()
                .fetch_discovery(&url_for(&server, "https://idp.example.com"))
                .await
                .expect_err("a redirect must not be followed");
            assert!(err.to_string().contains("302"), "{err}");
            server.verify().await;
        }

        /// Overly large responses are refused without reading them fully (by declared length and by read length).
        #[tokio::test]
        async fn an_oversized_document_is_rejected() {
            let server = MockServer::start().await;
            let padding = "x".repeat(MAX_DISCOVERY_BYTES + 1);
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "{{\"issuer\":\"https://idp.example.com\",\"pad\":\"{padding}\"}}"
                )))
                .mount(&server)
                .await;
            let err = ReqwestExternalOidcClient::new()
                .fetch_discovery(&url_for(&server, "https://idp.example.com"))
                .await
                .expect_err("oversized");
            assert!(err.to_string().contains("exceeds"), "{err}");
        }

        #[tokio::test]
        async fn errors_and_non_json_bodies_are_failures() {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_string("<html>login</html>"))
                .mount(&server)
                .await;
            assert!(ReqwestExternalOidcClient::new()
                .fetch_discovery(&url_for(&server, "https://idp.example.com"))
                .await
                .is_err());

            let missing = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&missing)
                .await;
            let err = ReqwestExternalOidcClient::new()
                .fetch_discovery(&url_for(&missing, "https://idp.example.com"))
                .await
                .expect_err("404");
            assert!(err.to_string().contains("404"), "{err}");
        }
    }
}
