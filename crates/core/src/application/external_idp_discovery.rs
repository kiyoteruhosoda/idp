//! Importing an external IdP's (OIDC) discovery document (task #77).
//!
//! Reads `{issuer}/.well-known/openid-configuration` from the issuer an admin entered and returns initial
//! values for the registration form (`authorization_endpoint` / `token_endpoint` / `jwks_uri`). **Importing is not registering**
//! ——nothing is saved and nothing is audited (same as importing SAML IdP metadata). Registration
//! happens via `ExternalIdpManagementService::register` after the admin has checked the values.
//!
//! The order is what matters.
//!
//! 1. Check the destination ([`DiscoveryUrl::for_issuer`]; https only, internal destinations rejected). **If it fails,
//!    not a single request goes out.**
//! 2. Fetch ([`OidcDiscoveryClient`]; no redirect following, timeout, size limit)
//! 3. Verify the document ([`OidcDiscoveryDocument::verify_for`]; exact `issuer` match and checks on each endpoint)
//!
//! [`OidcDiscoveryDocument::verify_for`]: crate::domain::oidc_discovery::OidcDiscoveryDocument::verify_for

use crate::domain::error::DomainError;
use crate::domain::external_oidc_port::OidcDiscoveryClient;
use crate::domain::oidc_discovery::{DiscoveryUrl, ImportedOidcProvider};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryImportError {
    /// The input (issuer) or the fetched document is unacceptable (destination check, `issuer` mismatch, missing fields).
    #[error("validation error: {0}")]
    Validation(String),
    /// Could not fetch the document (unreachable, non-2xx, redirect, too large, not JSON).
    #[error("discovery document unavailable: {0}")]
    Unavailable(String),
}

pub struct ExternalIdpDiscoveryService {
    client: Arc<dyn OidcDiscoveryClient>,
}

impl ExternalIdpDiscoveryService {
    pub fn new(client: Arc<dyn OidcDiscoveryClient>) -> Self {
        Self { client }
    }

    /// Reads the issuer's discovery document and returns candidate values for registration (saves nothing).
    pub async fn import(&self, issuer: &str) -> Result<ImportedOidcProvider, DiscoveryImportError> {
        let url = DiscoveryUrl::for_issuer(issuer).map_err(validation)?;
        let document = self
            .client
            .fetch_discovery(&url)
            .await
            .map_err(|e| match e {
                // The fetch implementation keeps connection-level details (why it was unreachable) only in the operations log, not here.
                DomainError::Repository(m) => DiscoveryImportError::Unavailable(m),
                other => DiscoveryImportError::Unavailable(other.to_string()),
            })?;
        document.verify_for(&url).map_err(validation)
    }
}

fn validation(e: DomainError) -> DiscoveryImportError {
    match e {
        DomainError::InvalidValue(m) => DiscoveryImportError::Validation(m),
        other => DiscoveryImportError::Validation(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result;
    use crate::domain::oidc_discovery::OidcDiscoveryDocument;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A fake that only records fetches. Used to confirm nothing went out before the destination check.
    struct RecordingClient {
        document: std::result::Result<OidcDiscoveryDocument, String>,
        fetched: Mutex<Vec<String>>,
    }

    impl RecordingClient {
        fn returning(document: std::result::Result<OidcDiscoveryDocument, String>) -> Arc<Self> {
            Arc::new(Self {
                document,
                fetched: Mutex::new(Vec::new()),
            })
        }

        fn fetched(&self) -> Vec<String> {
            self.fetched.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl OidcDiscoveryClient for RecordingClient {
        async fn fetch_discovery(&self, url: &DiscoveryUrl) -> Result<OidcDiscoveryDocument> {
            self.fetched.lock().unwrap().push(url.as_str().to_string());
            match &self.document {
                Ok(d) => Ok(d.clone()),
                Err(m) => Err(DomainError::Repository(m.clone())),
            }
        }
    }

    fn document(issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: Some(issuer.to_string()),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            jwks_uri: Some("https://idp.example.com/jwks".to_string()),
        }
    }

    #[tokio::test]
    async fn the_document_under_the_issuer_is_imported() {
        let client = RecordingClient::returning(Ok(document("https://idp.example.com")));
        let imported = ExternalIdpDiscoveryService::new(client.clone())
            .import("https://idp.example.com")
            .await
            .expect("import");
        assert_eq!(imported.token_endpoint, "https://idp.example.com/token");
        assert_eq!(
            client.fetched(),
            vec!["https://idp.example.com/.well-known/openid-configuration"]
        );
    }

    /// An issuer that fails the destination check makes **not a single outbound request** (no SSRF).
    #[tokio::test]
    async fn internal_destinations_are_never_fetched() {
        for issuer in [
            "http://idp.example.com",
            "https://169.254.169.254",
            "https://127.0.0.1:8443",
            "https://localhost",
            "https://192.168.1.10",
        ] {
            let client = RecordingClient::returning(Ok(document(issuer)));
            let err = ExternalIdpDiscoveryService::new(client.clone())
                .import(issuer)
                .await
                .expect_err("must be rejected");
            assert!(
                matches!(err, DiscoveryImportError::Validation(_)),
                "{issuer}: {err}"
            );
            assert!(client.fetched().is_empty(), "{issuer} must not be fetched");
        }
    }

    #[tokio::test]
    async fn an_issuer_mismatch_is_rejected() {
        let client = RecordingClient::returning(Ok(document("https://evil.example.com")));
        let err = ExternalIdpDiscoveryService::new(client)
            .import("https://idp.example.com")
            .await
            .expect_err("mismatch");
        assert!(
            matches!(&err, DiscoveryImportError::Validation(m) if m.contains("does not match")),
            "{err}"
        );
    }

    /// A fetch failure is kept separate from `Validation` (not an input error; the peer's document could not be fetched).
    #[tokio::test]
    async fn fetch_failures_are_reported_as_unavailable() {
        let client = RecordingClient::returning(Err(
            "discovery endpoint returned 404 Not Found".to_string()
        ));
        let err = ExternalIdpDiscoveryService::new(client)
            .import("https://idp.example.com")
            .await
            .expect_err("unavailable");
        assert!(
            matches!(&err, DiscoveryImportError::Unavailable(m) if m.contains("404")),
            "{err}"
        );
    }
}
