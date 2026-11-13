//! Progress state of SAML SP-initiated SSO (`saml_sso_requests`; temporary state equivalent to
//! OIDC's [`crate::domain::auth_session`]).
//!
//! `/{tenant_id}/saml/sso` validates the AuthnRequest, creates it, and hands off to web with a
//! single-use, short-lived handle (the ADR-0018 handoff scheme applied to SAML too). While SSO is
//! not established it resumes via the row id (web's host-only `saml_request_id` cookie), and it is
//! deleted when the response is issued.

use crate::domain::crypto;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// SHA-256 of `saml_request_id` (a random value web keeps in a host-only cookie).
/// Like auth_session_id it is a bearer credential, so only the hash is stored in the DB (SEC6).
pub fn id_hash(saml_request_id: &str) -> String {
    crypto::sha256_hex(saml_request_id)
}

#[derive(Debug, Clone)]
pub struct SamlSsoRequest {
    /// SHA-256 of `saml_request_id` ([`id_hash`]). The plaintext never goes here.
    pub id_hash: String,
    /// The tenant that started the flow (`/{tenant_id}/saml/sso`; ADR-0009 §8).
    pub tenant_id: TenantId,
    /// The resolved registered SP.
    pub service_provider_id: Uuid,
    /// Issuer of the AuthnRequest (the registered SP's entity_id; the response `Audience`).
    pub sp_entity_id: String,
    /// Verified assertion destination (the registered SP's acs_url).
    pub acs_url: String,
    /// ID of the AuthnRequest (the response `InResponseTo`; `None` when omitted).
    pub request_id: Option<String>,
    /// RelayState sent by the SP (returned transparently in the response form).
    pub relay_state: Option<String>,
    /// SHA-256 of the web handoff handle (single-use; consumed to `None` on exchange).
    pub handle_hash: Option<String>,
    /// Expiry of the handle (shorter-lived than the main `expires_at`).
    pub handle_expires_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl SamlSsoRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Whether the web handoff handle can be exchanged at `now` (unconsumed and unexpired).
    pub fn handle_is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.handle_hash.is_some() && self.handle_expires_at.is_some_and(|exp| exp > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn handle_validity_requires_both_hash_and_deadline() {
        let now = Utc::now();
        let mut request = SamlSsoRequest {
            id_hash: id_hash("r"),
            tenant_id: Uuid::now_v7().into(),
            service_provider_id: Uuid::nil(),
            sp_entity_id: "urn:sp".to_string(),
            acs_url: "https://sp.example.test/acs".to_string(),
            request_id: None,
            relay_state: None,
            handle_hash: Some("h".to_string()),
            handle_expires_at: Some(now + Duration::seconds(60)),
            expires_at: now + Duration::minutes(10),
            created_at: now,
        };
        assert!(request.handle_is_valid_at(now));
        assert!(!request.handle_is_valid_at(now + Duration::seconds(61)));
        // Consumed (NULL) is invalid (single-use).
        request.handle_hash = None;
        assert!(!request.handle_is_valid_at(now));
        // The main expiry.
        assert!(!request.is_expired_at(now));
        assert!(request.is_expired_at(now + Duration::minutes(10)));
    }
}
