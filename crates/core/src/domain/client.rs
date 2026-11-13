//! Clients entity (design spec §3.2).
#![allow(dead_code)]

use crate::domain::client_jwks::ClientJwks;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ClientStatus, ClientType, GrantType, TokenEndpointAuthMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
    /// The tenant the client belongs to (ADR-0009 §2. `client_id` is unique within a tenant).
    pub tenant_id: TenantId,
    pub client_id: String,
    /// Confidential clients only. Stored hashed.
    pub client_secret_hash: Option<String>,
    pub client_type: ClientType,
    pub client_status: ClientStatus,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Public keys for verifying `private_key_jwt` client assertions (ADR-0030). `None` for other
    /// methods. Verification looks only at this set (the client's `jwks_uri` is not fetched).
    pub jwks: Option<ClientJwks>,
    /// URIs registered as redirect targets after RP-initiated logout (F4).
    pub post_logout_redirect_uris: Vec<String>,
    /// iframe URI for front-channel logout (F4).
    pub frontchannel_logout_uri: Option<String>,
    /// HTTP POST target URI for back-channel logout (F4).
    pub backchannel_logout_uri: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    pub fn is_active(&self) -> bool {
        self.client_status == ClientStatus::Active
    }

    /// Whether logically deleted (ADR-0035). Used to exclude from list/get and to refuse updates.
    ///
    /// The authorization and token paths already reject via `is_active()`, so this check need not be added there.
    pub fn is_deleted(&self) -> bool {
        self.client_status == ClientStatus::Deleted
    }

    /// Whether `redirect_uri` exactly matches a registered value (design spec §2.3, §4.2).
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == redirect_uri)
    }

    /// Whether `post_logout_redirect_uri` exactly matches a registered value (F4 RP-initiated logout).
    pub fn allows_post_logout_redirect_uri(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris.iter().any(|u| u == uri)
    }

    /// Whether the requested scopes are all a subset of the registered scopes (design spec §4.2).
    pub fn allows_scopes(&self, requested: &[String]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }

    /// Whether the given grant_type is registered (G4).
    ///
    /// `client_credentials` is a strong permission to obtain access tokens with no user present, so it is limited to clients
    /// a tenant admin has explicitly enabled per client (being confidential is required separately).
    pub fn allows_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.iter().any(|g| g == grant_type.as_str())
    }

    /// Whether the client authenticates with `private_key_jwt` (a signed assertion) (ADR-0030).
    ///
    /// Always false for public clients: since they cannot keep a private key secret, key-pair authentication cannot hold either.
    pub fn uses_private_key_jwt(&self) -> bool {
        self.client_type == ClientType::Confidential
            && self.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
    }

    /// Whether server-to-server (M2M) token acquisition is allowed (G4).
    /// Public clients cannot keep credentials secret, so it is always disallowed even if permitted in the registration.
    pub fn allows_client_credentials(&self) -> bool {
        self.client_type == ClientType::Confidential
            && self.allows_grant_type(GrantType::ClientCredentials)
    }

    /// Whether this is a service account (ADR-0038): a client that runs only on `client_credentials` and is not
    /// used for user sign-in.
    ///
    /// The basis for separating app identities by kind (ADR-0059). Sign-in (`authorization_code`) and
    /// service accounts do not coexist in one client (ADR-0032 Revised), but even if an old registration
    /// has both, it is not treated as a service account: binding a party users come in through as a "machine identity"
    /// would drop the app from the sign-in checks.
    pub fn is_service_account(&self) -> bool {
        self.allows_client_credentials() && !self.allows_grant_type(GrantType::AuthorizationCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn client(client_type: ClientType, grant_types: &[&str]) -> Client {
        let now = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        Client {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from(Uuid::from_u128(2)),
            client_id: "c".to_string(),
            client_secret_hash: None,
            client_type,
            client_status: ClientStatus::Active,
            app_name: "app".to_string(),
            redirect_uris: vec![],
            grant_types: grant_types.iter().map(|s| s.to_string()).collect(),
            response_types: vec!["code".to_string()],
            scopes: vec![],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Public clients cannot use M2M even if permitted in the registration (they cannot keep a secret).
    #[test]
    fn client_credentials_requires_a_confidential_client_and_an_explicit_grant() {
        assert!(client(
            ClientType::Confidential,
            &["authorization_code", "client_credentials"]
        )
        .allows_client_credentials());
        assert!(
            !client(ClientType::Confidential, &["authorization_code"]).allows_client_credentials()
        );
        assert!(!client(
            ClientType::Public,
            &["authorization_code", "client_credentials"]
        )
        .allows_client_credentials());
    }
}
