//! External IdP authentication (AP10; user authentication / auth policy spec §13).
//!
//! Types for accepting an authentication result at an external OpenID Provider as an assay login.
//!
//! # Identity rests only on `iss` + `sub`
//!
//! The only basis for linking an external account to an assay user is `iss` + `sub` (§13.2). We do
//! not link by email address because if the external IdP lets emails be changed or reused,
//! **someone else could claim the same email and get into an existing account**. There is demand to
//! auto-link by email match on first login, so that is an explicit per-provider setting
//! (`allow_auto_link`), where the operator takes responsibility that "the external IdP verifies
//! email ownership".
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Scopes requested from external IdPs by default.
pub const DEFAULT_SCOPES: [&str; 3] = ["openid", "profile", "email"];

/// Protocol of the external IdP (ADR-0027). The single source of allowed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExternalIdpProtocol {
    #[default]
    Oidc,
    Saml,
}

impl ExternalIdpProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }

    /// Interprets stored / input values. Unknown values are **an error, not coerced to the
    /// default**. Coercing would treat a configuration registered as SAML as OIDC, changing the
    /// verification requirements with it.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw.trim() {
            "oidc" => Ok(Self::Oidc),
            "saml" => Ok(Self::Saml),
            other => Err(DomainError::InvalidValue(format!(
                "unsupported external IdP protocol: {other}"
            ))),
        }
    }
}

/// OIDC-specific settings of an external IdP.
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// Client secret (ciphertext). `None` when registered as a public client.
    pub client_secret_encrypted: Option<String>,
    pub scopes: Vec<String>,
}

impl OidcProviderConfig {
    /// Scopes put in the authorization request (default when unset). `openid` is always included
    /// (an ID Token is needed).
    pub fn effective_scopes(&self) -> Vec<String> {
        let mut scopes: Vec<String> = if self.scopes.is_empty() {
            DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
        } else {
            self.scopes.clone()
        };
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".to_string());
        }
        scopes
    }
}

/// SAML-specific settings of an external IdP (SP side; ADR-0027).
#[derive(Debug, Clone)]
pub struct SamlProviderConfig {
    /// The IdP's `SingleSignOnService` URL (where AuthnRequests are sent with the HTTP-Redirect
    /// binding).
    pub sso_url: String,
    /// X.509 certificates for signature verification (base64 DER). **Several can be held** — during
    /// an IdP certificate rollover old and new are valid at once, and holding only one would stop
    /// logins at every rollover.
    pub certificates: Vec<String>,
    /// `NameIDFormat` requested in the `AuthnRequest`.
    pub name_id_format: String,
}

/// Protocol-specific settings. **Which combinations are valid** is expressed here (the DB merely
/// sets unused columns to NULL, so this enum is the single source of validity).
#[derive(Debug, Clone)]
pub enum ExternalIdpConfig {
    Oidc(OidcProviderConfig),
    Saml(SamlProviderConfig),
}

impl ExternalIdpConfig {
    pub fn protocol(&self) -> ExternalIdpProtocol {
        match self {
            Self::Oidc(_) => ExternalIdpProtocol::Oidc,
            Self::Saml(_) => ExternalIdpProtocol::Saml,
        }
    }

    pub fn as_oidc(&self) -> Option<&OidcProviderConfig> {
        match self {
            Self::Oidc(c) => Some(c),
            Self::Saml(_) => None,
        }
    }

    pub fn as_saml(&self) -> Option<&SamlProviderConfig> {
        match self {
            Self::Saml(c) => Some(c),
            Self::Oidc(_) => None,
        }
    }
}

/// One external IdP configured for a tenant.
///
/// `issuer` is **the trust anchor shared by both protocols** (ADR-0027). In OIDC it is the ID
/// Token's `iss`, in SAML the Response / Assertion `<Issuer>` (the IdP's entityID); both are "the
/// identifier of the issuer that made the claim", so `user_external_identities.external_issuer` can
/// be used in the same form.
#[derive(Debug, Clone)]
pub struct ExternalIdentityProvider {
    pub id: Uuid,
    pub tenant_id: TenantId,
    /// Identifier code unique within the tenant (appears in URL paths).
    pub provider_code: String,
    pub display_name: String,
    /// The external IdP's issuer (OIDC: ID Token `iss` / SAML: IdP entityID). Matched exactly.
    pub issuer: String,
    /// Protocol-specific settings.
    pub config: ExternalIdpConfig,
    pub enabled: bool,
    /// Whether to auto-link to an existing user on verified email match.
    pub allow_auto_link: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ExternalIdentityProvider {
    /// Format check of `provider_code` (alphanumerics, `-`, `_`, `.`, 1–100 characters).
    /// Limited to characters that can go as is into URL path segments and audit logs
    /// (same criteria as `AuthenticationPolicy::validate_code`).
    pub fn validate_code(code: &str) -> Result<(), DomainError> {
        if code.is_empty() || code.len() > 100 {
            return Err(DomainError::InvalidValue(
                "provider code must be 1-100 characters".to_string(),
            ));
        }
        if !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(DomainError::InvalidValue(
                "provider code must contain only ASCII alphanumerics, '-', '_' or '.'".to_string(),
            ));
        }
        Ok(())
    }

    /// Endpoint URL validation.
    ///
    /// Only `https`, refusing internal destinations (loopback, private IPs, etc.). External IdP
    /// endpoints are fetched by assay's server itself, so loosening this would make the admin API
    /// an SSRF stepping stone (same reason as back-channel logout URIs; SEC2).
    pub fn validate_endpoint(url: &str, field: &str) -> Result<(), DomainError> {
        let parsed = url::Url::parse(url.trim())
            .map_err(|_| DomainError::InvalidValue(format!("{field} must be a valid URL")))?;
        if parsed.scheme() != "https" {
            return Err(DomainError::InvalidValue(format!("{field} must use https")));
        }
        if crate::domain::outbound_uri::is_internal_destination(url) {
            return Err(DomainError::InvalidValue(format!(
                "{field} must not point at an internal destination"
            )));
        }
        Ok(())
    }

    pub fn protocol(&self) -> ExternalIdpProtocol {
        self.config.protocol()
    }
}

/// Mapping between an identity at an external IdP and an assay user.
#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_id: Uuid,
    pub external_issuer: String,
    pub external_subject: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Progress state from the redirect to the external IdP until the callback.
#[derive(Debug, Clone)]
pub struct ExternalLoginRequest {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub provider_id: Uuid,
    /// SHA-256 of `state` (`RelayState` in SAML). The raw value is handled only as the value
    /// returned from the external IdP.
    pub state_hash: String,
    /// A value we create and the other side returns. **The key to replay detection.** In OIDC it is
    /// the ID Token's `nonce`, in SAML the `AuthnRequest`'s `ID` (matched against the response's
    /// `InResponseTo`). Same role, so one column holds it.
    pub nonce: String,
    /// PKCE `code_verifier` (ciphertext). **`None` for SAML** (there is no PKCE equivalent).
    pub code_verifier_encrypted: Option<String>,
    /// `id_hash` of the calling OIDC auth_session (`None` when via the portal).
    /// auth_session_id is a bearer credential, so the copy is also kept as a hash (SEC6).
    pub auth_session_id_hash: Option<String>,
    /// SHA-256 of the value (cookie) given only to the browser that started (task #581). Checked at
    /// the return point, blocking login CSRF that **makes someone else's browser follow the return
    /// URL** (logging them in to the attacker's account). `state` goes through the external IdP
    /// into the URL, so it alone cannot identify the browser.
    pub browser_binding_hash: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl ExternalLoginRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Whether the returning browser is the one that started (task #581).
    ///
    /// Progress states without a start value (created before this check existed) are not let
    /// through either — there is no way to confirm which browser started, so the user is asked to
    /// start over (lifetime is 10 minutes).
    pub fn is_bound_to(&self, presented: Option<&str>) -> bool {
        match (self.browser_binding_hash.as_deref(), presented) {
            (Some(expected), Some(presented)) if !presented.is_empty() => {
                let presented = crate::domain::crypto::sha256_hex(presented);
                // It compares hashes, but avoid exiting early on length and content anyway.
                expected.len() == presented.len()
                    && expected
                        .bytes()
                        .zip(presented.bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                        == 0
            }
            _ => false,
        }
    }
}

/// Claims needed for linking, taken from the external IdP's ID Token.
#[derive(Debug, Clone)]
pub struct ExternalClaims {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    /// Whether the external IdP claims it verified email ownership. A prerequisite for
    /// auto-linking.
    pub email_verified: bool,
    pub name: Option<String>,
    /// The ID Token's `nonce` (matched against the stored value for replay detection).
    pub nonce: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(scopes: Vec<String>) -> OidcProviderConfig {
        OidcProviderConfig {
            authorization_endpoint: "https://idp.corp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.corp.example.com/token".to_string(),
            jwks_uri: "https://idp.corp.example.com/jwks".to_string(),
            client_id: "client".to_string(),
            client_secret_encrypted: None,
            scopes,
        }
    }

    #[test]
    fn provider_code_validation_rejects_unsafe_values() {
        assert!(ExternalIdentityProvider::validate_code("corp-sso.v2").is_ok());
        assert!(ExternalIdentityProvider::validate_code("").is_err());
        assert!(ExternalIdentityProvider::validate_code(&"a".repeat(101)).is_err());
        assert!(ExternalIdentityProvider::validate_code("slash/code").is_err());
        assert!(ExternalIdentityProvider::validate_code("スペース あり").is_err());
    }

    /// Endpoints are https only; internal destinations are refused (not an SSRF stepping stone).
    #[test]
    fn endpoints_must_be_public_https_urls() {
        assert!(ExternalIdentityProvider::validate_endpoint(
            "https://idp.example.com/authorize",
            "authorization_endpoint"
        )
        .is_ok());
        for bad in [
            "http://idp.example.com/authorize",
            "https://127.0.0.1/authorize",
            "https://localhost/authorize",
            "https://10.0.0.5/authorize",
            "not-a-url",
        ] {
            assert!(
                ExternalIdentityProvider::validate_endpoint(bad, "authorization_endpoint").is_err(),
                "{bad} must be rejected"
            );
        }
    }

    /// `openid` is always requested (without an ID Token, `iss`+`sub` cannot be obtained).
    #[test]
    fn openid_scope_is_always_requested() {
        assert_eq!(
            provider(Vec::new()).effective_scopes(),
            vec!["openid", "profile", "email"]
        );
        assert_eq!(
            provider(vec!["email".to_string()]).effective_scopes(),
            vec!["openid", "email"]
        );
        assert_eq!(
            provider(vec!["openid".to_string(), "groups".to_string()]).effective_scopes(),
            vec!["openid", "groups"]
        );
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// Unknown protocols are an error, not coerced to the default. Coercing would treat a
    /// configuration registered as SAML as OIDC, changing the verification requirements with it.
    #[test]
    fn unknown_protocols_are_rejected_not_defaulted() {
        assert_eq!(
            ExternalIdpProtocol::parse("oidc").unwrap(),
            ExternalIdpProtocol::Oidc
        );
        assert_eq!(
            ExternalIdpProtocol::parse("saml").unwrap(),
            ExternalIdpProtocol::Saml
        );
        assert!(ExternalIdpProtocol::parse("ws-fed").is_err());
        assert!(ExternalIdpProtocol::parse("").is_err());
    }
}
