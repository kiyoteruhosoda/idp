//! Importing an external OpenID Provider's discovery document (task #77; OIDC Discovery 1.0).
//!
//! Registering an external IdP (OIDC) requires copying `authorization_endpoint` / `token_endpoint`
//! / `jwks_uri` one by one from the provider's document. Providers publish it at
//! `{issuer}/.well-known/openid-configuration`, so entering just the issuer can fill in the rest.
//! As with SAML IdP metadata import ([`crate::domain::saml_metadata`]), **import is not
//! registration** — what is built here is the initial value of the registration form; the admin
//! checks it before registering.
//!
//! Unlike SAML import, **assay's server itself sends HTTP to an admin-entered URL.** Therefore:
//!
//! - The fetch target can only be expressed as a [`DiscoveryUrl`]. This type can only be built
//!   after the issuer passed the ADR-0023 decision 5 check (https only, internal destinations
//!   refused; [`ExternalIdentityProvider::validate_endpoint`]), and the fetch port
//!   ([`crate::domain::external_oidc_port::OidcDiscoveryClient`]) accepts only this type. A path
//!   that fetches an unchecked URL cannot be built at the type level.
//! - If the `issuer` in the document differs from the input by even one character, refuse (OIDC
//!   Discovery §4.3). Accepting a document with a different issuer would make the ID Token `iss`
//!   check (exact match) fail on every login, or register another issuer's values.
//! - Endpoints from the document go through the same check as at registration. The document is not
//!   admin input, but once registered assay connects there (internal destinations are never filled
//!   into the form).

use crate::domain::error::DomainError;
use crate::domain::external_idp::ExternalIdentityProvider;

/// Location of the discovery document (OIDC Discovery §4).
pub const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// URL of a discovery document whose destination passed the check.
///
/// **Has no way to be built without the check** (except the `#[cfg(test)]` test helper). The fetch
/// implementation accepts only this type, so no path can forget to call the SSRF check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryUrl {
    /// The issuer requested for import (trimmed of surrounding whitespace). Used for the §4.3
    /// match.
    issuer: String,
    url: String,
}

impl DiscoveryUrl {
    /// Builds the discovery document URL from the issuer.
    ///
    /// The issuer must be https and not an internal destination (same as the `issuer` check at
    /// registration). Issuers with a query or fragment are invalid in OIDC and refused (OIDC
    /// Discovery §2 / Core §2 `iss`). The trailing `/` is removed before appending
    /// `/.well-known/openid-configuration` (§4.1).
    pub fn for_issuer(issuer: &str) -> Result<Self, DomainError> {
        let issuer = issuer.trim();
        ExternalIdentityProvider::validate_endpoint(issuer, "issuer")?;
        let parsed = url::Url::parse(issuer)
            .map_err(|_| DomainError::InvalidValue("issuer must be a valid URL".to_string()))?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(DomainError::InvalidValue(
                "issuer must not contain a query or fragment".to_string(),
            ));
        }
        let url = format!("{}{WELL_KNOWN_PATH}", issuer.trim_end_matches('/'));
        // The built URL also goes through the same check (guaranteeing by check, not by reasoning
        // about the construction, that appending strings did not change how the destination is
        // interpreted).
        ExternalIdentityProvider::validate_endpoint(&url, "issuer")?;
        Ok(Self {
            issuer: issuer.to_string(),
            url,
        })
    }

    /// For tests: builds without the destination check (wiremock listens on `http://127.0.0.1`).
    #[cfg(test)]
    pub(crate) fn unchecked_for_test(issuer: &str, url: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            url: url.to_string(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }
}

/// Items of the discovery document used to register an external IdP (as fetched; unverified).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcDiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

/// Imported candidate values for registration (verified). Presented as the registration form's
/// initial values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedOidcProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl OidcDiscoveryDocument {
    /// Verifies the document against the issuer requested for import and returns candidate values.
    ///
    /// 1. The document's `issuer` **exactly matches** the requested issuer (§4.3; a trailing `/`
    ///    counts too — the ID Token's `iss` is also matched exactly against this value, so rounding
    ///    here breaks every login after registration)
    /// 2. All three endpoints are present (assay uses only authorization code + JWKS verification)
    /// 3. Each endpoint passes the same check as at registration (https only, internal destinations
    ///    refused)
    pub fn verify_for(self, requested: &DiscoveryUrl) -> Result<ImportedOidcProvider, DomainError> {
        let issuer = self.issuer.unwrap_or_default();
        if issuer != requested.issuer() {
            return Err(DomainError::InvalidValue(format!(
                "the discovery document's issuer \"{issuer}\" does not match the requested issuer \"{}\"",
                requested.issuer()
            )));
        }
        let required = |value: Option<String>, field: &str| -> Result<String, DomainError> {
            let value = value
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    DomainError::InvalidValue(format!("the discovery document has no {field}"))
                })?;
            ExternalIdentityProvider::validate_endpoint(&value, field)?;
            Ok(value)
        };
        Ok(ImportedOidcProvider {
            authorization_endpoint: required(
                self.authorization_endpoint,
                "authorization_endpoint",
            )?,
            token_endpoint: required(self.token_endpoint, "token_endpoint")?,
            jwks_uri: required(self.jwks_uri, "jwks_uri")?,
            issuer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: Some(issuer.to_string()),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            jwks_uri: Some("https://idp.example.com/jwks".to_string()),
        }
    }

    /// The trailing `/` is removed before appending well-known (§4.1). For an issuer with a path
    /// (per-tenant IdP) it goes after the path.
    #[test]
    fn the_discovery_url_is_built_under_the_issuer() {
        assert_eq!(
            DiscoveryUrl::for_issuer("https://idp.example.com")
                .unwrap()
                .as_str(),
            "https://idp.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            DiscoveryUrl::for_issuer(" https://idp.example.com/tenant-a/ ")
                .unwrap()
                .as_str(),
            "https://idp.example.com/tenant-a/.well-known/openid-configuration"
        );
    }

    /// Checks the destination **before fetching** (not becoming an SSRF stepping stone; ADR-0023
    /// decision 5).
    #[test]
    fn internal_or_plain_http_issuers_are_rejected_before_any_request() {
        for bad in [
            "http://idp.example.com",
            "https://127.0.0.1",
            "https://localhost",
            "https://169.254.169.254/latest",
            "https://10.0.0.5",
            "https://[::1]",
            "https://idp.example.com?x=1",
            "https://idp.example.com#frag",
            "not a url",
            "",
        ] {
            assert!(
                DiscoveryUrl::for_issuer(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn a_matching_document_yields_the_registration_values() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        let imported = document("https://idp.example.com")
            .verify_for(&url)
            .unwrap();
        assert_eq!(imported.issuer, "https://idp.example.com");
        assert_eq!(
            imported.authorization_endpoint,
            "https://idp.example.com/authorize"
        );
        assert_eq!(imported.token_endpoint, "https://idp.example.com/token");
        assert_eq!(imported.jwks_uri, "https://idp.example.com/jwks");
    }

    /// Refuses when the document's `issuer` differs from the input (§4.3). A trailing `/`
    /// difference counts as a difference.
    #[test]
    fn an_issuer_mismatch_is_rejected() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        for other in [
            "https://evil.example.com",
            "https://idp.example.com/",
            "https://IDP.example.com",
        ] {
            let err = document(other).verify_for(&url).unwrap_err();
            assert!(err.to_string().contains("does not match"), "{other}: {err}");
        }
        let missing = OidcDiscoveryDocument {
            issuer: None,
            ..document("https://idp.example.com")
        };
        assert!(missing.verify_for(&url).is_err());
    }

    /// Endpoints from the document go through the same check as at registration (internal
    /// destinations are not filled into the form).
    #[test]
    fn endpoints_from_the_document_must_be_public_https() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        let internal = OidcDiscoveryDocument {
            token_endpoint: Some("https://10.0.0.5/token".to_string()),
            ..document("https://idp.example.com")
        };
        assert!(internal.verify_for(&url).is_err());
        let plain = OidcDiscoveryDocument {
            jwks_uri: Some("http://idp.example.com/jwks".to_string()),
            ..document("https://idp.example.com")
        };
        assert!(plain.verify_for(&url).is_err());
        let missing = OidcDiscoveryDocument {
            jwks_uri: None,
            ..document("https://idp.example.com")
        };
        assert!(missing.verify_for(&url).is_err());
    }
}
