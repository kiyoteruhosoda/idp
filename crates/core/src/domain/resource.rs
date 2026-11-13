//! Protected resources — **the addressee of a token** (ADR-0042; RFC 8707).
//!
//! One row represents "a name this authorization server may put in `aud`". When
//! `client_credentials` requests `resource=<this name>`, the issued token's `aud` becomes this
//! value.
//!
//! # An addressee, not a destination
//!
//! **Nobody calls** this URI. The authorization server does not connect to it, and the resource
//! server need not listen there (in fact blobshare runs on a separate LAN port, not the public host
//! name). The name has the shape of a URI because that is a way of writing that does not collide
//! across organizations; an unresolvable form like `api://blobshare` is fine too. It is easy to
//! confuse with `redirect_uri`, but that is a **place** browsers are actually sent.
//!
//! # No vocabulary
//!
//! "What may be done there" (business permissions like `page:write`) is not registered here. The
//! resource server decides by `client_id` (ADR-0033). Only the addressee is carried because **the
//! addressee does not change but the permission model changes every time the app is fixed**;
//! holding both would make idp chase app changes.

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::ResourceStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Column limit of `resources.resource_uri`.
pub const RESOURCE_URI_MAX_LEN: usize = 255;
/// Column limit of `resources.display_name`.
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// A registered addressee.
#[derive(Debug, Clone)]
pub struct ProtectedResource {
    pub id: Uuid,
    /// The tenant owning this addressee. Uniqueness of addressees is closed within the tenant
    /// (ADR-0009 §1).
    pub tenant_id: TenantId,
    /// The exact value that goes into `aud`. Matching is **exact** (same policy as `redirect_uri`).
    pub resource_uri: String,
    pub display_name: String,
    pub status: ResourceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProtectedResource {
    /// Whether it can be used as the addressee of new tokens. `DISABLED` keeps the registration but
    /// stops issuance.
    pub fn is_active(&self) -> bool {
        self.status == ResourceStatus::Active
    }
}

/// Validates that the addressee can be registered and returns the value to store.
///
/// **Does not normalize.** Storing the result parsed by `url` (`https://example.com` →
/// `https://example.com/`) would make the registered string differ from the string in `aud`,
/// breaking exact matching at the resource server. Parsing is used only to check "absolute URI?"
/// and "no fragment?"; what is stored is the input itself (only surrounding whitespace is dropped).
///
/// Errors go back to the admin, but use translation keys like the other admin APIs (translation is
/// in the Presentation layer).
pub fn validate_resource_uri(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-resource-uri-required"));
    }
    // The column is VARCHAR(255) = **255 characters**, so count characters, not bytes (the same
    // measure as `display_name`; counting bytes would miss short names containing non-ASCII).
    if value.chars().count() > RESOURCE_URI_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-resource-uri-too-long",
            RESOURCE_URI_MAX_LEN.to_string(),
        ));
    }
    // Relative URIs are rejected by `Url::parse` (RFC 8707 §2 requires an absolute URI).
    let parsed = url::Url::parse(value).map_err(|_| MessageKey::new("api-resource-uri-invalid"))?;
    // Fragments are explicitly forbidden by RFC 8707 §2. Everything after `#` is not sent to the
    // server, so two addressees could be distinguished by an "invisible difference".
    if parsed.fragment().is_some() {
        return Err(MessageKey::new("api-resource-uri-fragment"));
    }
    Ok(value.to_string())
}

/// Validates the name shown on screen and returns the value to store.
pub fn validate_display_name(raw: &str) -> Result<String, MessageKey> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(MessageKey::new("api-resource-display-name-required"));
    }
    if value.chars().count() > DISPLAY_NAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-resource-display-name-too-long",
            DISPLAY_NAME_MAX_LEN.to_string(),
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_name_that_does_not_resolve() {
        // It is never called, so a nonexistent scheme is fine.
        assert_eq!(
            validate_resource_uri("api://blobshare").unwrap(),
            "api://blobshare"
        );
    }

    #[test]
    fn keeps_the_registered_string_as_it_is() {
        // Do not carry `Url` normalization (adding a trailing slash) into the stored value.
        assert_eq!(
            validate_resource_uri("  https://wiki.nolumia.com  ").unwrap(),
            "https://wiki.nolumia.com"
        );
    }

    #[test]
    fn rejects_relative_and_fragment_and_empty() {
        assert!(validate_resource_uri("/api/machine").is_err());
        assert!(validate_resource_uri("https://wiki.nolumia.com/#x").is_err());
        assert!(validate_resource_uri("   ").is_err());
    }

    #[test]
    fn rejects_a_name_longer_than_the_column() {
        let long = format!("https://example.com/{}", "a".repeat(RESOURCE_URI_MAX_LEN));
        assert!(validate_resource_uri(&long).is_err());
    }
}
