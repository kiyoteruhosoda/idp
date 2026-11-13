//! Domains exclusively assigned to a tenant (MT25; ADR-0029).
//!
//! One row means "users who claim this domain are users of this tenant". When the login field gets
//! input in the form `local@domain`, it is used to **determine the single home tenant** from the
//! domain (home realm discovery). Once the home tenant is known, only that tenant's registry is
//! searched, avoiding a cross scan of participating guests — that scan was exactly the cause of
//! "two guests with the same name joining locks both out"
//! (`crate::application::login_user_resolution`).
//!
//! # Why domains
//!
//! Extending identifier uniqueness across tenants would match the resolution scope, but would break
//! ADR-0009 §1's tenant independence (once one tenant took `admin`, no other tenant could use it).
//! With domains, what is contested is decided by ownership, so tenants do not share an inventory of
//! names. Entra ID's UPN is globally unique for the same reason: what is unique is not a global
//! space but "domain × local part within it".

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Column limit for `tenant_domains.domain` (253, same as the DNS name limit).
pub const DOMAIN_MAX_LEN: usize = 253;
/// DNS label length limit.
const LABEL_MAX_LEN: usize = 63;

#[derive(Debug, Clone)]
pub struct TenantDomain {
    pub id: Uuid,
    /// The tenant owning this domain.
    pub tenant_id: TenantId,
    /// Normalized domain ([`normalize_domain`]).
    pub domain: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Normalizes a domain into a match key (lowercase, trim whitespace and trailing dot).
///
/// The trailing dot is dropped because `corp.example.` and `corp.example` name the same thing in
/// DNS. Keeping it would let two tenants claim the same domain separately, making the unique
/// constraint meaningless.
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Validates that a domain can be registered and returns the normalized value.
///
/// **Accepts only A-labels (punycode).** Allowing Unicode domains as is would let the same name be
/// registered two ways, as a U-label and an A-label, slipping past the unique constraint. Input
/// `local@domain` is matched with the same normalization, so input typed as U-labels does not take
/// the domain path (it just falls back to the old guest scan; it does not become unable to sign
/// in).
///
/// Errors go back to admins, not users, but use translation keys like the other admin APIs
/// (translation is in the Presentation layer).
pub fn validate_domain(raw: &str) -> Result<String, MessageKey> {
    let normalized = normalize_domain(raw);
    if normalized.is_empty() {
        return Err(MessageKey::new("api-tenant-domain-required"));
    }
    if normalized.len() > DOMAIN_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-tenant-domain-too-long",
            DOMAIN_MAX_LEN.to_string(),
        ));
    }
    // Single labels (`corp`) are allowed too. Dotless suffixes exist, like AD internal domains.
    let labels_are_valid = normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= LABEL_MAX_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !labels_are_valid {
        return Err(MessageKey::new("api-tenant-domain-invalid"));
    }
    Ok(normalized)
}

/// Splits login field input into "local part + normalized domain".
///
/// Only domain-qualified input (`alice@corp.example`) can be split; a bare user name gives `None`.
/// Input with multiple `@` also gives `None` — a tenant is never chosen by a value whose domain
/// part is ambiguous.
///
/// The check is the same "characters on both sides of `@`" as `accepts` of
/// [`crate::domain::login_identifier::LoginIdentifierType::Email`], with domain format validation
/// layered on. Input failing the format does not take the domain path and falls back to the old
/// resolution.
pub fn split_qualified_identifier(input: &str) -> Option<(&str, String)> {
    let trimmed = input.trim();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.contains('@') {
        return None;
    }
    let domain = validate_domain(domain).ok()?;
    Some((local, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_the_trailing_dot() {
        assert_eq!(normalize_domain("  Corp.Example.  "), "corp.example");
        assert_eq!(validate_domain("CORP.EXAMPLE").unwrap(), "corp.example");
    }

    /// Single labels are allowed; empty labels, leading/trailing hyphens, and non-ASCII are
    /// rejected.
    #[test]
    fn accepts_plausible_domains_and_rejects_malformed_ones() {
        for ok in ["corp", "corp.example", "a-b.c-d.example", "xn--wgv71a.jp"] {
            assert!(validate_domain(ok).is_ok(), "{ok} should be registrable");
        }
        for bad in [
            "",
            ".",
            "corp..example",
            "-corp.example",
            "corp-.example",
            "日本語.jp",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad} should be rejected");
        }
    }

    /// Length limits match the column (label 63, total 253).
    #[test]
    fn rejects_values_that_do_not_fit_the_column() {
        assert!(validate_domain(&"a".repeat(LABEL_MAX_LEN)).is_ok());
        assert!(validate_domain(&"a".repeat(LABEL_MAX_LEN + 1)).is_err());
        let long = std::iter::repeat_n("abcdefgh", 32)
            .collect::<Vec<_>>()
            .join(".");
        assert!(long.len() > DOMAIN_MAX_LEN);
        assert!(validate_domain(&long).is_err());
    }

    /// Only domain-qualified input can be split; the local part is kept as is (normalization is
    /// done by the type side).
    #[test]
    fn splits_only_domain_qualified_input() {
        assert_eq!(
            split_qualified_identifier(" Alice@Corp.Example "),
            Some(("Alice", "corp.example".to_string()))
        );
        assert_eq!(split_qualified_identifier("alice"), None);
        assert_eq!(split_qualified_identifier("@corp.example"), None);
        assert_eq!(split_qualified_identifier("alice@"), None);
        // Input with multiple `@` must not choose a tenant.
        assert_eq!(split_qualified_identifier("a@b@corp.example"), None);
        // Values unreadable as a domain do not take this path (they fall back to the old
        // resolution).
        assert_eq!(split_qualified_identifier("alice@-corp.example"), None);
    }
}
