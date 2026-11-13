//! Registry of login identifiers (AP8; user authentication / auth policy spec §4).
//!
//! Widens the values that can be entered in the login field from the single
//! `users.preferred_username` to several. One row means "this user can also log in with this value
//! of this type".
//!
//! # Display value and normalized value
//!
//! Only [`UserLoginIdentifier::normalized_value`] is used for matching; what is shown on screen is
//! [`UserLoginIdentifier::display_value`], as the user registered it. The phone numbers
//! `090-1234-5678` and `+81 90 1234 5678` point to the same number, but the user recognizes the
//! former as what they registered. Using the normalized value for display would "list values the
//! user does not remember registering", and identity could not be confirmed.
//!
//! # Deactivation
//!
//! Rows with [`UserLoginIdentifier::is_active`] `false` do not match in the login field. Rows are
//! kept to distinguish "this value cannot be used" from "this value belongs to no one". Deleting
//! would let someone else register the same value, silently changing where a deactivated identifier
//! points.
//!
//! # Relation to `users.preferred_username` (expand phase)
//!
//! The primary login identifier remains `users.preferred_username` for now, and this registry holds
//! a copy of it as the `username` type (backfill in migration 0029). Resolution goes "active
//! registry row → otherwise `users.preferred_username`"
//! ([`crate::domain::repositories::UserRepository::find_by_login_identifier`]). The profile update
//! paths keep the copy in sync so it does not go stale (ADR-0025).
#![allow(dead_code)]

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::user::User;
use crate::domain::values::string_enum;
use chrono::{DateTime, Utc};
use uuid::Uuid;

string_enum!(
    /// Type of identifier (spec §4).
    ///
    /// The type exists to decide **how to normalize**. The same string ignores case as a username
    /// and ignores separators as a phone number; the type expresses that difference.
    LoginIdentifierType {
        /// Username. An identifier of the same nature as `users.preferred_username`.
        Username => "username",
        /// Email address. **Not registered by default** (migration 0029 does not import it).
        /// Whether to allow login by email is the tenant's decision; it takes effect only when an
        /// admin adds it explicitly.
        Email => "email",
        /// Phone number. Matched as a digit string with separators and spaces dropped, keeping only
        /// a leading `+`.
        PhoneNumber => "phone_number",
        /// Numbers issued by the organization, such as employee numbers. Matched ignoring case,
        /// with spaces dropped.
        EmployeeNumber => "employee_number",
    }
);

/// Upper bound of the normalized value (`VARCHAR(255)` of
/// `user_login_identifiers.normalized_value`).
pub const NORMALIZED_VALUE_MAX_LEN: usize = 255;
/// Upper bound of the display value (`VARCHAR(320)` of `user_login_identifiers.display_value`).
pub const DISPLAY_VALUE_MAX_LEN: usize = 320;

/// Range of digits accepted as a phone number (E.164's max of 15, with room for extensions etc.: up
/// to 20).
const PHONE_MIN_DIGITS: usize = 6;
const PHONE_MAX_DIGITS: usize = 20;

impl LoginIdentifierType {
    /// Normalizes an input value into a match key.
    ///
    /// Format validity is not checked ([`Self::normalize_checked`] does that). Login resolution
    /// builds "what the input would be as each type" for all types and looks them up, so this never
    /// fails.
    pub fn normalize(&self, raw: &str) -> String {
        let trimmed = raw.trim();
        match self {
            // Ignore case. The DB collation (`utf8mb4_unicode_ci`) is case-insensitive too, but
            // lowercase here as well for consistency between display and storage.
            Self::Username | Self::Email => trimmed.to_lowercase(),
            // Drop separators and spaces, keeping only a leading `+` (international prefix).
            Self::PhoneNumber => {
                let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
                if trimmed.starts_with('+') {
                    format!("+{digits}")
                } else {
                    digits
                }
            }
            // Ignore case and spaces (`A-1234` and `a 1234` are different, so symbols are not
            // dropped).
            Self::EmployeeNumber => trimmed
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_uppercase(),
        }
    }

    /// Whether the input **can be read as** this type (format check).
    ///
    /// The point is that registration validation ([`Self::normalize_checked`]) and login candidate
    /// generation ([`lookup_candidates`]) use **the same check**. If they diverge, you get either
    /// "values that can be registered but are not candidates at login" (= identifiers that never
    /// match) or "values that cannot be registered but become candidates" (= values that hit rows
    /// of another type).
    ///
    /// The latter is dangerous. For example, applying phone normalization to any input, the
    /// username `alice123456` stripped to digits `123456` could match **someone else's phone
    /// number**. Narrowing candidates by this check means input that does not look like a phone
    /// number is not looked up as one.
    pub fn accepts(&self, raw: &str) -> bool {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return false;
        }
        match self {
            // Username is the format-free catch-all.
            Self::Username => true,
            // Has characters on both sides of `@` (same criterion as `values::validate_email`).
            Self::Email => {
                let parts: Vec<&str> = trimmed.split('@').collect();
                parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
            }
            // Only digits and separators, with a digit count in range.
            Self::PhoneNumber => {
                let digits = trimmed.chars().filter(char::is_ascii_digit).count();
                trimmed
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'))
                    && (PHONE_MIN_DIGITS..=PHONE_MAX_DIGITS).contains(&digits)
            }
            // Contains no whitespace (since normalization drops whitespace, allowing it would make
            // the value "not findable in the way it was registered").
            Self::EmployeeNumber => !trimmed.chars().any(char::is_whitespace),
        }
    }

    /// Validates and then normalizes an input value (at registration).
    ///
    /// Errors are returned to users, so a **translation key** is returned, not text (translation is
    /// in the Presentation layer; MT19).
    pub fn normalize_checked(&self, raw: &str) -> Result<String, MessageKey> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(MessageKey::new("api-login-identifier-required"));
        }
        if trimmed.chars().count() > DISPLAY_VALUE_MAX_LEN {
            return Err(MessageKey::with_value(
                "api-login-identifier-too-long",
                DISPLAY_VALUE_MAX_LEN.to_string(),
            ));
        }
        if !self.accepts(trimmed) {
            return Err(MessageKey::new(match self {
                Self::Email => "api-email-invalid",
                Self::PhoneNumber => "api-login-identifier-phone-invalid",
                Self::EmployeeNumber => "api-login-identifier-employee-invalid",
                Self::Username => "api-login-identifier-required",
            }));
        }
        let normalized = self.normalize(trimmed);
        if normalized.is_empty() {
            return Err(MessageKey::new("api-login-identifier-required"));
        }
        if normalized.chars().count() > NORMALIZED_VALUE_MAX_LEN {
            return Err(MessageKey::with_value(
                "api-login-identifier-too-long",
                NORMALIZED_VALUE_MAX_LEN.to_string(),
            ));
        }
        Ok(normalized)
    }
}

/// Result of looking up a login identifier (MT25).
///
/// **Not an `Option<User>`.** "Matched no one" and "matched several so returns no one" are handled
/// differently by callers, yet folding both into `None` makes them indistinguishable. This actually
/// caused two bugs:
///
/// 1. Input ambiguous in the home tenant was treated like "not found" and fell through to guest
///    resolution ([`crate::application::login_user_resolution`]). The rule "do not let ambiguous
///    input through" was broken exactly where it was needed.
/// 2. The availability check at registration (the callers of [`Self::is_taken`]) saw ambiguous
///    values as "free". A third person could be added to a value already matching two, increasing
///    ambiguity.
///
/// Not carrying candidates (a list of user ids) when ambiguous is intentional. Carrying them would
/// let callers "take the first one", defeating the point of refusing.
//
// Only `Resolved` is large (one `User`), but it is not boxed. This value is built once per login
// and immediately destructured; boxing would add one allocation **for every successful login**
// (it is the same size as when it was `Option<User>`, which nobody had a problem with).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum LoginIdentifierMatch {
    /// Matched exactly one person.
    Resolved(User),
    /// Cannot return anyone. The reason is [`UnresolvedReason`].
    Unresolved(UnresolvedReason),
}

/// Why the user could not be determined from the identifier ([`LoginIdentifierMatch::Unresolved`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// Matched no identifier.
    NotFound,
    /// Matched several users. Uniqueness within a tenant is **type-independent** (one normalized
    /// value belongs to one person; migration 0041), so the same normalized value never matches two
    /// people. Two cases remain: one input spreading to several normalized values because
    /// normalization differs per type (`090-123-4567` is kept as is as a username, `0901234567` as
    /// a phone number), and guest resolution spanning home tenants and thus falling outside the
    /// uniqueness scope (MT25; the permanent fix is home realm discovery, recorded in
    /// `docs/Progress.md`).
    Ambiguous,
}

impl UnresolvedReason {
    /// Reason code recorded in the audit log (a language-independent fixed value). The response to
    /// users is a uniform credentials error, but operators need to distinguish "no such value" from
    /// "ambiguous value" — the latter is a state where the user cannot get in even with correct
    /// credentials and needs an admin fix.
    pub fn audit_code(self) -> &'static str {
        match self {
            Self::NotFound => "unknown_user",
            Self::Ambiguous => "ambiguous_identifier",
        }
    }
}

impl LoginIdentifierMatch {
    /// Matched no one.
    pub fn not_found() -> Self {
        Self::Unresolved(UnresolvedReason::NotFound)
    }

    /// Matched several people.
    pub fn ambiguous() -> Self {
        Self::Unresolved(UnresolvedReason::Ambiguous)
    }

    /// Whether the value **already belongs to someone** (availability check on registration /
    /// rename).
    ///
    /// **Ambiguous also counts as "in use".** Ambiguous means "already matches several", the
    /// opposite of free. Looking only at `Resolved` here would let a third person be added to an
    /// ambiguous value.
    pub fn is_taken(&self) -> bool {
        !matches!(self, Self::Unresolved(UnresolvedReason::NotFound))
    }

    /// The resolved user. Both ambiguous and absent give `None`.
    ///
    /// An accessor for callers that do not branch on the reason (tests, places that only need the
    /// result); **not used in login paths** — those must record an audit entry per reason.
    pub fn into_user(self) -> Option<User> {
        match self {
            Self::Resolved(user) => Some(user),
            Self::Unresolved(_) => None,
        }
    }
}

impl From<Option<User>> for LoginIdentifierMatch {
    fn from(found: Option<User>) -> Self {
        match found {
            Some(user) => Self::Resolved(user),
            None => Self::not_found(),
        }
    }
}

/// Expands login field input into candidate match keys per type.
///
/// The input itself does not state its type (users just type "my number"), so it builds **what it
/// would be when read as each type** and looks for matches. Since normalization differs per type,
/// "normalize once and look up" is not possible.
///
/// Candidates are built only for types that pass [`LoginIdentifierType::accepts`]. Using the same
/// check as registration validation makes both "a registrable value always becomes a candidate of
/// its type" and "readings that cannot be registered are not looked up" hold. Without the latter,
/// digits taken from a username could hit someone else's phone number (see the comment on
/// `accepts`).
///
/// Duplicates are dropped (`alice` may normalize the same as username and email, but there is no
/// point putting the same pair twice in `IN`).
pub fn lookup_candidates(input: &str) -> Vec<(LoginIdentifierType, String)> {
    use LoginIdentifierType::*;
    let mut out: Vec<(LoginIdentifierType, String)> = Vec::new();
    for kind in [Username, Email, PhoneNumber, EmployeeNumber] {
        if !kind.accepts(input) {
            continue;
        }
        let normalized = kind.normalize(input);
        if normalized.is_empty() || normalized.chars().count() > NORMALIZED_VALUE_MAX_LEN {
            continue;
        }
        if !out.iter().any(|(k, v)| *k == kind && *v == normalized) {
            out.push((kind, normalized));
        }
    }
    out
}

/// One row of the registry.
#[derive(Debug, Clone)]
pub struct UserLoginIdentifier {
    pub id: Uuid,
    /// Home tenant. Uniqueness is checked within the tenant (ADR-0009 §2).
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub identifier_type: LoginIdentifierType,
    /// The value as the user registered it (for display).
    pub display_value: String,
    /// Match key (with per-type normalization applied).
    pub normalized_value: String,
    /// If `false`, it does not match in the login field.
    pub is_active: bool,
    /// Whether it is the primary login identifier (AP15). At most one row per user (guaranteed by a
    /// DB UNIQUE).
    ///
    /// The primary identifier **cannot be changed or deleted per identifier** (change it via
    /// profile editing, stop it via account deactivation). It is handled differently from
    /// additional identifiers, so this column distinguishes it, not the type.
    pub is_primary: bool,
    /// Whether it is the primary email address row (ADR-0050). A copy of `users.email`; for the
    /// same reason as `is_primary` it cannot be changed or deleted per identifier.
    ///
    /// It is a separate column from `is_primary` because **the same row is never both** (only one
    /// row per normalized value can exist, so users whose username and email are the same value
    /// have no primary email row; decision 6).
    pub is_primary_email: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_per_type() {
        assert_eq!(
            LoginIdentifierType::Username.normalize("  Alice  "),
            "alice"
        );
        assert_eq!(
            LoginIdentifierType::Email.normalize("Alice@Example.COM"),
            "alice@example.com"
        );
        assert_eq!(
            LoginIdentifierType::PhoneNumber.normalize("090-1234-5678"),
            "09012345678"
        );
        assert_eq!(
            LoginIdentifierType::PhoneNumber.normalize("(090) 1234.5678"),
            "09012345678"
        );
        assert_eq!(
            LoginIdentifierType::EmployeeNumber.normalize(" a-1234 "),
            "A-1234"
        );
    }

    #[test]
    fn phone_normalization_keeps_international_prefix_distinct() {
        // Dropping the leading `+` would make domestic and international notation the same key. The
        // mapping between country codes and domestic prefixes (`+81 90…` = `090…`) differs per
        // country, and guessing here could hit someone else's number. To allow login with both,
        // register both as identifiers.
        assert_ne!(
            LoginIdentifierType::PhoneNumber.normalize("+819012345678"),
            LoginIdentifierType::PhoneNumber.normalize("09012345678")
        );
    }

    #[test]
    fn rejects_malformed_values() {
        assert!(LoginIdentifierType::Username
            .normalize_checked("   ")
            .is_err());
        assert!(LoginIdentifierType::Email
            .normalize_checked("not-an-email")
            .is_err());
        // Phone numbers with too few digits or mixed symbols cannot be registered.
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("12345")
            .is_err());
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("090-1234-abcd")
            .is_err());
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("090-1234-5678")
            .is_ok());
        // An employee number containing spaces would become a value "not findable in the way it was
        // registered" once normalization drops them.
        assert!(LoginIdentifierType::EmployeeNumber
            .normalize_checked("A 1234")
            .is_err());
        assert!(LoginIdentifierType::EmployeeNumber
            .normalize_checked("A-1234")
            .is_ok());
    }

    /// A registrable value must always be found as a candidate of its type.
    /// If this drifts, "identifiers that could be registered but cannot log in" appear.
    #[test]
    fn every_registrable_value_is_looked_up_under_its_own_type() {
        let cases = [
            (LoginIdentifierType::Username, "Alice"),
            (LoginIdentifierType::Email, "alice@example.com"),
            (LoginIdentifierType::PhoneNumber, "090-1234-5678"),
            (LoginIdentifierType::PhoneNumber, "+81 (90) 1234-5678"),
            (LoginIdentifierType::EmployeeNumber, "A-1234"),
        ];
        for (kind, raw) in cases {
            let normalized = kind.normalize_checked(raw).expect("registrable");
            assert!(
                lookup_candidates(raw).contains(&(kind, normalized.clone())),
                "{kind} / {raw} is not among the candidates"
            );
        }
    }

    /// Reverse direction: readings that **cannot be registered** as that type are not looked up.
    ///
    /// Without this, `123456` taken from the username `alice123456` would
    /// match someone else's phone number (which one `LIMIT 1` returns is undefined).
    #[test]
    fn does_not_look_up_types_the_input_could_not_be_registered_as() {
        let candidates = lookup_candidates("alice123456");
        assert!(!candidates
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::PhoneNumber));
        assert!(!candidates
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::Email));
        assert!(candidates.contains(&(LoginIdentifierType::Username, "alice123456".to_string())));

        // Input with whitespace is not looked up as an employee number (making `AB` from `a b`
        // could hit someone else).
        assert!(!lookup_candidates("a b")
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::EmployeeNumber));
    }

    #[test]
    fn lookup_candidates_are_empty_for_blank_input() {
        assert!(lookup_candidates("   ").is_empty());
        // Making `+`-only input a phone number candidate would create a key that could match
        // everyone's number.
        assert!(!lookup_candidates("+")
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::PhoneNumber));
    }
}
