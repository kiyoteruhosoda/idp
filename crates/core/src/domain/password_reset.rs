//! One-time tokens for password reset / account setup (MT18, ADR-0062).
//!
//! The plaintext token reaches the user only via the link; only its SHA-256 hex (`token_hash`) is
//! stored. Setting `used_at` makes it single-use (the same one-time pattern as authorization
//! codes).

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Purpose of the link. **With the same single token, only what the link target allows changes**
/// (ADR-0062).
///
/// The DB uses `VARCHAR` + `CHECK` rather than a native ENUM, so this enum is the single source of
/// allowed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetPurpose {
    /// Password reset requested by the user (forgotten password; MT18).
    Reset,
    /// Account setup issued by an admin. Besides setting a password, it also allows **registering a
    /// passkey**.
    Setup,
}

impl ResetPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResetPurpose::Reset => "reset",
            ResetPurpose::Setup => "setup",
        }
    }

    /// Restores from the stored value. ⚠ **Unknown values are not coerced to `Reset`** — otherwise
    /// rows for purposes added later would be treated as "user's own reset", and operations allowed
    /// only for them would pass silently.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reset" => Some(ResetPurpose::Reset),
            "setup" => Some(ResetPurpose::Setup),
            _ => None,
        }
    }

    /// Whether a link with this purpose **may register a passkey**.
    ///
    /// Only `setup` allows it. `reset` is the "forgot password" path; allowing an authenticator
    /// there would give someone with temporary access to the mailbox a way to persist (a password
    /// is cut off by the next reset).
    pub fn allows_passkey_registration(&self) -> bool {
        matches!(self, ResetPurpose::Setup)
    }
}

#[derive(Debug, Clone)]
pub struct PasswordResetToken {
    /// SHA-256 hex of the token (the plaintext is not stored).
    pub token_hash: String,
    pub user_id: Uuid,
    pub purpose: ResetPurpose,
    pub expires_at: DateTime<Utc>,
    /// Consumption time. `None` = unused.
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_round_trips_through_its_stored_value() {
        for purpose in [ResetPurpose::Reset, ResetPurpose::Setup] {
            assert_eq!(ResetPurpose::parse(purpose.as_str()), Some(purpose));
        }
    }

    #[test]
    fn an_unknown_purpose_is_not_rounded_to_reset() {
        assert_eq!(ResetPurpose::parse("activation"), None);
        assert_eq!(ResetPurpose::parse(""), None);
    }

    /// Only admin-issued links can add a passkey.
    #[test]
    fn only_a_setup_link_may_register_a_passkey() {
        assert!(ResetPurpose::Setup.allows_passkey_registration());
        assert!(!ResetPurpose::Reset.allows_passkey_registration());
    }
}
