//! Password policy (AP7; user authentication / auth policy spec §11.2).
//!
//! The old requirements were only minimum and maximum length, which look only at "the shape of the
//! input". This module adds three requirements that look at **the history of that password**.
//!
//! | Requirement | What it prevents | Inputs needed |
//! |---|---|---|
//! | Reject breached passwords | Stuffing attacks from published credential lists | External lookup service ([`BreachedPasswordChecker`]) |
//! | No reuse of past passwords | Changing back after a forced change | History of retired hashes |
//! | Expiry | Being used for years once set | Time it was set (`users.password_changed_at`) |
//!
//! The decisions themselves are here (Domain); fetching inputs (DB, external API) is done by
//! [`crate::application::password_policy::PasswordPolicyService`]. Only the length check completes
//! synchronously without inputs, so this module's [`PasswordPolicy::validate_length`] takes on
//! just that.
//!
//! # Why expiry is treated like "forced change"
//!
//! Expiry **does not refuse login**. Refusing would leave users unable to recover by themselves,
//! requiring an admin reissue (= password delivery via another route) every time. Instead it is
//! treated as the same "guide to the password change screen" state as `must_change_password`
//! ([`password_change_required`]). No flag is written to the DB because the expiry **changes
//! retroactively** when the setting changes, so storing the decision at write time would disagree
//! with the setting.

use crate::domain::error::Result;
use crate::domain::message::MessageKey;
use crate::domain::user::User;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

/// Default lookup target for breach checks (Have I Been Pwned range API). Implemented in
/// `infrastructure::breached_password`. The default is defined on the domain side because the
/// settings default table (`RUNTIME_SETTING_DEFINITIONS`) references it (so the settings list does
/// not depend on implementation details).
pub const DEFAULT_BREACH_API_BASE_URL: &str = "https://api.pwnedpasswords.com/range";

/// Minimum password length (default; overridden by the setting `PASSWORD_MIN_LENGTH`).
pub const MIN_PASSWORD_LEN: usize = 8;

/// Maximum password length. argon2 consumes CPU proportional to input length, so an upper bound
/// avoids computational DoS by extremely long input (generously allowing typical password manager
/// lengths).
pub const MAX_PASSWORD_LEN: usize = 256;

/// Why a new password was not accepted.
///
/// Not lumped into "weak" because the user's next action differs per reason (too short can be
/// lengthened, but breached / reused can only be fixed by **thinking of another value**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordRejection {
    /// Does not meet requirements on the input itself, such as length. User-facing text is returned
    /// via the bundled translation key.
    Strength(MessageKey),
    /// A known breached password ([`BreachedPasswordChecker`] reported a match).
    Breached,
    /// Reuse of the current or a past password.
    Reused,
}

impl PasswordRejection {
    /// Translation key returned to the user (the Presentation layer translates per
    /// `Accept-Language`).
    pub fn message_key(&self) -> MessageKey {
        match self {
            Self::Strength(key) => key.clone(),
            Self::Breached => MessageKey::new("api-password-breached"),
            Self::Reused => MessageKey::new("api-password-reused"),
        }
    }
}

impl std::fmt::Display for PasswordRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message_key())
    }
}

/// Password policy settings (a single value representation injected from `PASSWORD_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Minimum length (judged by byte length; see [`PasswordPolicy::validate_length`] below).
    pub min_length: usize,
    /// Maximum length.
    pub max_length: usize,
    /// Number of recent passwords whose reuse is forbidden (**including the current one**). `0`
    /// ignores history, `1` rejects the same value as the current one.
    pub history_count: u32,
    /// Password validity in days. `0` means no expiry.
    pub max_age_days: u32,
    /// Whether to reject breached passwords.
    pub reject_breached: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: MIN_PASSWORD_LEN,
            max_length: MAX_PASSWORD_LEN,
            history_count: 0,
            max_age_days: 0,
            reject_breached: false,
        }
    }
}

impl PasswordPolicy {
    /// Validates only the length (the only requirement that needs no inputs and completes
    /// synchronously).
    ///
    /// Length is judged in bytes. argon2's cost depends on byte length, so the upper bound stays
    /// meaningful even with multibyte characters.
    pub fn validate_length(&self, password: &str) -> std::result::Result<(), PasswordRejection> {
        if password.len() < self.min_length {
            return Err(PasswordRejection::Strength(MessageKey::with_value(
                "api-password-too-short",
                self.min_length.to_string(),
            )));
        }
        if password.len() > self.max_length {
            return Err(PasswordRejection::Strength(MessageKey::with_value(
                "api-password-too-long",
                self.max_length.to_string(),
            )));
        }
        Ok(())
    }

    /// Whether to check history (`history_count >= 1`).
    pub fn checks_history(&self) -> bool {
        self.history_count >= 1
    }

    /// Number of retired hashes read from the history table. The one current password is read from
    /// the user row, so the history side needs one fewer.
    pub fn retired_hashes_to_check(&self) -> u32 {
        self.history_count.saturating_sub(1)
    }

    /// How many retired hashes to keep per user (pruning limit).
    ///
    /// Matches the count used for decisions. Even to avoid running short right after loosening the
    /// policy, there is no reason to keep unused hashes (retention is kept to the purposeful
    /// minimum).
    pub fn retained_history_len(&self) -> u32 {
        self.retired_hashes_to_check()
    }

    /// Whether a password set at `changed_at` has expired as of `now`.
    pub fn is_expired(&self, changed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        if self.max_age_days == 0 {
            return false;
        }
        match Duration::try_days(i64::from(self.max_age_days)) {
            Some(max_age) => now >= changed_at + max_age,
            // Days beyond chrono's representable range = effectively no expiry.
            None => false,
        }
    }
}

/// Whether the user **should be required to change their password** (forced flag, or expiry).
///
/// Both the login path and the change path look at this one function. If only login looked at
/// expiry and the change path did not, users would end up "sent to the change screen but not
/// allowed to change".
pub fn password_change_required(user: &User, policy: &PasswordPolicy, now: DateTime<Utc>) -> bool {
    user.must_change_password || policy.is_expired(user.password_set_at(), now)
}

/// Port that decides whether a password is a known breached one (DIP boundary; implemented in the
/// infrastructure layer).
#[async_trait]
pub trait BreachedPasswordChecker: Send + Sync {
    /// `true` if it is a known breached password.
    ///
    /// **Returns `false` when it could not decide** (fail-open). If an external service outage made
    /// password changes and resets impossible, the opposite danger arises: credentials cannot be
    /// exchanged in the middle of a compromise. Unreachability is logged as a warning by the
    /// implementation.
    async fn is_breached(&self, password: &str) -> Result<bool>;
}

/// Implementation that skips breach checks (used when `PASSWORD_BREACH_CHECK_ENABLED=false` and in
/// tests without external communication).
pub struct NoBreachCheck;

#[async_trait]
impl BreachedPasswordChecker for NoBreachCheck {
    async fn is_breached(&self, _password: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::UserStatus;
    use uuid::Uuid;

    fn policy(history_count: u32, max_age_days: u32) -> PasswordPolicy {
        PasswordPolicy {
            history_count,
            max_age_days,
            ..PasswordPolicy::default()
        }
    }

    fn user(must_change: bool, password_changed_at: Option<DateTime<Utc>>) -> User {
        let now = Utc::now();
        User {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7().into(),
            sub: Uuid::now_v7(),
            email: "u@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "hash".to_string(),
            must_change_password: must_change,
            password_changed_at,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now - Duration::try_days(400).unwrap(),
            updated_at: now,
        }
    }

    #[test]
    fn rejects_short_password_and_accepts_long_enough() {
        let p = PasswordPolicy::default();
        assert!(p.validate_length("short").is_err());
        assert!(p.validate_length("longenough").is_ok());
    }

    #[test]
    fn accepts_boundary_lengths_and_rejects_overlong() {
        let p = PasswordPolicy::default();
        assert!(p.validate_length(&"a".repeat(p.min_length)).is_ok());
        assert!(p.validate_length(&"a".repeat(p.max_length)).is_ok());
        assert!(p.validate_length(&"a".repeat(p.max_length + 1)).is_err());
    }

    #[test]
    fn min_length_follows_the_configured_value() {
        let p = PasswordPolicy {
            min_length: 12,
            ..PasswordPolicy::default()
        };
        assert!(p.validate_length("elevenchars").is_err());
        assert!(p.validate_length("twelvechars!").is_ok());
    }

    #[test]
    fn history_count_maps_to_current_password_plus_retired_hashes() {
        assert!(!policy(0, 0).checks_history());
        assert_eq!(policy(0, 0).retired_hashes_to_check(), 0);
        // 1 = current password only (the history table is not read).
        assert!(policy(1, 0).checks_history());
        assert_eq!(policy(1, 0).retired_hashes_to_check(), 0);
        // 5 = current + 4 retired.
        assert_eq!(policy(5, 0).retired_hashes_to_check(), 4);
    }

    #[test]
    fn zero_max_age_never_expires() {
        let now = Utc::now();
        let ancient = now - Duration::try_days(10_000).unwrap();
        assert!(!policy(0, 0).is_expired(ancient, now));
    }

    #[test]
    fn expires_exactly_at_the_configured_age() {
        let now = Utc::now();
        let p = policy(0, 90);
        assert!(!p.is_expired(now - Duration::try_days(89).unwrap(), now));
        assert!(p.is_expired(now - Duration::try_days(90).unwrap(), now));
        assert!(p.is_expired(now - Duration::try_days(91).unwrap(), now));
    }

    #[test]
    fn change_required_when_flagged_or_expired() {
        let now = Utc::now();
        let recent = Some(now - Duration::try_days(1).unwrap());

        // Without an expiry set, an old creation time alone does not require a change.
        assert!(!password_change_required(
            &user(false, recent),
            &policy(0, 0),
            now
        ));
        // The forced flag applies regardless of the expiry setting.
        assert!(password_change_required(
            &user(true, recent),
            &policy(0, 0),
            now
        ));
        // Expiry requires a change even without the forced flag.
        assert!(password_change_required(
            &user(false, Some(now - Duration::try_days(100).unwrap())),
            &policy(0, 90),
            now
        ));
    }

    #[test]
    fn unrecorded_change_time_falls_back_to_account_creation() {
        // Users created before the migration who have not changed their password since (the column
        // is NULL). The creation time (400 days ago) is taken as the set time, so a 90-day expiry
        // judges it expired.
        let now = Utc::now();
        assert!(password_change_required(
            &user(false, None),
            &policy(0, 90),
            now
        ));
    }
}
