//! Unified management of authenticators (AP9; user authentication / authentication policy spec §5).
//!
//! Represents one row of the **registry**, independent of type (TOTP, WebAuthn, recovery code, email OTP).
//! It exists so that "which authenticators can this user use now" is answered in one place;
//! type-specific secrets (TOTP secret, WebAuthn passkey) stay in the existing tables
//! (expand phase; no data move; see the comment in migration 0023 for why).
//!
//! State transitions (§5.3):
//!
//! ```text
//!   pending ──confirm──► active ──suspend──► suspended ──resume──► active
//!      │                   │                     │
//!      └──────revoke───────┴─────────revoke──────┴──────────────► revoked (terminal)
//! ```
//!
//! `suspended` exists to give an answer other than deletion to the real situation where **a device was
//! lost but may come back**. With only deletion, it would have to be re-registered when it turns up.
#![allow(dead_code)]

use crate::domain::values::{string_enum, AuthenticationMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

string_enum!(
    /// Authenticator type (spec §5.1).
    ///
    /// `SmsOtp` has **no issuance path** because assay has no means of sending (SMS gateway).
    /// The value exists so that adding a sending means later does not require changing the DB CHECK constraint
    /// and the Rust enum at the same time (keeps existing rows compatible).
    AuthenticatorType {
        Totp => "totp",
        WebAuthn => "webauthn",
        RecoveryCode => "recovery_code",
        EmailOtp => "email_otp",
        SmsOtp => "sms_otp",
    }
);

impl AuthenticatorType {
    /// Authentication method recorded when identity is verified with this authenticator (AP4).
    pub fn authentication_method(&self) -> AuthenticationMethod {
        match self {
            Self::Totp => AuthenticationMethod::Totp,
            Self::WebAuthn => AuthenticationMethod::WebAuthn,
            Self::RecoveryCode => AuthenticationMethod::RecoveryCode,
            Self::EmailOtp => AuthenticationMethod::EmailOtp,
            Self::SmsOtp => AuthenticationMethod::SmsOtp,
        }
    }

    /// Whether a user may register more than one of this type.
    ///
    /// TOTP is limited to one because the existing table uses `user_id` as primary key. WebAuthn is registered
    /// per device, so multiple. Recovery codes are one row per code, so multiple (issued as a batch).
    pub fn allows_multiple(&self) -> bool {
        !matches!(self, Self::Totp)
    }

    /// Whether it is single-use (expires after one use).
    pub fn is_single_use(&self) -> bool {
        matches!(self, Self::RecoveryCode | Self::EmailOtp | Self::SmsOtp)
    }
}

string_enum!(
    /// Authenticator state (spec §5.3).
    AuthenticatorStatus {
        /// Registration in progress (e.g. TOTP QR shown but confirmation code not entered). Not usable for authentication.
        Pending => "pending",
        /// Active. Usable for authentication.
        Active => "active",
        /// Suspended. The row is kept but not usable for authentication (interim measure for a lost device). Can return to `Active`.
        Suspended => "suspended",
        /// Revoked (terminal). Never returns to any other state.
        Revoked => "revoked",
    }
);

impl AuthenticatorStatus {
    /// Whether usable for authentication.
    pub fn is_usable(&self) -> bool {
        *self == Self::Active
    }

    /// Whether this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        *self == Self::Revoked
    }

    /// Whether the transition from `self` to `next` is allowed (spec §5.3).
    ///
    /// Revocation is terminal. Allowing a transition back from `Revoked` would create a path for "a revoked
    /// authenticator comes back" (neither an admin mistake nor an implementation bug could be prevented).
    pub fn can_transition_to(&self, next: Self) -> bool {
        use AuthenticatorStatus::*;
        match (self, next) {
            // Transitions to the same state are allowed as idempotent (double click, resend). Re-revoking an already
            // revoked one also passes here (putting `(Revoked, _) => false` first would reject the idempotent re-revoke).
            (a, b) if *a == b => true,
            (Revoked, _) => false,
            (_, Revoked) => true,
            (Pending, Active) => true,
            (Active, Suspended) => true,
            (Suspended, Active) => true,
            _ => false,
        }
    }
}

/// Window (seconds) for counting sent OTPs. Rows of issued codes are kept for this long even after expiry (task #749).
pub const OTP_SEND_WINDOW_SECS: i64 = 3_600;

/// One row of the authenticator registry.
#[derive(Debug, Clone)]
pub struct UserAuthenticator {
    pub id: Uuid,
    pub user_id: Uuid,
    pub authenticator_type: AuthenticatorType,
    pub status: AuthenticatorStatus,
    /// Display name set by the user (empty string if unset).
    pub label: String,
    /// Type-specific secret. TOTP: shared key (ciphertext); WebAuthn: `passkey_json`;
    /// recovery code / email OTP: SHA-256. Since AP11b the registry is the only place it is stored.
    pub secret_encrypted: Option<String>,
    /// Destination for email OTP.
    pub target: Option<String>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    /// Expiry of this authenticator (code). `None` if it never expires.
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserAuthenticator {
    /// Whether usable for authentication at the given time (state is `Active` and not expired).
    /// Whether it has been **blocked** by a user (or admin) action.
    ///
    /// `pending` means "not yet confirmed", not blocked. Only the two states suspended and revoked
    /// are grounds for closing existing authentication paths.
    pub fn is_blocked(&self) -> bool {
        matches!(
            self.status,
            AuthenticatorStatus::Suspended | AuthenticatorStatus::Revoked
        )
    }

    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.status.is_usable() && self.expires_at.is_none_or(|exp| exp > now)
    }

    /// Whether it counts as a second factor (same criterion as AP4's strength derivation).
    pub fn counts_as_second_factor(&self) -> bool {
        self.authenticator_type
            .authentication_method()
            .is_second_factor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn authenticator(
        authenticator_type: AuthenticatorType,
        status: AuthenticatorStatus,
        expires_at: Option<DateTime<Utc>>,
    ) -> UserAuthenticator {
        UserAuthenticator {
            id: Uuid::from_u128(1),
            user_id: Uuid::from_u128(2),
            authenticator_type,
            status,
            label: String::new(),
            secret_encrypted: None,
            target: None,
            confirmed_at: Some(now()),
            last_used_at: None,
            expires_at,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn only_active_and_unexpired_authenticators_are_usable() {
        use AuthenticatorStatus::*;
        assert!(authenticator(AuthenticatorType::Totp, Active, None).is_usable_at(now()));
        for status in [Pending, Suspended, Revoked] {
            assert!(
                !authenticator(AuthenticatorType::Totp, status, None).is_usable_at(now()),
                "{status} must not be usable"
            );
        }
        // An expired single-use code is unusable even when Active.
        assert!(!authenticator(
            AuthenticatorType::EmailOtp,
            Active,
            Some(now() - Duration::seconds(1))
        )
        .is_usable_at(now()));
        assert!(authenticator(
            AuthenticatorType::EmailOtp,
            Active,
            Some(now() + Duration::seconds(1))
        )
        .is_usable_at(now()));
    }

    /// Revocation is terminal. No transition back is allowed.
    #[test]
    fn revoked_is_terminal() {
        use AuthenticatorStatus::*;
        for next in [Pending, Active, Suspended] {
            assert!(!Revoked.can_transition_to(next), "revoked -> {next}");
        }
        // Idempotent revoke is allowed.
        assert!(Revoked.can_transition_to(Revoked));
    }

    #[test]
    fn suspension_is_reversible_but_pending_cannot_be_suspended() {
        use AuthenticatorStatus::*;
        assert!(Active.can_transition_to(Suspended));
        assert!(Suspended.can_transition_to(Active));
        // "Suspending" an unconfirmed authenticator is meaningless (it only creates two unusable states).
        assert!(!Pending.can_transition_to(Suspended));
        // Revocation is possible from any state.
        for from in [Pending, Active, Suspended] {
            assert!(from.can_transition_to(Revoked));
        }
    }

    #[test]
    fn types_map_to_the_authentication_method_recorded_on_the_session() {
        assert_eq!(
            AuthenticatorType::Totp.authentication_method(),
            AuthenticationMethod::Totp
        );
        assert_eq!(
            AuthenticatorType::RecoveryCode.authentication_method(),
            AuthenticationMethod::RecoveryCode
        );
        // All types count as a second factor (the only knowledge factor is the password).
        for t in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
            AuthenticatorType::SmsOtp,
        ] {
            assert!(t.authentication_method().is_second_factor(), "{t}");
        }
    }

    #[test]
    fn totp_is_the_only_single_registration_type() {
        assert!(!AuthenticatorType::Totp.allows_multiple());
        for t in [
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            assert!(t.allows_multiple(), "{t}");
        }
    }

    #[test]
    fn single_use_types_are_the_code_based_ones() {
        assert!(AuthenticatorType::RecoveryCode.is_single_use());
        assert!(AuthenticatorType::EmailOtp.is_single_use());
        assert!(!AuthenticatorType::Totp.is_single_use());
        assert!(!AuthenticatorType::WebAuthn.is_single_use());
    }
}
