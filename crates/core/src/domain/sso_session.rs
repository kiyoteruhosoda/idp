//! SsoSessions entity (design spec §3.4).
//! The cookie holds `session_id`; the DB stores only `session_hash = SHA-256(session_id)`.
//!
//! A session also records "when, by which methods, and at what strength the user was verified"
//! (user authentication / auth policy spec §14.3, §18.1). This record is the sole input for
//! re-authentication by elapsed time since MFA (§18.2 `max_authentication_age`) and step-up
//! authentication (§15).
#![allow(dead_code)]

use crate::domain::crypto;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SsoSession {
    pub session_hash: String,
    pub user_id: Uuid,
    /// Initial login time. Also copied into the ID Token's `auth_time` on SSO restore (design spec
    /// §5.1).
    pub auth_time: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    /// Authentication methods actually verified to establish this session (spec §14.3). Ordered as
    /// verified.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// Authentication strength (derived from `authentication_methods`; also stored so checks take
    /// one round trip).
    pub authentication_strength: AuthenticationStrength,
    /// Time the second factor was verified (`None` if not done). Re-authentication by elapsed time
    /// since MFA (§18.2) and step-up (§15) are based on this time (not `auth_time`; re-entering
    /// only the password does not restore MFA freshness).
    pub mfa_completed_at: Option<DateTime<Utc>>,
    /// Time the user passed re-verification (step-up) right before a sensitive operation (AP5; spec
    /// §15). `auth_time` is the SSO origin and does not move on restore, so the freshness of "may
    /// this operation be done now" is measured separately.
    pub step_up_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SsoSession {
    /// Builds a new SSO session on successful login.
    ///
    /// Strength and `mfa_completed_at` are derived from `methods` (callers do not pass them). There
    /// are five login paths (OIDC, MFA, passkey, portal, admin console); if any of them computed
    /// strength wrongly, step-up and re-authentication decisions would all go wrong, so the
    /// derivation is confined to this one place.
    #[allow(clippy::too_many_arguments)]
    pub fn establish(
        session_hash: String,
        user_id: Uuid,
        now: DateTime<Utc>,
        idle_ttl: Duration,
        absolute_ttl: Duration,
        methods: Vec<AuthenticationMethod>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Self {
        let strength = AuthenticationStrength::from_methods(&methods);
        Self {
            session_hash,
            user_id,
            auth_time: now,
            idle_expires_at: now + idle_ttl,
            absolute_expires_at: now + absolute_ttl,
            authentication_methods: methods,
            authentication_strength: strength,
            // The second factor has been verified "just now" (establish is not called outside login
            // paths).
            mfa_completed_at: (strength == AuthenticationStrength::MultiFactor).then_some(now),
            // Login itself is a re-verification, so right after establishment it counts as stepped
            // up.
            step_up_at: Some(now),
            user_agent,
            ip_address,
            created_at: now,
            updated_at: now,
        }
    }

    /// Length (seconds) until the absolute expiry decided at establishment. web uses it for the SSO
    /// cookie's `Max-Age`.
    ///
    /// Lifetime settings differ per tenant (ADR-0058), so the cookie side does not re-read settings
    /// but takes it from **the established session itself** (re-reading would make cookie and
    /// session diverge the moment the value changes).
    pub fn absolute_ttl_secs(&self) -> u64 {
        u64::try_from((self.absolute_expires_at - self.created_at).num_seconds()).unwrap_or(0)
    }

    /// Whether valid at the given time (neither idle nor absolute exceeded).
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.idle_expires_at > now && self.absolute_expires_at > now
    }

    /// Whether the second factor is complete (spec §14.3).
    pub fn is_multi_factor(&self) -> bool {
        self.authentication_strength == AuthenticationStrength::MultiFactor
    }

    /// Whether the user was verified with the given method.
    pub fn used_method(&self, method: AuthenticationMethod) -> bool {
        self.authentication_methods.contains(&method)
    }

    /// Whether `max_age` (seconds) is satisfied (OIDC Core §3.1.2.1 `max_age` / spec §18.2).
    /// If not, re-authentication (equivalent to `prompt=login`) is required.
    pub fn satisfies_max_age(&self, max_age_secs: u64, now: DateTime<Utc>) -> bool {
        now - self.auth_time <= Duration::seconds(max_age_secs as i64)
    }

    /// Whether the elapsed time since MFA completion is within `max_age_secs` (spec §18.2).
    /// Sessions without completed MFA never satisfy it (`false`).
    pub fn satisfies_mfa_age(&self, max_age_secs: u64, now: DateTime<Utc>) -> bool {
        self.mfa_completed_at
            .is_some_and(|at| now - at <= Duration::seconds(max_age_secs as i64))
    }

    /// Session identifier that can be shown on screen (self-service session list / revocation;
    /// G10).
    ///
    /// `session_hash` is not the raw cookie value, so showing it would not allow authentication,
    /// but there is no need to put the DB primary key on screen either. A domain-separated
    /// irreversible derivation is returned, and matching is done by scanning the user's own
    /// sessions (no path restores `session_hash` from the value).
    pub fn display_id(&self) -> String {
        display_id_of(&self.session_hash)
    }

    /// Session identifier `sid` shared by back-channel / front-channel logout and the ID Token
    /// (OpenID Connect Back-Channel Logout 1.0 §2.1; G5).
    ///
    /// RPs perform per-session logout with this value. It is derived irreversibly from
    /// `session_hash`, so no extra column is needed, and even if it reaches an RP it cannot be used
    /// to hijack the SSO session.
    pub fn sid(&self) -> String {
        sid_of(&self.session_hash)
    }
}

/// Derives the display ID from `session_hash` (the body of [`SsoSession::display_id`]).
pub fn display_id_of(session_hash: &str) -> String {
    crypto::sha256_hex(&format!("sso-session-display:{session_hash}"))[..32].to_string()
}

/// Derives `sid` from `session_hash` (the body of [`SsoSession::sid`]).
///
/// On logout the SSO session row is deleted before the logout_token is built, so the same `sid`
/// must be reproducible from `session_hash` alone after the row is gone. That is why the derivation
/// is a public function.
pub fn sid_of(session_hash: &str) -> String {
    crypto::sha256_hex(&format!("sso-session-sid:{session_hash}"))[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn session(
        methods: Vec<AuthenticationMethod>,
        mfa_completed_at: Option<DateTime<Utc>>,
    ) -> SsoSession {
        SsoSession {
            session_hash: "a".repeat(64),
            user_id: Uuid::from_u128(1),
            auth_time: now(),
            idle_expires_at: now() + Duration::hours(1),
            absolute_expires_at: now() + Duration::hours(8),
            authentication_strength: AuthenticationStrength::from_methods(&methods),
            authentication_methods: methods,
            mfa_completed_at,
            step_up_at: Some(now()),
            user_agent: None,
            ip_address: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn strength_follows_the_recorded_methods() {
        assert!(!session(vec![AuthenticationMethod::Password], None).is_multi_factor());
        assert!(session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            Some(now())
        )
        .is_multi_factor());
    }

    #[test]
    fn max_age_is_measured_from_auth_time() {
        let s = session(vec![AuthenticationMethod::Password], None);
        assert!(s.satisfies_max_age(300, now() + Duration::seconds(300)));
        assert!(!s.satisfies_max_age(300, now() + Duration::seconds(301)));
    }

    /// Sessions without completed MFA do not satisfy the MFA elapsed-time requirement (a password
    /// alone does not restore it).
    #[test]
    fn mfa_age_requires_a_completed_second_factor() {
        let password_only = session(vec![AuthenticationMethod::Password], None);
        assert!(!password_only.satisfies_mfa_age(300, now()));

        let mfa = session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            Some(now()),
        );
        assert!(mfa.satisfies_mfa_age(300, now() + Duration::seconds(300)));
        assert!(!mfa.satisfies_mfa_age(300, now() + Duration::seconds(301)));
    }

    /// Display ID and `sid` differ per session and do not leak `session_hash` as is.
    #[test]
    fn derived_identifiers_are_stable_and_do_not_leak_the_hash() {
        let s = session(vec![AuthenticationMethod::Password], None);
        assert_eq!(s.display_id(), s.display_id());
        assert_eq!(s.sid(), sid_of(&s.session_hash));
        assert_ne!(s.display_id(), s.sid());
        assert!(!s.session_hash.contains(&s.display_id()));
        assert!(!s.session_hash.contains(&s.sid()));

        let mut other = s.clone();
        other.session_hash = "b".repeat(64);
        assert_ne!(s.display_id(), other.display_id());
        assert_ne!(s.sid(), other.sid());
    }
}
