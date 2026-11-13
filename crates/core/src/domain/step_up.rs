//! Step-up authentication (user authentication / auth policy spec §15; AP5).
//!
//! Being logged in and **having confirmed that this operation may be done now** are different
//! things. Sessions are valid for 8 hours by default, and an attacker holding a stolen session can
//! act as "logged in" the whole time. For operations that, if successful, **let someone take over
//! the account**, such as changing the password or MFA settings, the condition is "passed
//! re-verification just before", not having a session.
//!
//! Inputs are the authentication context recorded in the SSO session in AP4 (methods, strength, MFA
//! completion time) and the step-up time. Evaluation is a pure function ([`evaluate_step_up`])
//! independent of the DB and frameworks.

use crate::domain::sso_session::SsoSession;
use crate::domain::values::AuthenticationStrength;
use chrono::{DateTime, Duration, Utc};

/// Sensitive operations that require step-up (spec §15).
///
/// Targets operations where "success transfers control of the account". Viewing (session list,
/// linked apps list) is not included — seeing does not transfer control, and requiring
/// re-authentication for every operation makes users click through confirmations without reading
/// (weakening the actual protection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveOperation {
    /// Changing the password (presenting the current password is also required, but that alone
    /// cannot cross the second factor).
    ChangePassword,
    /// Adding / removing authenticators (TOTP, passkey). If an attacker adds their own
    /// authenticator, they can act as legitimate credentials from then on, so this needs the
    /// strongest protection.
    ManageAuthenticators,
    /// Linking / unlinking an external IdP (AP10). Linking creates a new login path.
    ManageExternalIdentities,
    /// Revoking signed-in sessions (locking out other devices).
    RevokeSession,
    /// Registering the current browser as "my device" (task #872). **Only passkeys pass**
    /// ([`Self::passkey_only`]). Someone who merely stole the password cannot register their own
    /// device.
    RegisterDevice,
    /// Registering / revoking SSH public keys (task #885). **Only passkeys pass**. Registered keys
    /// are automatically distributed to machines, so someone who merely stole the password cannot
    /// add their own key (nor remove one).
    ManageSshKeys,
}

impl SensitiveOperation {
    /// Stable string representation used in audit logs and API contracts.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChangePassword => "change_password",
            Self::ManageAuthenticators => "manage_authenticators",
            Self::ManageExternalIdentities => "manage_external_identities",
            Self::RevokeSession => "revoke_session",
            Self::RegisterDevice => "register_device",
            Self::ManageSshKeys => "manage_ssh_keys",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "change_password" => Some(Self::ChangePassword),
            "manage_authenticators" => Some(Self::ManageAuthenticators),
            "manage_external_identities" => Some(Self::ManageExternalIdentities),
            "revoke_session" => Some(Self::RevokeSession),
            "register_device" => Some(Self::RegisterDevice),
            "manage_ssh_keys" => Some(Self::ManageSshKeys),
            _ => None,
        }
    }

    /// Whether this operation "requires the second factor if the user has one".
    ///
    /// If authenticator management and external IdP linking could pass with a single factor, it
    /// would be a path where "an attacker who merely stole the password removes MFA (or adds their
    /// own authenticator) and takes over", so they always require the second factor. Password
    /// changes and session revocation suffice with the current password. Whether the operation
    /// accepts only passkey verification (password re-verification does not pass; task #872).
    ///
    /// The freshness criterion also differs: not the tenant's step-up interval but
    /// [`crate::domain::user_device::REGISTRATION_PASSKEY_MAX_AGE_SECS`] (5 minutes), measured not
    /// by `step_up_at` but by the passkey verification time
    /// ([`crate::domain::user_device::passkey_verified_recently`]).
    pub fn passkey_only(&self) -> bool {
        matches!(self, Self::RegisterDevice | Self::ManageSshKeys)
    }

    pub fn requires_second_factor(&self) -> bool {
        matches!(
            self,
            Self::ManageAuthenticators | Self::ManageExternalIdentities
        )
    }
}

/// Step-up requirements.
#[derive(Debug, Clone, Copy)]
pub struct StepUpRequirement {
    /// Re-verification is required if more than this many seconds passed since the last
    /// verification (same idea as spec §18.2, differing only in that the target is "right before
    /// this operation" rather than "the whole session").
    pub max_age_secs: u64,
    /// Required authentication strength. How to treat users without a second factor is decided by
    /// the Application layer (requiring multiple factors from someone who has none can never pass).
    pub required_strength: AuthenticationStrength,
}

impl StepUpRequirement {
    /// Decides the requirements from the operation and "whether the user has registered a second
    /// factor".
    ///
    /// Requiring multiple factors from a user without a second factor would just block the
    /// operation forever, so it falls back to single-factor re-verification (organizations wanting
    /// mandatory MFA close the entrance with auth policy `require_mfa`).
    pub fn for_operation(
        operation: SensitiveOperation,
        max_age_secs: u64,
        user_has_second_factor: bool,
    ) -> Self {
        let required_strength = if operation.requires_second_factor() && user_has_second_factor {
            AuthenticationStrength::MultiFactor
        } else {
            AuthenticationStrength::SingleFactor
        };
        Self {
            max_age_secs,
            required_strength,
        }
    }
}

/// Result of the step-up decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpDecision {
    /// The last verification satisfies the requirements. The operation may proceed.
    Satisfied,
    /// Verification is stale. Same strength is fine; verify once more.
    ReauthenticationRequired,
    /// Strength is insufficient (second factor not passed). Verify through the second factor.
    SecondFactorRequired,
}

/// Time of the last verification. Uses `step_up_at` if present, otherwise the login time
/// (`auth_time`).
///
/// Right after login it counts as stepped up (login itself is a verification, and asking the same
/// again right after would be a pointless repetition for the user).
fn last_verified_at(session: &SsoSession, step_up_at: Option<DateTime<Utc>>) -> DateTime<Utc> {
    match step_up_at {
        Some(at) if at > session.auth_time => at,
        _ => session.auth_time,
    }
}

/// Evaluates step-up (spec §15).
///
/// - If strength is insufficient, `SecondFactorRequired` (regardless of freshness; an old
///   single-factor verification is not let through "because it is fresh").
/// - If strength suffices but it is stale, `ReauthenticationRequired`.
/// - When multiple factors are required, "freshness" is measured by **the second factor's
///   completion time**. Re-entering only the password does not restore the second factor's
///   freshness.
pub fn evaluate_step_up(
    session: &SsoSession,
    step_up_at: Option<DateTime<Utc>>,
    requirement: StepUpRequirement,
    now: DateTime<Utc>,
) -> StepUpDecision {
    if !session
        .authentication_strength
        .satisfies(requirement.required_strength)
    {
        return StepUpDecision::SecondFactorRequired;
    }

    let max_age = Duration::seconds(requirement.max_age_secs as i64);
    let fresh = if requirement.required_strength == AuthenticationStrength::MultiFactor {
        // Measured by the second factor's freshness. Passing the second factor again in step-up
        // also updates `mfa_completed_at`, so this one value covers both "MFA at login" and "MFA at
        // step-up".
        session
            .mfa_completed_at
            .is_some_and(|at| now - at <= max_age)
    } else {
        now - last_verified_at(session, step_up_at) <= max_age
    };

    if fresh {
        StepUpDecision::Satisfied
    } else {
        StepUpDecision::ReauthenticationRequired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::AuthenticationMethod;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn session(methods: Vec<AuthenticationMethod>, auth_time: DateTime<Utc>) -> SsoSession {
        let mut s = SsoSession::establish(
            "hash".to_string(),
            Uuid::from_u128(1),
            auth_time,
            Duration::hours(1),
            Duration::hours(8),
            methods,
            None,
            None,
        );
        s.idle_expires_at = now() + Duration::hours(1);
        s.absolute_expires_at = now() + Duration::hours(8);
        s
    }

    fn single_factor(max_age_secs: u64) -> StepUpRequirement {
        StepUpRequirement {
            max_age_secs,
            required_strength: AuthenticationStrength::SingleFactor,
        }
    }

    fn multi_factor(max_age_secs: u64) -> StepUpRequirement {
        StepUpRequirement {
            max_age_secs,
            required_strength: AuthenticationStrength::MultiFactor,
        }
    }

    /// Right after login it counts as stepped up (the same is not asked again).
    #[test]
    fn a_fresh_login_satisfies_step_up() {
        let s = session(vec![AuthenticationMethod::Password], now());
        assert_eq!(
            evaluate_step_up(&s, None, single_factor(300), now()),
            StepUpDecision::Satisfied
        );
    }

    #[test]
    fn an_old_login_requires_reauthentication() {
        let s = session(
            vec![AuthenticationMethod::Password],
            now() - Duration::seconds(301),
        );
        assert_eq!(
            evaluate_step_up(&s, None, single_factor(300), now()),
            StepUpDecision::ReauthenticationRequired
        );
    }

    /// If the step-up time is fresh, it satisfies even when the login is old.
    #[test]
    fn a_recent_step_up_refreshes_an_old_login() {
        let s = session(
            vec![AuthenticationMethod::Password],
            now() - Duration::hours(4),
        );
        assert_eq!(
            evaluate_step_up(
                &s,
                Some(now() - Duration::seconds(60)),
                single_factor(300),
                now()
            ),
            StepUpDecision::Satisfied
        );
    }

    /// A single-factor session never satisfies a multi-factor requirement, however fresh.
    #[test]
    fn a_single_factor_session_never_satisfies_a_multi_factor_requirement() {
        let s = session(vec![AuthenticationMethod::Password], now());
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::SecondFactorRequired
        );
    }

    /// Under a multi-factor requirement, a password-only step-up does not restore freshness
    /// (because it is measured by `mfa_completed_at`).
    #[test]
    fn multi_factor_freshness_is_measured_from_the_second_factor() {
        let mut s = session(
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            now() - Duration::hours(4),
        );
        s.mfa_completed_at = Some(now() - Duration::hours(4));
        // Re-entered only the password (step_up_at is fresh), but the second factor is still from 4
        // hours ago.
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::ReauthenticationRequired
        );
        // Passing through the second factor again satisfies it.
        s.mfa_completed_at = Some(now() - Duration::seconds(10));
        assert_eq!(
            evaluate_step_up(&s, Some(now()), multi_factor(300), now()),
            StepUpDecision::Satisfied
        );
    }

    /// Users without a second factor are not asked for multiple factors (it could never pass).
    #[test]
    fn requirement_falls_back_to_single_factor_without_an_enrolled_authenticator() {
        let with =
            StepUpRequirement::for_operation(SensitiveOperation::ManageAuthenticators, 300, true);
        assert_eq!(with.required_strength, AuthenticationStrength::MultiFactor);
        let without =
            StepUpRequirement::for_operation(SensitiveOperation::ManageAuthenticators, 300, false);
        assert_eq!(
            without.required_strength,
            AuthenticationStrength::SingleFactor
        );
        // Operations not requiring a second factor are satisfied by a single factor even with an
        // authenticator.
        let password =
            StepUpRequirement::for_operation(SensitiveOperation::ChangePassword, 300, true);
        assert_eq!(
            password.required_strength,
            AuthenticationStrength::SingleFactor
        );
    }

    #[test]
    fn operation_round_trips_through_str() {
        for op in [
            SensitiveOperation::ChangePassword,
            SensitiveOperation::ManageAuthenticators,
            SensitiveOperation::ManageExternalIdentities,
            SensitiveOperation::RevokeSession,
            SensitiveOperation::RegisterDevice,
            SensitiveOperation::ManageSshKeys,
        ] {
            assert_eq!(SensitiveOperation::parse(op.as_str()), Some(op));
        }
        assert!(SensitiveOperation::RegisterDevice.passkey_only());
        assert!(SensitiveOperation::ManageSshKeys.passkey_only());
        assert!(!SensitiveOperation::RevokeSession.passkey_only());
        assert_eq!(SensitiveOperation::parse("delete_everything"), None);
    }
}
