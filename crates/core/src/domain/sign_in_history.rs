//! The "sign-in history" the user sees (task #879; ADR-0073).
//!
//! Each sign-in attempt (success, failure, lockout, refused by policy) is kept as one row, and
//! successful sign-ins carry "which apps used it and how its refresh tokens were used".
//!
//! # Do not mix the two sources
//!
//! The source and browser of a sign-in row are **the signing-in user's browser**. The source and
//! self-identification of a refresh are **whoever sent the token**, which is the app's server if it
//! refreshes in the background. Putting them in the same column would misread "an outside server's
//! IP" as "signed in from outside the home", so they are held in separate types too
//! ([`SignInRecord`] and [`RefreshUsage`]).

use crate::domain::audit::{AuditEvent, AuditEventType};
use crate::domain::tenant::TenantId;
use crate::domain::user_device::CountryCode;
use crate::domain::values::{string_enum, AuthenticationMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Upper bound on items per page (the screen views this many at a time, newest first).
pub const SIGN_IN_HISTORY_PAGE_MAX: u32 = 50;

string_enum!(
    /// Outcome of a sign-in attempt (allowed values of `sign_in_history.outcome`).
    SignInOutcome {
        /// Signed in.
        Succeeded => "succeeded",
        /// Refused, e.g. credentials did not match.
        Failed => "failed",
        /// Refused due to repeated failures / during lockout.
        Locked => "locked",
        /// Refused by an authentication policy.
        Denied => "denied",
    }
);

string_enum!(
    /// Kind of refusal reason (a classification mapped to on-screen wording; a coarsened audit log
    /// `reason`).
    SignInFailureKind {
        WrongPassword => "wrong_password",
        WrongPasskey => "wrong_passkey",
        /// A verification code (TOTP, recovery code, email/SMS code) did not match.
        WrongCode => "wrong_code",
        /// Locked out after repeated failures.
        TooManyFailures => "too_many_failures",
        /// Arrived during lockout.
        AccountLocked => "account_locked",
        /// The user is suspended / the email is unverified.
        AccountNotActive => "account_not_active",
        /// Too many attempts from the same source.
        RateLimited => "rate_limited",
        /// Refused by policy, e.g. auth policy or lacking admin permission.
        PolicyDenied => "policy_denied",
        /// Sign-in at the external IdP did not go through.
        ExternalFailed => "external_failed",
        Other => "other",
    }
);

/// A refused sign-in attempt (copied where the audit log is written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInFailure {
    pub user_id: Uuid,
    pub tenant_id: Option<TenantId>,
    pub occurred_at: DateTime<Utc>,
    pub outcome: SignInOutcome,
    pub kind: SignInFailureKind,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Country (only values web decided to trust; task #895). Not in audit events, so the copying
    /// site adds it.
    pub country: Option<CountryCode>,
    pub client_id: Option<String>,
}

/// Country of the current request (a value web decided to trust and attached to the internal call;
/// task #895).
///
/// Read by the audit log writer
/// ([`crate::application::sign_in_history::SignInFailureRecordingSink`]) to add the country to
/// copies of refused sign-ins. `None` outside a request (patrols etc.) or for requests that hit api
/// directly from outside.
pub trait RequestCountry: Send + Sync {
    fn current(&self) -> Option<CountryCode>;
}

/// Holds no country (tests, outside a request).
pub struct NoRequestCountry;

impl RequestCountry for NoRequestCountry {
    fn current(&self) -> Option<CountryCode> {
        None
    }
}

/// Returns a copy if the audit event is "a refused sign-in that belongs in the user's history".
///
/// Failures with no determined user (unknown username) appear in no one's history.
pub fn sign_in_failure_from_audit(event: &AuditEvent) -> Option<SignInFailure> {
    let user_id = event.user_id?;
    let reason = event.reason.as_deref().unwrap_or("");
    let (outcome, kind) = match event.event_type {
        AuditEventType::LoginFailed => failure_kind(reason),
        AuditEventType::LoginLocked => (
            SignInOutcome::Locked,
            if reason == "too_many_failures" {
                SignInFailureKind::TooManyFailures
            } else {
                SignInFailureKind::AccountLocked
            },
        ),
        AuditEventType::LoginPolicyDenied => {
            (SignInOutcome::Denied, SignInFailureKind::PolicyDenied)
        }
        AuditEventType::ExternalLoginFailed => {
            (SignInOutcome::Failed, SignInFailureKind::ExternalFailed)
        }
        _ => return None,
    };
    Some(SignInFailure {
        user_id,
        tenant_id: event.tenant_id,
        occurred_at: event.occurred_at,
        outcome,
        kind,
        ip_address: event.ip_address.clone(),
        user_agent: event.user_agent.clone(),
        country: None,
        client_id: event.client_id.clone(),
    })
}

/// Maps the `reason` of `login.failed` to the classification.
fn failure_kind(reason: &str) -> (SignInOutcome, SignInFailureKind) {
    let kind = match reason {
        "invalid_password" | "invalid_current_password" => SignInFailureKind::WrongPassword,
        "invalid_passkey" => SignInFailureKind::WrongPasskey,
        "account_not_active" | "email_not_verified" => SignInFailureKind::AccountNotActive,
        "ip_rate_limited" => SignInFailureKind::RateLimited,
        "missing_admin_permission" => {
            return (SignInOutcome::Denied, SignInFailureKind::PolicyDenied)
        }
        r if r.starts_with("invalid_")
            && (r.contains("totp") || r.contains("code") || r.contains("otp")) =>
        {
            SignInFailureKind::WrongCode
        }
        _ => SignInFailureKind::Other,
    };
    (SignInOutcome::Failed, kind)
}

/// A successful sign-in (copied in the response where web set the sign-in cookie).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInSuccess {
    pub user_id: Uuid,
    pub tenant_id: TenantId,
    pub occurred_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<CountryCode>,
    pub methods: Vec<AuthenticationMethod>,
    /// `sid` of the SSO session (the same value refresh tokens hold).
    pub sid: String,
    /// Whether it was a registered device (`None` if the device mark did not arrive).
    pub device_registered: Option<bool>,
}

/// One row of history (read side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInRecord {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub outcome: SignInOutcome,
    pub failure_kind: Option<SignInFailureKind>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<CountryCode>,
    pub methods: Vec<AuthenticationMethod>,
    /// The app that started the refused sign-in (if known).
    pub client_id: Option<String>,
    pub app_name: Option<String>,
    pub sid: Option<String>,
    pub device_registered: Option<bool>,
}

/// How a successful sign-in was used by an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInAppUse {
    pub sid: String,
    pub client_id: String,
    pub app_name: Option<String>,
    pub first_issued_at: DateTime<Utc>,
    pub last_issued_at: DateTime<Utc>,
    /// `None` if no refresh token was issued.
    pub refresh: Option<RefreshUsage>,
}

/// How refresh tokens were used. Source and self-identification are those of **whoever sent the
/// refresh**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshUsage {
    pub use_count: u32,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip_address: Option<String>,
    pub last_user_agent: Option<String>,
    pub reuse_detected_at: Option<DateTime<Utc>>,
    pub state: RefreshState,
}

/// Current state of the refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// Still usable.
    Active,
    /// Revoked before expiry (logout, device revocation, reuse detection, etc.).
    Revoked { at: Option<DateTime<Utc>> },
    /// Expired (including ones whose rows were removed by cleanup).
    Expired,
}

/// Aggregation per (sid, client) of `refresh_tokens`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefreshTokenTally {
    /// Number of remaining rows (0 if removed by cleanup).
    pub rows: u32,
    /// Number of rows not revoked and unexpired.
    pub active: u32,
    /// Number of unexpired rows (including revoked).
    pub unexpired: u32,
    pub last_revoked_at: Option<DateTime<Utc>>,
}

impl RefreshTokenTally {
    /// Decides the current state from the aggregation.
    ///
    /// Each refresh (rotation) revokes the old row, so "some row is revoked" alone does not mean
    /// revoked. It counts as revoked only when no row is usable and unexpired rows remain.
    pub fn state(&self) -> RefreshState {
        if self.active > 0 {
            RefreshState::Active
        } else if self.unexpired > 0 {
            RefreshState::Revoked {
                at: self.last_revoked_at,
            }
        } else {
            RefreshState::Expired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditResult;

    fn event(event_type: AuditEventType, reason: &str, user: Option<Uuid>) -> AuditEvent {
        AuditEvent {
            event_type,
            occurred_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            tenant_id: None,
            user_id: user,
            client_id: Some("app".into()),
            ip_address: Some("203.0.113.5".into()),
            user_agent: Some("UA".into()),
            result: AuditResult::Failure,
            reason: Some(reason.into()),
            correlation_id: "c".into(),
        }
    }

    #[test]
    fn wrong_password_and_lockout_are_told_apart() {
        let u = Some(Uuid::nil());
        let f =
            sign_in_failure_from_audit(&event(AuditEventType::LoginFailed, "invalid_password", u))
                .unwrap();
        assert_eq!(
            (f.outcome, f.kind),
            (SignInOutcome::Failed, SignInFailureKind::WrongPassword)
        );
        let l =
            sign_in_failure_from_audit(&event(AuditEventType::LoginLocked, "too_many_failures", u))
                .unwrap();
        assert_eq!(
            (l.outcome, l.kind),
            (SignInOutcome::Locked, SignInFailureKind::TooManyFailures)
        );
        let a =
            sign_in_failure_from_audit(&event(AuditEventType::LoginLocked, "account_locked", u))
                .unwrap();
        assert_eq!(a.kind, SignInFailureKind::AccountLocked);
    }

    #[test]
    fn codes_passkeys_and_policies_are_classified() {
        let u = Some(Uuid::nil());
        let kind = |t, r| sign_in_failure_from_audit(&event(t, r, u)).unwrap().kind;
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_totp"),
            SignInFailureKind::WrongCode
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_recovery_code"),
            SignInFailureKind::WrongCode
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_passkey"),
            SignInFailureKind::WrongPasskey
        );
        assert_eq!(
            kind(AuditEventType::LoginPolicyDenied, "policy=x"),
            SignInFailureKind::PolicyDenied
        );
        assert_eq!(
            kind(AuditEventType::ExternalLoginFailed, "provider=g reason=x"),
            SignInFailureKind::ExternalFailed
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "something_new"),
            SignInFailureKind::Other
        );
    }

    #[test]
    fn failures_without_a_user_and_other_events_are_not_copied() {
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::LoginFailed,
            "unknown_user",
            None
        ))
        .is_none());
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::LoginSucceeded,
            "",
            Some(Uuid::nil())
        ))
        .is_none());
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::StepUpFailed,
            "",
            Some(Uuid::nil())
        ))
        .is_none());
    }

    #[test]
    fn rotation_alone_is_not_revocation() {
        let t = |rows, active, unexpired| RefreshTokenTally {
            rows,
            active,
            unexpired,
            last_revoked_at: None,
        };
        // Refreshed 3 times: the 3 old ones are revoked, the latest one is usable.
        assert_eq!(t(4, 1, 4).state(), RefreshState::Active);
        assert_eq!(
            t(4, 0, 4).state(),
            RefreshState::Revoked { at: None },
            "no usable row although some are unexpired = revoked"
        );
        assert_eq!(t(4, 0, 0).state(), RefreshState::Expired);
        assert_eq!(t(0, 0, 0).state(), RefreshState::Expired, "purged");
    }
}
