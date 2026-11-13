//! Step-up authentication use case (AP5. User authentication & authentication policy spec §15).
//!
//! Right before sensitive operations (password change, adding/removing authenticators, linking external IdPs, revoking sessions),
//! decides "has it been confirmed that this operation may be done now", and if not, makes the user re-verify.
//!
//! The decision ([`crate::domain::step_up::evaluate_step_up`]) is a pure domain function; this service is
//! responsible for collecting and passing the SSO session and whether the user has authenticators, and for recording
//! to the SSO session when verification passes.
//!
//! # Two paths (password and passkey)
//!
//! On the **password path** the password is always verified (the starting point is "something only the user knows"). The second factor is
//! additionally verified only when the requirement is multi-factor. If it were built to let TOTP alone pass, skipping the password,
//! an attacker who picked up the device could pass the identity check.
//!
//! The **passkey path** ([`StepUpService::verify_with_passkey`]) satisfies possession and User
//! Verification in this one step, and is phishing resistant. It is the only method that meets the above requirement of
//! "picking up the device alone is not enough" without a knowledge factor, so it can stand in for the password
//! (extends the scope of the rule ADR-0020 §3 / ADR-0040 decision 2 already apply to sign-in).
//!
//! Without it, users who signed in with a passkey **could neither add another passkey nor remove a lost one
//! afterwards**: authenticator management is subject to step-up, and that step-up accepted
//! only passwords. ADR-0040 decision 3 says forced password changes are not checked on the passkey path,
//! and users who have never been aware of a password really exist.
//!
//! Password-specific gates (account lock `locked_until`) are not checked on the passkey path: they
//! counter password brute force and have no effect on brute-forcing signing keys (same rule as ADR-0040 decision 3).
//!
//! # Brute-force countermeasures
//!
//! Step-up is an entry point receiving credentials just like the sign-in screen, so it shares the same IP rate limiter as
//! sign-in (with a separate budget, an attacker locked out of sign-in could keep trying via step-up).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authenticator_management::has_usable_passkey;
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::passkey_assertion::{PasskeyAssertionError, PasskeyStepUpCeremony};
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::password::PasswordHasher;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    SsoSessionRepository, TotpSecretRepository, UserAuthenticatorRepository, UserRepository,
};
use crate::domain::step_up::{
    evaluate_step_up, SensitiveOperation, StepUpDecision, StepUpRequirement,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user_device::passkey_verified_recently;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use std::sync::Arc;

/// The decision of "may this operation be done now" (decides how the screen behaves next).
pub enum StepUpCheckOutcome {
    /// Requirements are met. The operation may continue.
    Satisfied,
    /// Identity must be re-verified. If `second_factor_required` is true, TOTP is required too.
    ChallengeRequired {
        second_factor_required: bool,
        /// Whether passkey verification may be offered (the user has a passkey **usable now**). Showing the button
        /// to users without one makes it fail after the browser dialog appears.
        passkey_available: bool,
        /// Whether the operation can only be verified with a passkey (the screen does not show a password field. task #872).
        passkey_only: bool,
    },
    /// The SSO session is missing or expired, or the user is disabled.
    SessionExpired,
    Internal(String),
}

pub struct StepUpVerifyCommand {
    /// Raw value of the SSO session Cookie.
    pub sso_session_id: String,
    /// The target sensitive operation (used for deciding requirements and for the audit).
    pub operation: SensitiveOperation,
    pub password: String,
    /// TOTP code (required only when the second factor is requested).
    pub totp_code: Option<String>,
}

/// Identity verification with a passkey (AP5). Unlike the password path, only one assertion is presented.
pub struct StepUpPasskeyVerifyCommand {
    /// Raw value of the SSO session Cookie. **Only a passkey of this session's own user passes.**
    pub sso_session_id: String,
    pub operation: SensitiveOperation,
    /// The challenge ID returned by `begin_passkey`.
    pub challenge_id: uuid::Uuid,
    /// The `PublicKeyCredential` (JSON) returned by the browser.
    pub credential: serde_json::Value,
}

pub enum StepUpVerifyOutcome {
    /// Verified. Recorded in the SSO session; the operation may continue.
    Ok,
    /// Password or TOTP mismatch (which one is wrong is not returned).
    InvalidCredentials,
    /// The second factor is needed but no code was presented. The screen shows the TOTP input field.
    SecondFactorRequired,
    /// Per-IP rate limit exceeded.
    RateLimited,
    SessionExpired,
    Internal(String),
}

pub struct StepUpService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// The WebAuthn ceremony. Shares the same implementation as the 3 sign-in paths (AP9 suspension checks, signature
    /// counter updates, and tenant boundaries do not drift per path. ADR-0040 decision 1).
    passkey_ceremony: Arc<dyn PasskeyStepUpCeremony>,
    /// Authenticator registry (AP9). Used to decide whether the passkey option may be shown.
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    /// Resolution of settings tenants can override (ADR-0058). Looked up on every reference.
    settings: Arc<dyn EffectiveTenantSettings>,
}

impl StepUpService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        passkey_ceremony: Arc<dyn PasskeyStepUpCeremony>,
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            totp_secrets,
            passkey_ceremony,
            authenticators,
            hasher,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            settings,
        }
    }

    /// Called right before a sensitive operation to decide whether step-up is needed.
    pub async fn check(
        &self,
        sso_session_id: &str,
        operation: SensitiveOperation,
    ) -> StepUpCheckOutcome {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return StepUpCheckOutcome::SessionExpired,
            Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
        };
        let home_tenant_id = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => u.tenant_id,
            Ok(_) => return StepUpCheckOutcome::SessionExpired,
            Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
        };
        // The re-verification interval is the value of the user's home tenant (same tenant as `verify`. ADR-0058).
        let max_age_secs = match self.settings.step_up_max_age_secs(home_tenant_id).await {
            Ok(secs) => secs,
            Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
        };

        // Operations allowed only via passkey (task #872) are decided only by the time verified with a passkey.
        if operation.passkey_only() {
            let verified_at = match self.sso_sessions.passkey_verified_at(&session_hash).await {
                Ok(at) => at,
                Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
            };
            if passkey_verified_recently(&session, verified_at, now) {
                return StepUpCheckOutcome::Satisfied;
            }
            let passkey_available =
                match has_usable_passkey(self.authenticators.as_ref(), session.user_id).await {
                    Ok(v) => v,
                    Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
                };
            return StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: true,
                passkey_available,
                passkey_only: true,
            };
        }

        let has_second_factor =
            match user_has_confirmed_totp(self.totp_secrets.as_ref(), session.user_id).await {
                Ok(v) => v,
                Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
            };
        let requirement =
            StepUpRequirement::for_operation(operation, max_age_secs, has_second_factor);

        let decision = evaluate_step_up(&session, session.step_up_at, requirement, now);
        // Look up the registry only once it is decided to show the screen. **The gate is passed on every sensitive operation**,
        // so looking it up every time even when satisfied would add unneeded queries for every operation.
        if matches!(decision, StepUpDecision::Satisfied) {
            return StepUpCheckOutcome::Satisfied;
        }
        let passkey_available =
            match has_usable_passkey(self.authenticators.as_ref(), session.user_id).await {
                Ok(v) => v,
                Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
            };

        match decision {
            StepUpDecision::Satisfied => StepUpCheckOutcome::Satisfied,
            StepUpDecision::ReauthenticationRequired => StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: requirement.required_strength
                    == AuthenticationStrength::MultiFactor,
                passkey_available,
                passkey_only: false,
            },
            StepUpDecision::SecondFactorRequired => StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: true,
                passkey_available,
                passkey_only: false,
            },
        }
    }

    /// Re-verifies identity, and if it passes, records it in the SSO session.
    pub async fn verify(
        &self,
        tenant: TenantContext,
        cmd: StepUpVerifyCommand,
        ctx: &RequestContext,
    ) -> StepUpVerifyOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (consumes the same budget as sign-in).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return StepUpVerifyOutcome::RateLimited;
            }
        }

        // Operations allowed only via passkey are not verified on the password path (task #872).
        if cmd.operation.passkey_only() {
            return StepUpVerifyOutcome::InvalidCredentials;
        }

        // 2. Resolve the user from the session.
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() && !u.is_locked_at(now) => u,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };

        // 3. Password verification (step-up always starts from this).
        let password_ok = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        if !password_ok {
            self.record_failure(tenant, cmd.operation, user.id, "invalid_password", ctx)
                .await;
            return StepUpVerifyOutcome::InvalidCredentials;
        }

        // 4. Verify the second factor too, depending on the requirement.
        let has_second_factor =
            match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                Ok(v) => v,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
        // The re-verification interval is the value of the user's home tenant (same tenant as `check`. ADR-0058).
        let max_age_secs = match self.settings.step_up_max_age_secs(user.tenant_id).await {
            Ok(secs) => secs,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        let requirement =
            StepUpRequirement::for_operation(cmd.operation, max_age_secs, has_second_factor);
        let mut methods = vec![AuthenticationMethod::Password];

        if requirement.required_strength == AuthenticationStrength::MultiFactor {
            let Some(code) = cmd.totp_code.as_deref().filter(|c| !c.is_empty()) else {
                return StepUpVerifyOutcome::SecondFactorRequired;
            };
            let record = match self.totp_secrets.find_by_user_id(user.id).await {
                Ok(Some(r)) if r.is_confirmed() => r,
                // Do not pass when the requirement is multi-factor but the authenticator has disappeared (deleted concurrently).
                Ok(_) => return StepUpVerifyOutcome::SecondFactorRequired,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            let secret = match crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key) {
                Ok(b) => b,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            let matched_step = match verify_totp_code(&secret, code) {
                Ok(v) => v,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            // Accept only if the step could be recorded (refuses reuse of the same or older code. Replay countermeasure).
            let accepted = match matched_step {
                Some(step) => match self
                    .totp_secrets
                    .record_totp_step_if_newer(user.id, step as i64, now)
                    .await
                {
                    Ok(recorded) => recorded,
                    Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
                },
                None => false,
            };
            if !accepted {
                self.record_failure(tenant, cmd.operation, user.id, "invalid_totp", ctx)
                    .await;
                return StepUpVerifyOutcome::InvalidCredentials;
            }
            methods.push(AuthenticationMethod::Totp);
        }

        // 5. Record. Single-factor re-verification does not change strength or MFA freshness (implemented on the repository side).
        if let Err(e) = self
            .sso_sessions
            .record_step_up(&session_hash, &methods, now)
            .await
        {
            return StepUpVerifyOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::StepUpSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(&format!("operation={}", cmd.operation.as_str())),
                ctx,
            )
            .await;
        StepUpVerifyOutcome::Ok
    }

    /// Starts identity verification with a passkey (issues one challenge).
    ///
    /// It is a different kind from sign-in challenges, so **a challenge issued here cannot be used to sign in**
    /// (and vice versa. Extends the idea of ADR-0040 decision 4 to identity verification).
    pub async fn begin_passkey(&self) -> Result<(uuid::Uuid, serde_json::Value), String> {
        self.passkey_ceremony.begin().await
    }

    /// Re-verifies identity with a passkey, and if it passes, records it in the SSO session.
    ///
    /// Three differences from the password path. **No knowledge factor is required** (a passkey satisfies possession + User Verification
    /// in one step), **the account lock is not checked** (it counters password brute force and has no effect on signing keys.
    /// ADR-0040 decision 3), and **there is no second-factor stage** (`[WebAuthn]` is recorded as multi-factor, so
    /// operations requiring multi-factor are also satisfied by this one step. ADR-0020 §3).
    pub async fn verify_with_passkey(
        &self,
        tenant: TenantContext,
        cmd: StepUpPasskeyVerifyCommand,
        ctx: &RequestContext,
    ) -> StepUpVerifyOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (consumes the same budget as the password path. If budgets differed per entry point,
        //    an attacker locked out of one could keep trying on the other).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return StepUpVerifyOutcome::RateLimited;
            }
        }

        // 2. Resolve the user from the session (the lock is not checked, since it has no effect as noted above).
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };

        // 3. The WebAuthn ceremony (challenge consumption, registry suspension check, signature counter update,
        //    tenant boundary) goes through the same one as the 3 sign-in paths.
        let verified = match self
            .passkey_ceremony
            .verify(tenant_id, cmd.challenge_id, cmd.credential, ctx)
            .await
        {
            Ok(v) => v,
            Err(PasskeyAssertionError::Internal(e)) => return StepUpVerifyOutcome::Internal(e),
            Err(_) => {
                self.record_failure(tenant, cmd.operation, user.id, "invalid_passkey", ctx)
                    .await;
                return StepUpVerifyOutcome::InvalidCredentials;
            }
        };

        // 4. **Is this the session's own user?** Passing verification only means "someone's passkey",
        //    and someone else's session must not be elevated with someone else's passkey.
        if verified.user_id != user.id {
            self.record_failure(tenant, cmd.operation, user.id, "other_user_passkey", ctx)
                .await;
            return StepUpVerifyOutcome::InvalidCredentials;
        }

        // 5. Record. `[WebAuthn]` includes a second factor, so it is recorded as multi-factor, and operations requiring
        //    multi-factor (authenticator management, linking external IdPs) are also satisfied by this one step.
        let methods = vec![AuthenticationMethod::WebAuthn];
        if let Err(e) = self
            .sso_sessions
            .record_step_up(&session_hash, &methods, now)
            .await
        {
            return StepUpVerifyOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::StepUpSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(&format!(
                    "operation={} method=webauthn",
                    cmd.operation.as_str()
                )),
                ctx,
            )
            .await;
        StepUpVerifyOutcome::Ok
    }

    async fn record_failure(
        &self,
        tenant: TenantContext,
        operation: SensitiveOperation,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::StepUpFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(&format!("operation={} reason={reason}", operation.as_str())),
                ctx,
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::passkey_assertion::VerifiedPasskeyUser;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::user::User;
    use crate::domain::user_authenticator::{
        AuthenticatorStatus, AuthenticatorType, UserAuthenticator,
    };
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const COOKIE: &str = "sso-cookie";
    /// The fake user (the one person `FakeUsers` returns; the session's owner).
    const USER: Uuid = Uuid::from_u128(1);
    const KEY: [u8; 32] = [3u8; 32];

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(9)))
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    struct AllowAll;
    impl LoginRateLimiter for AllowAll {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _e: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct FakeSessions {
        row: Mutex<SsoSession>,
        step_ups: Mutex<Vec<Vec<AuthenticationMethod>>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, hash: &str) -> DomainResult<Option<SsoSession>> {
            let row = self.row.lock().unwrap();
            Ok((row.session_hash == hash).then(|| row.clone()))
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn record_step_up(
            &self,
            _h: &str,
            methods: &[AuthenticationMethod],
            verified_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            // Performs the same update as the implementation (`SqlxSsoSessionRepository::record_step_up`). Multi-factor
            // step-up also rewrites method and strength: omitting this would run the tests in a state that does not exist
            // in reality, "passed the second factor but strength stays single", and the passkey path decision could not be tested.
            self.step_ups.lock().unwrap().push(methods.to_vec());
            let mut row = self.row.lock().unwrap();
            row.step_up_at = Some(verified_at);
            if AuthenticationStrength::from_methods(methods) == AuthenticationStrength::MultiFactor
            {
                row.authentication_methods = methods.to_vec();
                row.authentication_strength = AuthenticationStrength::MultiFactor;
                row.mfa_completed_at = Some(verified_at);
            }
            Ok(())
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeUsers;
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// This test does not go through the sign-in failure path (SEC13 verification is in login / mfa_login).
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(Some(User {
                id,
                tenant_id: TenantId::from(Uuid::from_u128(9)),
                sub: Uuid::from_u128(3),
                email: "u@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("u".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: "hash:correct".to_string(),
                must_change_password: false,
                password_changed_at: None,
                status: UserStatus::Active,
                pending_setup: false,
                failed_login_count: 0,
                locked_until: None,
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeTotp {
        confirmed: bool,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotp {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self.confirmed.then(|| TotpSecret {
                user_id,
                secret_encrypted: crypto::encrypt(b"12345678901234567890", &KEY).expect("encrypt"),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// A fake holding only the registry's passkey rows (other operations do not go through this path).
    #[derive(Default)]
    struct FakeAuthenticators {
        passkeys: Vec<UserAuthenticator>,
    }
    impl FakeAuthenticators {
        fn with_active_passkey() -> Self {
            Self {
                passkeys: vec![passkey_row(AuthenticatorStatus::Active)],
            }
        }
    }
    #[async_trait]
    impl UserAuthenticatorRepository for FakeAuthenticators {
        async fn create(&self, _a: &UserAuthenticator) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_user(&self, _user_id: Uuid) -> DomainResult<Vec<UserAuthenticator>> {
            Ok(self.passkeys.clone())
        }
    }

    fn passkey_row(status: AuthenticatorStatus) -> UserAuthenticator {
        UserAuthenticator {
            id: Uuid::from_u128(77),
            user_id: Uuid::from_u128(1),
            authenticator_type: AuthenticatorType::WebAuthn,
            status,
            label: "MacBook".to_string(),
            secret_encrypted: Some("key".to_string()),
            target: None,
            confirmed_at: Some(now()),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    /// Fake of the ceremony. Being able to swap only the returned owner ID is enough for the tests
    /// (verifying the assertion itself is the job of `passkey_assertion`).
    struct FakeCeremony(Result<Uuid, ()>);
    #[async_trait]
    impl PasskeyStepUpCeremony for FakeCeremony {
        async fn begin(&self) -> Result<(Uuid, serde_json::Value), String> {
            Ok((Uuid::from_u128(9), serde_json::json!({})))
        }
        async fn verify(
            &self,
            tenant_id: crate::domain::tenant::TenantId,
            _challenge_id: Uuid,
            _credential: serde_json::Value,
            _ctx: &RequestContext,
        ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError> {
            match self.0 {
                Ok(user_id) => Ok(VerifiedPasskeyUser {
                    user_id,
                    home_tenant_id: tenant_id,
                    auth_session_id_hash: None,
                }),
                Err(()) => Err(PasskeyAssertionError::InvalidCredential),
            }
        }
    }

    fn service(session: SsoSession, has_totp: bool) -> (StepUpService, Arc<FakeSessions>) {
        build_service(session, has_totp, FakeAuthenticators::default(), Ok(USER))
    }

    fn build_service(
        session: SsoSession,
        has_totp: bool,
        authenticators: FakeAuthenticators,
        ceremony_user: Result<Uuid, ()>,
    ) -> (StepUpService, Arc<FakeSessions>) {
        build_service_with(
            session,
            has_totp,
            authenticators,
            ceremony_user,
            crate::application::tenant_settings::testing::tenant_settings().service,
        )
    }

    fn build_service_with(
        session: SsoSession,
        has_totp: bool,
        authenticators: FakeAuthenticators,
        ceremony_user: Result<Uuid, ()>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> (StepUpService, Arc<FakeSessions>) {
        let sessions = Arc::new(FakeSessions {
            row: Mutex::new(session),
            step_ups: Mutex::new(Vec::new()),
        });
        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let service = StepUpService::new(
            sessions.clone(),
            Arc::new(FakeUsers),
            Arc::new(FakeTotp {
                confirmed: has_totp,
            }),
            Arc::new(FakeCeremony(ceremony_user)),
            Arc::new(authenticators),
            Arc::new(PlainHasher),
            Arc::new(AllowAll),
            Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone())),
            clock,
            KEY,
            settings,
        );
        (service, sessions)
    }

    fn session(methods: Vec<AuthenticationMethod>, age: Duration) -> SsoSession {
        let mut s = SsoSession::establish(
            crypto::sha256_hex(COOKIE),
            Uuid::from_u128(1),
            now() - age,
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

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "t".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// Right after sign-in, step-up is already satisfied. Do not ask for re-entry immediately.
    #[tokio::test]
    async fn a_fresh_session_satisfies_a_password_level_operation() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    /// "Authenticator management" for users with authenticators does not pass with a single-factor session.
    #[tokio::test]
    async fn managing_authenticators_needs_the_second_factor() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            true,
        );
        let StepUpCheckOutcome::ChallengeRequired {
            second_factor_required,
            ..
        } = svc
            .check(COOKIE, SensitiveOperation::ManageAuthenticators)
            .await
        else {
            panic!("expected a challenge");
        };
        assert!(second_factor_required);
    }

    /// Users without authenticators are not asked for a second factor (it could not be passed even if asked).
    #[tokio::test]
    async fn managing_authenticators_without_an_enrolled_one_stays_single_factor() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ManageAuthenticators)
                .await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    /// Old sessions are asked to re-verify. If the password passes, `step_up_at` advances and it is satisfied afterwards.
    #[tokio::test]
    async fn a_stale_session_is_refreshed_by_a_password_step_up() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: false,
                ..
            }
        ));

        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::Ok));
        assert_eq!(
            *sessions.step_ups.lock().unwrap(),
            vec![vec![AuthenticationMethod::Password]]
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    #[tokio::test]
    async fn a_wrong_password_does_not_refresh_the_session() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
        );
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "wrong".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::InvalidCredentials));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// A request omitting TOTP for an operation requiring the second factor does not pass even with the correct password.
    #[tokio::test]
    async fn a_multi_factor_operation_rejects_a_password_only_step_up() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            true,
        );
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ManageAuthenticators,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::SecondFactorRequired));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// If the session has expired, even the correct password does not pass.
    #[tokio::test]
    async fn an_expired_session_cannot_step_up() {
        let mut expired = session(vec![AuthenticationMethod::Password], Duration::hours(4));
        expired.idle_expires_at = now() - Duration::minutes(1);
        let (svc, _) = service(expired, false);
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::SessionExpired
        ));
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::SessionExpired));
    }

    // ── Identity verification with a passkey (T38. Extends the scope of ADR-0040 decision 2 to step-up) ──────

    /// A passkey is recorded as multi-factor in one step. **Without this, users who signed in with a passkey
    /// could never enter authenticator management (an operation requiring multi-factor).**
    #[tokio::test]
    async fn a_passkey_satisfies_a_step_up_that_demands_two_factors() {
        let (svc, sessions) = build_service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            true,
            FakeAuthenticators::with_active_passkey(),
            Ok(USER),
        );
        // With a password-only session, authenticator management requires up to the second factor.
        let StepUpCheckOutcome::ChallengeRequired {
            second_factor_required,
            passkey_available,
            ..
        } = svc
            .check(COOKIE, SensitiveOperation::ManageAuthenticators)
            .await
        else {
            panic!("expected a challenge");
        };
        assert!(second_factor_required);
        assert!(
            passkey_available,
            "show the passkey option when a usable passkey exists"
        );

        let outcome = svc
            .verify_with_passkey(tenant(), passkey_command(), &ctx())
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::Ok));

        // The recorded methods include a second factor, so operations requiring multi-factor pass as is.
        let recorded = sessions.step_ups.lock().unwrap().clone();
        assert_eq!(recorded, vec![vec![AuthenticationMethod::WebAuthn]]);
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ManageAuthenticators)
                .await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    /// Someone else's session must not be elevated with someone else's passkey (the ceremony only answers "whose passkey it is",
    /// so whether it is the user themselves is checked by this layer).
    #[tokio::test]
    async fn a_passkey_belonging_to_someone_else_does_not_verify_this_session() {
        let (svc, sessions) = build_service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
            FakeAuthenticators::with_active_passkey(),
            Ok(Uuid::from_u128(999)),
        );

        let outcome = svc
            .verify_with_passkey(tenant(), passkey_command(), &ctx())
            .await;

        assert!(matches!(outcome, StepUpVerifyOutcome::InvalidCredentials));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// An assertion that failed verification is not recorded.
    #[tokio::test]
    async fn a_rejected_assertion_does_not_record_a_step_up() {
        let (svc, sessions) = build_service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
            FakeAuthenticators::with_active_passkey(),
            Err(()),
        );

        let outcome = svc
            .verify_with_passkey(tenant(), passkey_command(), &ctx())
            .await;

        assert!(matches!(outcome, StepUpVerifyOutcome::InvalidCredentials));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// The passkey option is not shown to users who only have suspended passkeys (pressing it would not pass).
    #[tokio::test]
    async fn a_suspended_passkey_does_not_offer_the_passkey_route() {
        let (svc, _) = build_service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
            FakeAuthenticators {
                passkeys: vec![passkey_row(AuthenticatorStatus::Suspended)],
            },
            Ok(USER),
        );

        let StepUpCheckOutcome::ChallengeRequired {
            passkey_available, ..
        } = svc.check(COOKIE, SensitiveOperation::ChangePassword).await
        else {
            panic!("expected a challenge");
        };
        assert!(!passkey_available);
    }

    fn passkey_command() -> StepUpPasskeyVerifyCommand {
        StepUpPasskeyVerifyCommand {
            sso_session_id: COOKIE.to_string(),
            operation: SensitiveOperation::ManageAuthenticators,
            challenge_id: Uuid::from_u128(9),
            credential: serde_json::json!({}),
        }
    }

    /// The re-verification interval is measured by the user's **home** tenant value. A session verified 10 minutes ago
    /// satisfies it if the home tenant set 1 hour, and if there is no row, re-verification is required per the global value (5 minutes).
    /// ⚠ Another tenant's row has no effect (a single-tenant test would pass even if it read the global value).
    #[tokio::test]
    async fn the_step_up_window_is_the_home_tenant_value() {
        let home = TenantId::from(Uuid::from_u128(9));
        let other = TenantId::from(Uuid::from_u128(10));
        let aged = || session(vec![AuthenticationMethod::Password], Duration::minutes(10));

        let fixture = crate::application::tenant_settings::testing::tenant_settings();
        fixture.set_global("STEP_UP_MAX_AGE_SECS", "300");
        fixture.set_tenant(home, "STEP_UP_MAX_AGE_SECS", "3600");
        let (svc, _) = build_service_with(
            aged(),
            false,
            FakeAuthenticators::default(),
            Ok(USER),
            fixture.service,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::Satisfied
        ));

        let fixture = crate::application::tenant_settings::testing::tenant_settings();
        fixture.set_global("STEP_UP_MAX_AGE_SECS", "300");
        fixture.set_tenant(other, "STEP_UP_MAX_AGE_SECS", "3600");
        let (svc, _) = build_service_with(
            aged(),
            false,
            FakeAuthenticators::default(),
            Ok(USER),
            fixture.service,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::ChallengeRequired { .. }
        ));
    }
}
