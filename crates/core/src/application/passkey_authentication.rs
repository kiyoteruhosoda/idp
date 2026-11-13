//! **Login in the OIDC authorization flow** with a passkey (WebAuthn discoverable credentials) use case.
//!
//! Logs in with a passkey alone, without entering a password. Authentication flow:
//! 1. `begin()` — generates a discoverable challenge and returns the options JSON.
//! 2. `complete()` — verifies the credential from the browser, then issues the SSO session -> issues the code.
//!
//! The ceremony itself (issuing/consuming challenges, assertion verification, authenticator registry checks, tenant boundary)
//! is owned by [`crate::application::passkey_assertion`]. This module is the layer on top that adds **continuing the
//! `auth_session` and issuing the authorization code**. Direct logins outside the authorization flow
//! ([`crate::application::admin_login`], [`crate::application::portal_login`]) each put their own continuation on
//! the same ceremony.
//!
//! Rate limiting is per IP and consumes **the same bucket** as password login and the direct-login passkey path
//! (with a bucket per entry point, a party locked out of one could keep trying on the other).
//!
//! Authentication policy (user authentication & authentication policy spec §7–§9): `deny` policies refuse on this path
//! too (blocking only the password path could be bypassed). `require_mfa` is treated as satisfied because WebAuthn is
//! multi-factor (possession + biometric/knowledge via User Verification) and phishing-resistant.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::passkey_assertion::{
    PasskeyAssertionError, PasskeyAssertionService, PasskeyFlow,
};
use crate::application::sign_in_completion::{
    AuthorizationContinuation, Establishment, SignIn, SignInCompletion,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::AuthSessionRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
pub enum PasskeyAuthOutcome {
    /// Authenticated and consented. 302 to redirect_to with the code.
    Success {
        location: String,
        /// Hidden fields to POST for `form_post` (G12). `None` means `query`.
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Authenticated but consent is needed. Send to the consent screen.
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Challenge not found or expired.
    ChallengeNotFound,
    /// No AuthSession, or expired (redo the OIDC flow).
    SessionExpired,
    /// Invalid credential.
    InvalidCredential,
    /// Denied by the authentication policy (spec §7.4 `deny`).
    /// Authentication passed, but use of this application is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    /// The SSO session is issued (the user is signed in to assay), so other applications proceed as usual.
    ApplicationNotPermitted {
        /// Application name shown on screen. Without knowing which application refused them, the user
        /// cannot decide whom to ask next.
        application_name: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    PolicyDenied,
    /// Per-IP rate limit exceeded (same bucket as login and direct login).
    RateLimited,
    /// Internal error.
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916).
    /// No SSO session was created. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

pub struct PasskeyAuthenticationService {
    /// WebAuthn ceremony (challenge issuance, assertion verification). Shared by the three login paths.
    assertion: Arc<PasskeyAssertionService>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    /// Shared tail after authentication succeeds (establishing SSO, continuing the authorization flow).
    sign_in: Arc<SignInCompletion>,
    /// Per-IP rate limit. **Consumes the same bucket as login and the direct-login passkey path** ——
    /// with a bucket per entry point, a party locked out of one could keep trying on the other.
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PasskeyAuthenticationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assertion: Arc<PasskeyAssertionService>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        sign_in: Arc<SignInCompletion>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            assertion,
            auth_sessions,
            policy_gate,
            sign_in,
            rate_limiter,
            audit,
            clock,
        }
    }

    /// Starts authentication. `auth_session_id` is needed to continue the OIDC flow.
    ///
    /// Returns: `(challenge_id, options_json)`
    pub async fn begin(
        &self,
        auth_session_id: Option<&str>,
    ) -> Result<(Uuid, serde_json::Value), String> {
        self.assertion.begin(auth_session_id).await
    }

    /// Completes authentication.
    pub async fn complete(
        &self,
        tenant: TenantContext,
        challenge_id: Uuid,
        credential_value: serde_json::Value,
        ctx: &RequestContext,
    ) -> PasskeyAuthOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (same order and same bucket as the direct-login passkey path and the password path).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return PasskeyAuthOutcome::RateLimited;
            }
        }

        // 2. Verification of the WebAuthn ceremony (consuming the challenge, registry suspension check, signature counter update,
        //    tenant boundary) is owned by `PasskeyAssertionService`. Below is the OIDC-flow-specific continuation.
        let verified = match self
            .assertion
            .verify(
                tenant_id,
                challenge_id,
                credential_value,
                PasskeyFlow::Oidc,
                ctx,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return e.into(),
        };
        let user_id = verified.user_id;

        // 3. Fetch the AuthSession and continue the OIDC flow.
        let Some(auth_session_id_hash) = verified.auth_session_id_hash.as_deref() else {
            // Passed `PasskeyFlow::Oidc` verification = the binding always exists.
            return PasskeyAuthOutcome::Internal("no auth_session_id in challenge".to_string());
        };
        let mut session = match self
            .auth_sessions
            .find(
                tenant_id,
                &AuthSessionIdHash::from_stored(auth_session_id_hash.to_string()),
            )
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return PasskeyAuthOutcome::SessionExpired,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return PasskeyAuthOutcome::SessionExpired;
        }

        let client_id = session.client_id().to_string();

        // 4. Authentication policy evaluation (spec §9). `deny` refuses on the passkey path too.
        //    `require_mfa` passes because WebAuthn (possession factor + User Verification) satisfies it.
        let decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::OidcClient(&client_id),
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &session.request().requested_acr(),
                now,
            })
            .await
        {
            Ok(decision) => decision,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if let PolicyDecision::Deny { policy_code } = &decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code}")),
                    ctx,
                )
                .await;
            return PasskeyAuthOutcome::PolicyDenied;
        }
        // `require_specific_method` (AP3). Passkey authentication is WebAuthn with User Verification done
        // (it passed `webauthn-rs` verification), so it satisfies §12.2's "WebAuthn required" and "UV required".
        // It fails only when hitting a requirement for another method, like "must be TOTP".
        if let Some(unmet) =
            decision.unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
        {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&client_id),
                    Some(&format!(
                        "policy={} reason=method_required required={}",
                        unmet.policy_code,
                        unmet.requirement.describe()
                    )),
                    ctx,
                )
                .await;
            return PasskeyAuthOutcome::PolicyDenied;
        }

        // 5. Establish the SSO session and continue the authorization flow (consent check -> code issuance).
        let sso = match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id,
                    home_tenant_id: verified.home_tenant_id,
                    methods: vec![AuthenticationMethod::WebAuthn],
                    client_id: Some(&client_id),
                    success_event: AuditEventType::LoginSucceeded,
                    success_detail: None,
                },
                ctx,
                now,
            )
            .await
        {
            Ok(Establishment::Established(sso)) => sso,
            Ok(Establishment::DeviceEnrollmentRequired { ticket }) => {
                return PasskeyAuthOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        match self
            .sign_in
            .continue_authorization(tenant, &mut session, &sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                PasskeyAuthOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                PasskeyAuthOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => PasskeyAuthOutcome::Success {
                location: dispatch.location,
                form_post: dispatch.form_post,
                sso_session_id,
                sso_absolute_ttl_secs,
            },
            Err(e) => PasskeyAuthOutcome::Internal(e.to_string()),
        }
    }
}

impl From<PasskeyAssertionError> for PasskeyAuthOutcome {
    fn from(e: PasskeyAssertionError) -> Self {
        match e {
            // A challenge for another purpose (one for direct login completed in the authorization flow) means only
            // "please try again" to the user, so it is treated the same as expired.
            PasskeyAssertionError::ChallengeNotFound | PasskeyAssertionError::WrongFlow => {
                PasskeyAuthOutcome::ChallengeNotFound
            }
            PasskeyAssertionError::InvalidCredential => PasskeyAuthOutcome::InvalidCredential,
            PasskeyAssertionError::Internal(msg) => PasskeyAuthOutcome::Internal(msg),
        }
    }
}
