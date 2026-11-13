//! Logins approved with the authenticator app ("continue with the app") and registering the authenticator app's key (task #892, ADR-0077).
//!
//! There are three kinds of routes:
//!
//! | Caller | What | Verified by |
//! |---|---|---|
//! | Authenticator app (public routes) | registration intake, key attestation, activation, request content, approve, deny, revoke | key signature ([`signed_message`]) |
//! | web (login screen) | start a request, complete with a code | mark of the browser that started the request (cookie) |
//! | web (account screen) | confirm registration, list keys, revoke | SSO session + passkey (within 5 minutes) |
//!
//! ⚠ No route is made where the browser that started the request waits for "was it approved" and completes (`domain::app_approver`).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::sign_in_completion::{
    AuthorizationContinuation, EstablishedSso, SignIn, SignInCompletion,
};
use crate::domain::app_approver::{
    self, signed_at_is_fresh, signed_message, ApprovalRequest, ApprovalState, ApproverEnrollment,
    ApproverKey, EnrollmentStage, SignedAction, APPROVAL_CODE_TTL_SECS, ENROLLMENT_CODE_TTL_SECS,
    REQUEST_TTL_SECS,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::key_attestation::{
    verify_attestation, verify_p256_signature, AttestationPolicy, AttestationRejection,
    KeySecurityLevel,
};
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    ApprovalRequestRepository, ApproverEnrollmentRepository, ApproverKeyRepository,
    AuthSessionRepository, ClientRepository, RefreshTokenRepository, SsoSessionRepository,
    TenantMembershipRepository, UserRepository,
};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::sso_session::{self, SsoSession};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_device::{passkey_verified_recently, CountryCode};
use crate::domain::values::AuthenticationMethod;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Upper limit for one certificate in the chain (DER byte count before receiving as base64).
const MAX_CERT_BYTES: usize = 8 * 1024;

// ⚠ Codes and marks are compared after SHA-256 (only SHA-256 is stored in the DB). The compared values are not the
//   secrets themselves, so constant-time comparison is not needed.

// ─── Results ─────────────────────────────────────────────────────────────

/// Failure on a public route (code returned to the app; carries no secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppApproverError {
    /// The authenticator app routes are closed (no package name configured).
    Disabled,
    NotFound,
    Expired,
    /// Stage or state does not match (double submission, wrong order).
    Conflict,
    AttestationRejected(AttestationRejection),
    /// The same key is already registered.
    AlreadyRegistered,
    /// Signature does not match, or the code is wrong.
    SignatureInvalid,
    /// No key (revoked).
    KeyRevoked,
    /// The key's owner cannot use this organization (stopped, or left the organization).
    NotAMember,
    BadRequest,
    RateLimited,
    Internal(String),
}

impl From<DomainError> for AppApproverError {
    fn from(e: DomainError) -> Self {
        Self::Internal(e.to_string())
    }
}

/// Result of starting the intake.
pub struct EnrollmentStarted {
    pub enrollment_id: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

/// An activated key.
pub struct ActivatedKey {
    pub key_id: String,
    pub username: String,
    pub display_name: Option<String>,
}

/// Request content shown to the app.
pub struct ApprovalRequestView {
    pub request_id: String,
    pub challenge: String,
    pub state: ApprovalState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    /// If it came mid-authorization, that RP's name (client_id if none).
    pub client_name: Option<String>,
}

/// Approval result (a code the app opens in the browser on the same phone).
pub struct Approved {
    pub code: String,
}

/// Result of web starting a request.
pub enum StartApprovalOutcome {
    Started {
        request_id: String,
        /// Mark handed only to the browser that started it (web puts it in a cookie).
        browser_binding: String,
    },
    Disabled,
    RateLimited,
    Internal(String),
}

/// Completion result (web receives it in the same shape as an external IdP login).
pub enum CompleteApprovalOutcome {
    /// Logged in. If `location` is `None`, go to assay's account screen.
    Success {
        location: Option<String>,
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ApplicationNotPermitted {
        application_name: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// The code is wrong, expired or used, or there is no request.
    Invalid,
    /// A browser other than the one that started the request (mark missing or different). No login is allowed.
    AnotherBrowser,
    PolicyDenied,
    UserUnavailable,
    Internal(String),
}

/// Content shown on the account screen's registration confirmation.
pub struct EnrollmentView {
    pub device_name: String,
    pub security_level: KeySecurityLevel,
    pub created_at: DateTime<Utc>,
}

pub enum EnrollmentViewOutcome {
    Ready(EnrollmentView),
    NotFound,
    SessionExpired,
    Internal(String),
}

pub enum ConfirmEnrollmentOutcome {
    /// Code returned to the app (put on the Auth Tab return target).
    Confirmed {
        code: String,
    },
    PasskeyRequired,
    NotFound,
    SessionExpired,
    Internal(String),
}

/// An "authenticator app" row on the account screen.
pub struct ApproverKeySummary {
    pub id: Uuid,
    pub device_name: String,
    pub security_level: KeySecurityLevel,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub enum ApproverKeysOutcome {
    Listed(Vec<ApproverKeySummary>),
    SessionExpired,
    Internal(String),
}

pub enum RevokeApproverKeyOutcome {
    Revoked { sessions: usize },
    NotFound,
    SessionExpired,
    Internal(String),
}

/// Inputs for web starting a request.
pub struct StartApproval<'a> {
    pub auth_session_id: Option<&'a str>,
    pub country: Option<&'a str>,
}

// ─── Service ─────────────────────────────────────────────────────────

pub struct AppApprovalDependencies {
    pub keys: Arc<dyn ApproverKeyRepository>,
    pub enrollments: Arc<dyn ApproverEnrollmentRepository>,
    pub requests: Arc<dyn ApprovalRequestRepository>,
    pub users: Arc<dyn UserRepository>,
    pub memberships: Arc<dyn TenantMembershipRepository>,
    pub sso_sessions: Arc<dyn SsoSessionRepository>,
    pub refresh_tokens: Arc<dyn RefreshTokenRepository>,
    pub auth_sessions: Arc<dyn AuthSessionRepository>,
    pub clients: Arc<dyn ClientRepository>,
    pub policy_gate: Arc<AuthenticationPolicyGate>,
    pub sign_in: Arc<SignInCompletion>,
    pub settings: Arc<dyn EffectiveTenantSettings>,
    pub audit: Arc<AuditService>,
    pub alerts: Arc<dyn SecurityAlertSink>,
    pub rate_limiter: Arc<dyn LoginRateLimiter>,
    pub clock: Arc<dyn Clock>,
}

pub struct AppApprovalService {
    deps: AppApprovalDependencies,
    /// `None` means the authenticator app routes are closed.
    policy: Option<AttestationPolicy>,
}

impl AppApprovalService {
    pub fn new(deps: AppApprovalDependencies, policy: Option<AttestationPolicy>) -> Self {
        Self { deps, policy }
    }

    pub fn is_enabled(&self) -> bool {
        self.policy.is_some()
    }

    fn policy(&self) -> Result<&AttestationPolicy, AppApproverError> {
        self.policy.as_ref().ok_or(AppApproverError::Disabled)
    }

    // ── Key registration (app) ──────────────────────────────────────────────

    /// Starts registration intake and returns the challenge to include in the Key Attestation.
    pub async fn start_enrollment(
        &self,
        tenant: TenantContext,
        ctx: &RequestContext,
    ) -> Result<EnrollmentStarted, AppApproverError> {
        self.policy()?;
        let now = self.deps.clock.now();
        self.rate_limit(ctx, now)?;
        let enrollment = ApproverEnrollment::start(tenant.tenant_id().as_uuid(), now);
        self.deps.enrollments.insert(&enrollment).await?;
        Ok(EnrollmentStarted {
            enrollment_id: enrollment.id,
            challenge: enrollment.challenge,
            expires_at: enrollment.expires_at,
        })
    }

    /// Verifies the key's certificate chain (base64 DER, key certificate first) and moves to waiting for the user's confirmation.
    pub async fn submit_key(
        &self,
        tenant: TenantContext,
        enrollment_id: &str,
        certificate_chain: &[String],
        device_name: &str,
        ctx: &RequestContext,
    ) -> Result<(), AppApproverError> {
        let policy = self.policy()?;
        let now = self.deps.clock.now();
        let mut enrollment = self.live_enrollment(tenant, enrollment_id, now).await?;
        if enrollment.stage != EnrollmentStage::AwaitingKey {
            return Err(AppApproverError::Conflict);
        }
        let device_name =
            app_approver::normalize_device_name(device_name).ok_or(AppApproverError::BadRequest)?;
        let chain = certificate_chain
            .iter()
            .map(|c| STANDARD.decode(c.trim().as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AppApproverError::BadRequest)?;
        if chain.iter().any(|c| c.len() > MAX_CERT_BYTES) {
            return Err(AppApproverError::BadRequest);
        }
        let challenge = enrollment.challenge_bytes().ok_or_else(|| {
            AppApproverError::Internal("stored challenge is not base64url".into())
        })?;
        let attested = match verify_attestation(&chain, &challenge, policy) {
            Ok(key) => key,
            Err(rejection) => {
                self.deps
                    .audit
                    .record(
                        AuditEventType::ApproverKeyRejected,
                        AuditResult::Failure,
                        Some(tenant.tenant_id()),
                        None,
                        None,
                        Some(&format!("reason={}", rejection.as_str())),
                        ctx,
                    )
                    .await;
                // Discard the intake (do not let it be redone with the same challenge).
                let _ = self.deps.enrollments.delete(&enrollment.id).await;
                return Err(AppApproverError::AttestationRejected(rejection));
            }
        };
        let key_id = app_approver::key_id_of(&attested.public_key_spki);
        if self.deps.keys.find_by_key_id(&key_id).await?.is_some() {
            return Err(AppApproverError::AlreadyRegistered);
        }
        enrollment.stage = EnrollmentStage::AwaitingConfirmation {
            public_key_spki: attested.public_key_spki,
            security_level: attested.security_level,
            device_name,
        };
        if !self
            .deps
            .enrollments
            .advance(&enrollment, "awaiting_key")
            .await?
        {
            return Err(AppApproverError::Conflict);
        }
        Ok(())
    }

    /// Activates the intake with the code issued at the user's confirmation and the key's signature.
    pub async fn activate(
        &self,
        tenant: TenantContext,
        enrollment_id: &str,
        code: &str,
        signature: &str,
        ctx: &RequestContext,
    ) -> Result<ActivatedKey, AppApproverError> {
        self.policy()?;
        let now = self.deps.clock.now();
        let enrollment = self.live_enrollment(tenant, enrollment_id, now).await?;
        let EnrollmentStage::Confirmed {
            public_key_spki,
            security_level,
            device_name,
            user_id,
            code_hash,
            code_expires_at,
        } = &enrollment.stage
        else {
            return Err(AppApproverError::Conflict);
        };
        if *code_expires_at <= now {
            return Err(AppApproverError::Expired);
        }
        if crypto::sha256_hex(code) != *code_hash {
            return Err(AppApproverError::SignatureInvalid);
        }
        let message = signed_message(
            SignedAction::Activate,
            &tenant.tenant_id().as_uuid().to_string(),
            enrollment_id,
            code,
        );
        if !signature_matches(public_key_spki, &message, signature) {
            return Err(AppApproverError::SignatureInvalid);
        }
        // Only the one that managed to delete the intake activates (double submission of the same code passes only once).
        if !self.deps.enrollments.delete(&enrollment.id).await? {
            return Err(AppApproverError::Conflict);
        }
        let user = self.member(tenant.tenant_id(), *user_id).await?;
        let key = ApproverKey {
            id: Uuid::now_v7(),
            user_id: user.id,
            key_id: app_approver::key_id_of(public_key_spki),
            public_key_spki: public_key_spki.clone(),
            security_level: *security_level,
            device_name: device_name.clone(),
            registered_at: now,
            last_used_at: None,
        };
        match self.deps.keys.insert(&key).await {
            Ok(()) => {}
            Err(DomainError::Conflict(_)) => return Err(AppApproverError::AlreadyRegistered),
            Err(e) => return Err(e.into()),
        }
        self.deps
            .audit
            .record(
                AuditEventType::ApproverKeyRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                None,
                Some(&format!(
                    "approver_key={} level={}",
                    key.id,
                    key.security_level.as_str()
                )),
                ctx,
            )
            .await;
        self.alert(
            &user,
            SecurityAlertKind::ApproverKeyRegistered {
                device_name: key.device_name.clone(),
            },
            now,
            None,
            ctx,
            &key.key_id,
        )
        .await;
        Ok(ActivatedKey {
            key_id: key.key_id,
            username: display_username(&user),
            display_name: user.name.clone().filter(|n| !n.is_empty()),
        })
    }

    /// Whether the app's key is still valid (the app asks on every launch; if revoked, it suggests registering again).
    pub async fn key_is_active(&self, key_id: &str) -> Result<bool, AppApproverError> {
        self.policy()?;
        Ok(self.deps.keys.find_by_key_id(key_id).await?.is_some())
    }

    /// Revokes the key from the app (`signed_at` within 5 minutes). Login states approved with that key also end.
    pub async fn revoke_by_app(
        &self,
        tenant: TenantContext,
        key_id: &str,
        signed_at: &str,
        signature: &str,
        ctx: &RequestContext,
    ) -> Result<(), AppApproverError> {
        self.policy()?;
        let now = self.deps.clock.now();
        if !signed_at_is_fresh(signed_at, now) {
            return Err(AppApproverError::SignatureInvalid);
        }
        let key = self
            .deps
            .keys
            .find_by_key_id(key_id)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        let message = signed_message(
            SignedAction::Revoke,
            &tenant.tenant_id().as_uuid().to_string(),
            key_id,
            signed_at,
        );
        if !signature_matches(&key.public_key_spki, &message, signature) {
            return Err(AppApproverError::SignatureInvalid);
        }
        let user = self
            .deps
            .users
            .find_by_id(key.user_id)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        self.remove_key(tenant, &user, key.id, None, now, ctx)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        Ok(())
    }

    // ── Approval (app) ───────────────────────────────────────────────────

    /// Request content (shown by the app before approval).
    pub async fn view_request(
        &self,
        tenant: TenantContext,
        request_id: &str,
    ) -> Result<ApprovalRequestView, AppApproverError> {
        self.policy()?;
        let now = self.deps.clock.now();
        let request = self
            .deps
            .requests
            .find(tenant.tenant_id().as_uuid(), request_id)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        if request.is_expired_at(now) {
            return Err(AppApproverError::Expired);
        }
        let client_name = match request.client_id.as_deref() {
            Some(client_id) => Some(
                self.deps
                    .clients
                    .find_by_client_id(tenant.tenant_id(), client_id)
                    .await?
                    .map(|c| c.app_name)
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| client_id.to_string()),
            ),
            None => None,
        };
        Ok(ApprovalRequestView {
            request_id: request.id,
            challenge: request.challenge,
            state: request.state,
            created_at: request.created_at,
            expires_at: request.expires_at,
            ip_address: request.ip_address,
            country: request.country,
            client_name,
        })
    }

    /// Approves. The returned code is usable once, for 30 seconds.
    pub async fn approve(
        &self,
        tenant: TenantContext,
        request_id: &str,
        key_id: &str,
        signature: &str,
        ctx: &RequestContext,
    ) -> Result<Approved, AppApproverError> {
        self.policy()?;
        let now = self.deps.clock.now();
        let (request, key, user) = self
            .signed_decision(tenant, request_id, key_id, signature, SignedAction::Approve)
            .await?;
        let code = app_approver::random_value();
        let expires_at = (now + Duration::seconds(APPROVAL_CODE_TTL_SECS)).min(request.expires_at);
        if !self
            .deps
            .requests
            .approve(
                &request.id,
                key.id,
                user.id,
                &crypto::sha256_hex(&code),
                expires_at,
            )
            .await?
        {
            return Err(AppApproverError::Conflict);
        }
        if let Err(e) = self.deps.keys.touch(key.id, now).await {
            tracing::warn!(error = %e, "approver key usage could not be recorded");
        }
        self.deps
            .audit
            .record(
                AuditEventType::AppApprovalApproved,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                request.client_id.as_deref(),
                Some(&format!("approver_key={}", key.id)),
                ctx,
            )
            .await;
        Ok(Approved { code })
    }

    /// Denies.
    pub async fn deny(
        &self,
        tenant: TenantContext,
        request_id: &str,
        key_id: &str,
        signature: &str,
        ctx: &RequestContext,
    ) -> Result<(), AppApproverError> {
        self.policy()?;
        let (request, key, user) = self
            .signed_decision(tenant, request_id, key_id, signature, SignedAction::Deny)
            .await?;
        if !self
            .deps
            .requests
            .transition(&request.id, ApprovalState::Pending, ApprovalState::Denied)
            .await?
        {
            return Err(AppApproverError::Conflict);
        }
        self.deps
            .audit
            .record(
                AuditEventType::AppApprovalDenied,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                request.client_id.as_deref(),
                Some(&format!("approver_key={}", key.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Common checks for approve/deny: the request is alive and waiting, the key is valid, the signature matches, the owner can use this organization.
    async fn signed_decision(
        &self,
        tenant: TenantContext,
        request_id: &str,
        key_id: &str,
        signature: &str,
        action: SignedAction,
    ) -> Result<(ApprovalRequest, ApproverKey, User), AppApproverError> {
        let now = self.deps.clock.now();
        let request = self
            .deps
            .requests
            .find(tenant.tenant_id().as_uuid(), request_id)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        if request.is_expired_at(now) {
            return Err(AppApproverError::Expired);
        }
        if request.state != ApprovalState::Pending {
            return Err(AppApproverError::Conflict);
        }
        let key = self
            .deps
            .keys
            .find_by_key_id(key_id)
            .await?
            .ok_or(AppApproverError::KeyRevoked)?;
        let message = signed_message(
            action,
            &tenant.tenant_id().as_uuid().to_string(),
            &request.id,
            &request.challenge,
        );
        if !signature_matches(&key.public_key_spki, &message, signature) {
            return Err(AppApproverError::SignatureInvalid);
        }
        let user = self.member(tenant.tenant_id(), key.user_id).await?;
        Ok((request, key, user))
    }

    // ── Request and completion (web login screen) ─────────────────────────────────

    /// Starts a "continue with the app" request. The returned mark is handed only to the starting browser (cookie).
    pub async fn start_request(
        &self,
        tenant: TenantContext,
        cmd: StartApproval<'_>,
        ctx: &RequestContext,
    ) -> StartApprovalOutcome {
        if self.policy.is_none() {
            return StartApprovalOutcome::Disabled;
        }
        let now = self.deps.clock.now();
        if self.rate_limit(ctx, now).is_err() {
            return StartApprovalOutcome::RateLimited;
        }
        // If it came mid-authorization, link that AuthSession (show the RP's name, continue on completion).
        let (auth_session_hash, client_id) = match cmd.auth_session_id {
            Some(id) => {
                let hash = AuthSessionIdHash::of_plain(id);
                match self
                    .deps
                    .auth_sessions
                    .find(tenant.tenant_id(), &hash)
                    .await
                {
                    Ok(Some(s)) if !s.is_expired_at(now) => (
                        Some(hash.as_str().to_string()),
                        Some(s.client_id().to_string()),
                    ),
                    Ok(_) => (None, None),
                    Err(e) => return StartApprovalOutcome::Internal(e.to_string()),
                }
            }
            None => (None, None),
        };
        let (browser_binding, browser_binding_hash) = app_approver::new_browser_binding();
        let request = ApprovalRequest {
            id: app_approver::random_value(),
            tenant_id: tenant.tenant_id().as_uuid(),
            browser_binding_hash,
            auth_session_hash,
            client_id,
            challenge: app_approver::random_value(),
            state: ApprovalState::Pending,
            ip_address: ctx.ip_address.clone(),
            country: cmd
                .country
                .and_then(CountryCode::parse)
                .map(|c| c.as_str().to_string()),
            approver_key: None,
            user_id: None,
            code_hash: None,
            code_expires_at: None,
            created_at: now,
            expires_at: now + Duration::seconds(REQUEST_TTL_SECS),
        };
        if let Err(e) = self.deps.requests.insert(&request).await {
            return StartApprovalOutcome::Internal(e.to_string());
        }
        StartApprovalOutcome::Started {
            request_id: request.id,
            browser_binding,
        }
    }

    /// Completes in the browser the app opened, matching the code and the mark.
    pub async fn complete_request(
        &self,
        tenant: TenantContext,
        request_id: &str,
        code: &str,
        browser_binding: Option<&str>,
        ctx: &RequestContext,
    ) -> CompleteApprovalOutcome {
        if self.policy.is_none() {
            return CompleteApprovalOutcome::Invalid;
        }
        let now = self.deps.clock.now();
        let request = match self
            .deps
            .requests
            .find(tenant.tenant_id().as_uuid(), request_id)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return CompleteApprovalOutcome::Invalid,
            Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
        };
        let (Some(code_hash), Some(code_expires_at), Some(key_ref), Some(user_id)) = (
            request.code_hash.as_deref(),
            request.code_expires_at,
            request.approver_key,
            request.user_id,
        ) else {
            return CompleteApprovalOutcome::Invalid;
        };
        if request.state != ApprovalState::Approved
            || code_expires_at <= now
            || crypto::sha256_hex(code) != code_hash
        {
            return CompleteApprovalOutcome::Invalid;
        }
        let same_browser =
            browser_binding.is_some_and(|b| crypto::sha256_hex(b) == request.browser_binding_hash);
        if !same_browser {
            return self
                .refuse_another_browser(tenant, &request, user_id, key_ref, now, ctx)
                .await;
        }
        // Only the one that managed to move the state completes (double use of the same code passes only once).
        match self
            .deps
            .requests
            .transition(
                &request.id,
                ApprovalState::Approved,
                ApprovalState::Completed,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return CompleteApprovalOutcome::Invalid,
            Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
        }
        let user = match self.member(tenant.tenant_id(), user_id).await {
            Ok(user) => user,
            Err(AppApproverError::Internal(e)) => return CompleteApprovalOutcome::Internal(e),
            Err(_) => return CompleteApprovalOutcome::UserUnavailable,
        };
        self.sign_in(tenant, &request, &user, key_ref, now, ctx)
            .await
    }

    /// Completion in a browser whose mark does not match: end the request, audit it, notify. No login is allowed.
    async fn refuse_another_browser(
        &self,
        tenant: TenantContext,
        request: &ApprovalRequest,
        user_id: Uuid,
        key_ref: Uuid,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> CompleteApprovalOutcome {
        match self
            .deps
            .requests
            .transition(&request.id, ApprovalState::Approved, ApprovalState::Refused)
            .await
        {
            Ok(true) => {}
            // Do not notify a second time for a request already completed or denied.
            Ok(false) => return CompleteApprovalOutcome::AnotherBrowser,
            Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
        }
        self.deps
            .audit
            .record(
                AuditEventType::AppApprovalRefused,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                Some(user_id),
                request.client_id.as_deref(),
                Some(&format!("approver_key={key_ref} reason=browser_binding")),
                ctx,
            )
            .await;
        match self.deps.users.find_by_id(user_id).await {
            Ok(Some(user)) => {
                let device_name = match self.deps.keys.list_for_user(user_id).await {
                    Ok(keys) => keys
                        .into_iter()
                        .find(|k| k.id == key_ref)
                        .map(|k| k.device_name)
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                };
                self.alert(
                    &user,
                    SecurityAlertKind::AppApprovalFromAnotherBrowser { device_name },
                    now,
                    None,
                    ctx,
                    &request.id,
                )
                .await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "user for a refused approval could not be read"),
        }
        CompleteApprovalOutcome::AnotherBrowser
    }

    /// Runs the authentication policy, creates an SSO session (app-approved, 30 days) and continues the authorization.
    async fn sign_in(
        &self,
        tenant: TenantContext,
        request: &ApprovalRequest,
        user: &User,
        key_ref: Uuid,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> CompleteApprovalOutcome {
        let tenant_id = tenant.tenant_id();
        let mut originating = None;
        if let Some(hash) = request.auth_session_hash.as_deref() {
            match self
                .deps
                .auth_sessions
                .find(tenant_id, &AuthSessionIdHash::from_stored(hash.to_string()))
                .await
            {
                Ok(Some(s)) if !s.is_expired_at(now) => originating = Some(s),
                Ok(_) => {}
                Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
            }
        }
        let requested_acr = originating
            .as_ref()
            .map(|s| s.request().requested_acr())
            .unwrap_or_default();
        let audience = match originating.as_ref() {
            Some(s) => PolicyAudience::OidcClient(s.client_id()),
            None => PolicyAudience::Unaddressed,
        };
        let decision = match self
            .deps
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience,
                user_id: user.id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &requested_acr,
                now,
            })
            .await
        {
            Ok(d) => d,
            Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
        };
        // The approval is a signature by a Keystore key (possession) unlocked by fingerprint (biometric), so it satisfies an MFA requirement.
        // It does not satisfy a method requirement ("must be a passkey").
        let denied = matches!(decision, PolicyDecision::Deny { .. })
            || decision
                .unmet_method_requirement(&[AuthenticationMethod::AppApproval], true)
                .is_some();
        if denied {
            self.deps
                .audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    request.client_id.as_deref(),
                    Some("method=app_approval"),
                    ctx,
                )
                .await;
            return CompleteApprovalOutcome::PolicyDenied;
        }

        let sso = match self
            .deps
            .sign_in
            .establish_sso_with_binding(
                SignIn {
                    tenant_id,
                    user_id: user.id,
                    home_tenant_id: user.tenant_id,
                    methods: vec![AuthenticationMethod::AppApproval],
                    client_id: request.client_id.as_deref(),
                    success_event: AuditEventType::LoginSucceeded,
                    success_detail: Some(format!("method=app_approval approver_key={key_ref}")),
                },
                crate::domain::session_key::SessionBinding::AppApproval,
                ctx,
                now,
            )
            .await
        {
            Ok(crate::application::sign_in_completion::Establishment::Established(sso)) => sso,
            // A login approved with the authenticator app passes the gate (task #916; the approving key is a key of a device registered with a passkey).
            Ok(
                crate::application::sign_in_completion::Establishment::DeviceEnrollmentRequired {
                    ..
                },
            ) => {
                return CompleteApprovalOutcome::Internal(
                    "app approval was sent to device enrollment".to_string(),
                )
            }
            Err(e) => return CompleteApprovalOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self
            .deps
            .keys
            .link_session(&sso.session().session_hash, key_ref)
            .await
        {
            // If the binding cannot be kept, the login state could not be cut by revocation. Delete what was created and refuse.
            let _ = self
                .deps
                .sso_sessions
                .delete(&sso.session().session_hash)
                .await;
            return CompleteApprovalOutcome::Internal(e.to_string());
        }
        self.continue_authorization(tenant, originating, &sso, now, ctx)
            .await
    }

    async fn continue_authorization(
        &self,
        tenant: TenantContext,
        originating: Option<crate::domain::auth_session::AuthSession>,
        sso: &EstablishedSso,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> CompleteApprovalOutcome {
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        let Some(mut session) = originating else {
            return CompleteApprovalOutcome::Success {
                location: None,
                form_post: None,
                sso_session_id,
                sso_absolute_ttl_secs,
            };
        };
        match self
            .deps
            .sign_in
            .continue_authorization(tenant, &mut session, sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                CompleteApprovalOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                CompleteApprovalOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => {
                CompleteApprovalOutcome::Success {
                    location: Some(dispatch.location),
                    form_post: dispatch.form_post,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Err(e) => CompleteApprovalOutcome::Internal(e.to_string()),
        }
    }

    // ── Account screen (web) ──────────────────────────────────────────

    /// Content shown on the registration confirmation screen.
    pub async fn enrollment_for_confirmation(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        enrollment_id: &str,
    ) -> EnrollmentViewOutcome {
        if self.policy.is_none() {
            return EnrollmentViewOutcome::NotFound;
        }
        let now = self.deps.clock.now();
        match self.active_session(sso_session_id, now).await {
            Ok(Some(_)) => {}
            Ok(None) => return EnrollmentViewOutcome::SessionExpired,
            Err(e) => return EnrollmentViewOutcome::Internal(e),
        }
        match self.live_enrollment(tenant, enrollment_id, now).await {
            Ok(ApproverEnrollment {
                stage:
                    EnrollmentStage::AwaitingConfirmation {
                        device_name,
                        security_level,
                        ..
                    },
                created_at,
                ..
            }) => EnrollmentViewOutcome::Ready(EnrollmentView {
                device_name,
                security_level,
                created_at,
            }),
            Ok(_) | Err(AppApproverError::NotFound | AppApproverError::Expired) => {
                EnrollmentViewOutcome::NotFound
            }
            Err(e) => EnrollmentViewOutcome::Internal(format!("{e:?}")),
        }
    }

    /// The user confirmed the registration (only within 5 minutes of confirming with a passkey). Issues the code returned to the app.
    pub async fn confirm_enrollment(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        enrollment_id: &str,
    ) -> ConfirmEnrollmentOutcome {
        if self.policy.is_none() {
            return ConfirmEnrollmentOutcome::NotFound;
        }
        let now = self.deps.clock.now();
        let (session, user) = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return ConfirmEnrollmentOutcome::SessionExpired,
            Err(e) => return ConfirmEnrollmentOutcome::Internal(e),
        };
        match self
            .deps
            .sso_sessions
            .passkey_verified_at(&session.session_hash)
            .await
        {
            Ok(at) if passkey_verified_recently(&session, at, now) => {}
            Ok(_) => return ConfirmEnrollmentOutcome::PasskeyRequired,
            Err(e) => return ConfirmEnrollmentOutcome::Internal(e.to_string()),
        }
        match self
            .deps
            .memberships
            .is_active_member(tenant.tenant_id(), user.id)
            .await
        {
            Ok(true) => {}
            Ok(false) => return ConfirmEnrollmentOutcome::NotFound,
            Err(e) => return ConfirmEnrollmentOutcome::Internal(e.to_string()),
        }
        let mut enrollment = match self.live_enrollment(tenant, enrollment_id, now).await {
            Ok(e) => e,
            Err(AppApproverError::Internal(e)) => return ConfirmEnrollmentOutcome::Internal(e),
            Err(_) => return ConfirmEnrollmentOutcome::NotFound,
        };
        let EnrollmentStage::AwaitingConfirmation {
            public_key_spki,
            security_level,
            device_name,
        } = enrollment.stage.clone()
        else {
            return ConfirmEnrollmentOutcome::NotFound;
        };
        let code = app_approver::random_value();
        enrollment.stage = EnrollmentStage::Confirmed {
            public_key_spki,
            security_level,
            device_name,
            user_id: user.id,
            code_hash: crypto::sha256_hex(&code),
            code_expires_at: (now + Duration::seconds(ENROLLMENT_CODE_TTL_SECS))
                .min(enrollment.expires_at),
        };
        match self
            .deps
            .enrollments
            .advance(&enrollment, "awaiting_confirmation")
            .await
        {
            Ok(true) => ConfirmEnrollmentOutcome::Confirmed { code },
            Ok(false) => ConfirmEnrollmentOutcome::NotFound,
            Err(e) => ConfirmEnrollmentOutcome::Internal(e.to_string()),
        }
    }

    /// The "authenticator app" rows of "my devices".
    pub async fn keys_for_account(&self, sso_session_id: &str) -> ApproverKeysOutcome {
        let now = self.deps.clock.now();
        let user = match self.active_session(sso_session_id, now).await {
            Ok(Some((_, user))) => user,
            Ok(None) => return ApproverKeysOutcome::SessionExpired,
            Err(e) => return ApproverKeysOutcome::Internal(e),
        };
        match self.deps.keys.list_for_user(user.id).await {
            Ok(keys) => ApproverKeysOutcome::Listed(
                keys.into_iter()
                    .map(|k| ApproverKeySummary {
                        id: k.id,
                        device_name: k.device_name,
                        security_level: k.security_level,
                        registered_at: k.registered_at,
                        last_used_at: k.last_used_at,
                    })
                    .collect(),
            ),
            Err(e) => ApproverKeysOutcome::Internal(e.to_string()),
        }
    }

    /// Revokes a key from the account screen. Login states approved with that key also end (the current screen's stays).
    pub async fn revoke_from_account(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        key: Uuid,
        ctx: &RequestContext,
    ) -> RevokeApproverKeyOutcome {
        let now = self.deps.clock.now();
        let (session, user) = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return RevokeApproverKeyOutcome::SessionExpired,
            Err(e) => return RevokeApproverKeyOutcome::Internal(e),
        };
        match self
            .remove_key(tenant, &user, key, Some(&session.session_hash), now, ctx)
            .await
        {
            Ok(Some(sessions)) => RevokeApproverKeyOutcome::Revoked { sessions },
            Ok(None) => RevokeApproverKeyOutcome::NotFound,
            Err(e) => RevokeApproverKeyOutcome::Internal(format!("{e:?}")),
        }
    }

    /// Deletes the key and ends login states and refresh tokens approved with it. Returns the number deleted.
    ///
    /// `keep_session` is the account screen's login state (do not kick the user out of their own screen).
    async fn remove_key(
        &self,
        tenant: TenantContext,
        user: &User,
        key: Uuid,
        keep_session: Option<&str>,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> Result<Option<usize>, AppApproverError> {
        // Before deleting, fetch login states approved with the key (deleting makes the binding NULL).
        let sessions = self.deps.keys.approved_sessions(key).await?;
        let Some(removed) = self.deps.keys.delete(user.id, key).await? else {
            return Ok(None);
        };
        let mut ended = 0;
        for hash in sessions {
            if Some(hash.as_str()) == keep_session {
                continue;
            }
            self.deps.sso_sessions.delete(&hash).await?;
            self.deps
                .refresh_tokens
                .revoke_all_for_session(user.id, &sso_session::sid_of(&hash), now)
                .await?;
            ended += 1;
        }
        self.deps
            .audit
            .record(
                AuditEventType::ApproverKeyRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                None,
                Some(&format!("approver_key={} sessions={ended}", removed.id)),
                ctx,
            )
            .await;
        self.alert(
            user,
            SecurityAlertKind::ApproverKeyRevoked {
                device_name: removed.device_name.clone(),
            },
            now,
            None,
            ctx,
            &removed.key_id,
        )
        .await;
        Ok(Some(ended))
    }

    // ── Common ───────────────────────────────────────────────────────────

    async fn live_enrollment(
        &self,
        tenant: TenantContext,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<ApproverEnrollment, AppApproverError> {
        let enrollment = self
            .deps
            .enrollments
            .find(tenant.tenant_id().as_uuid(), id)
            .await?
            .ok_or(AppApproverError::NotFound)?;
        if enrollment.is_expired_at(now) {
            return Err(AppApproverError::Expired);
        }
        Ok(enrollment)
    }

    /// Whether the key's owner is a user who can currently use this organization.
    async fn member(&self, tenant_id: TenantId, user_id: Uuid) -> Result<User, AppApproverError> {
        let now = self.deps.clock.now();
        let user = self
            .deps
            .users
            .find_by_id(user_id)
            .await?
            .filter(|u| u.is_active() && !u.is_locked_at(now))
            .ok_or(AppApproverError::NotAMember)?;
        if !self
            .deps
            .memberships
            .is_active_member(tenant_id, user.id)
            .await?
        {
            return Err(AppApproverError::NotAMember);
        }
        Ok(user)
    }

    async fn active_session(
        &self,
        sso_session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(SsoSession, User)>, String> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = match self.deps.sso_sessions.find_by_hash(&hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.deps.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some((session, user))),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Unauthenticated routes (intake, starting a request) are throttled by a per-IP bucket (same bucket as login).
    fn rate_limit(&self, ctx: &RequestContext, now: DateTime<Utc>) -> Result<(), AppApproverError> {
        match &ctx.ip_address {
            Some(ip) if !self.deps.rate_limiter.check_and_record(ip, now) => {
                Err(AppApproverError::RateLimited)
            }
            _ => Ok(()),
        }
    }

    /// Notifies (only when enabled in the home tenant; if unreadable, fall to notifying).
    async fn alert(
        &self,
        user: &User,
        kind: SecurityAlertKind,
        now: DateTime<Utc>,
        country: Option<CountryCode>,
        ctx: &RequestContext,
        group: &str,
    ) {
        let enabled = match self
            .deps
            .settings
            .unregistered_device_alerts_enabled(user.tenant_id)
            .await
        {
            Ok(enabled) => enabled,
            Err(e) => {
                tracing::warn!(error = %e, "alert setting could not be read; sending anyway");
                true
            }
        };
        if !enabled {
            return;
        }
        self.deps
            .alerts
            .send(SecurityAlert {
                kind,
                tenant_id: user.tenant_id,
                user_id: user.id,
                username: display_username(user),
                occurred_at: now,
                country,
                ip_address: ctx.ip_address.clone(),
                user_agent: ctx.user_agent.clone(),
                group_key: group.chars().take(16).collect(),
            })
            .await;
    }
}

fn display_username(user: &User) -> String {
    user.preferred_username
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]))
}

/// Whether the app's signature (base64url DER) matches the key and the message.
fn signature_matches(spki: &[u8], message: &str, signature: &str) -> bool {
    match URL_SAFE_NO_PAD.decode(signature.trim().as_bytes()) {
        Ok(sig) => verify_p256_signature(spki, message.as_bytes(), &sig),
        Err(_) => false,
    }
}
