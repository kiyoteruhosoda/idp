//! Restoring SSO sessions (silent re-authentication).
//!
//! Resuming the OIDC authorization flow ([`crate::application::authorize`]) and SAML SSO
//! ([`crate::application::saml_sso`]) share the same checks:
//! they verify, in order, expiry -> user validity -> **ACTIVE membership in the requested tenant** (ADR-0009 §8),
//! and on success extend the idle expiry and audit `sso_session.resumed`.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// An SSO session that was successfully restored.
pub struct RestoredSso {
    pub user_id: Uuid,
    /// First sign-in time (`auth_time`. Not updated on restore).
    pub auth_time: DateTime<Utc>,
    /// SHA-256 of the session (does not include the raw Cookie value). Can be used to refer to the session
    /// opaquely, e.g. as SAML `SessionIndex`.
    pub session_hash: String,
    /// The authentication method that established this session (AP4. Spec §14.3).
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// Authentication strength (AP4). Input for the step-up authentication (§15) decision.
    pub authentication_strength: AuthenticationStrength,
    /// Time the second factor was verified (AP4). Input for re-authentication by elapsed MFA time (§18.2).
    pub mfa_completed_at: Option<DateTime<Utc>>,
    /// Length (seconds) until the absolute expiry decided at establishment. The `Max-Age` when the web reissues the Cookie
    /// (same value as at sign-in. ADR-0058).
    pub absolute_ttl_secs: u64,
}

pub struct SsoRestorer {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Resolution of settings tenants can override (ADR-0058). Looked up on every reference.
    settings: Arc<dyn EffectiveTenantSettings>,
}

impl SsoRestorer {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            memberships,
            audit,
            clock,
            settings,
        }
    }

    /// Tries to restore an SSO session. If valid, extends the idle expiry and returns [`RestoredSso`].
    /// Expired sessions are deleted and `sso_session.expired` is recorded in the audit log.
    pub async fn try_resume(
        &self,
        tenant: TenantContext,
        session_id: &str,
        ctx: &RequestContext,
    ) -> Result<Option<RestoredSso>, DomainError> {
        let session_hash = crypto::sha256_hex(session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(None);
        };

        let now = self.clock.now();
        if !session.is_valid_at(now) {
            self.sso_sessions.delete(&session_hash).await?;
            self.audit
                .record(
                    AuditEventType::SsoSessionExpired,
                    AuditResult::Failure,
                    Some(tenant.tenant_id()),
                    Some(session.user_id),
                    None,
                    Some("idle or absolute timeout"),
                    ctx,
                )
                .await;
            return Ok(None);
        }

        // Do not restore SSO if the user is disabled (let re-sign-in detect it).
        let home_tenant_id = match self.users.find_by_id(session.user_id).await? {
            Some(user) if user.is_active() && !user.is_locked_at(now) => user.tenant_id,
            _ => return Ok(None),
        };

        // Membership check (ADR-0009 §8): SSO sessions are shared per host, so verify that
        // the user **has an ACTIVE membership (HOME or GUEST) in the requested tenant**.
        // An SSO session without membership is treated as unauthenticated in that tenant's flow (= go to sign-in).
        // Guests establish this SSO by signing in at their home tenant, and are allowed by this check in the tenant they joined.
        if !self
            .memberships
            .is_active_member(tenant.tenant_id(), session.user_id)
            .await?
        {
            return Ok(None);
        }

        // Update the idle expiry (absolute is not changed). auth_time keeps the first sign-in time.
        // ⚠ The extension length is decided by the value of the user's home tenant, **the same as at establishment** (ADR-0058).
        // Deciding by the restored screen's tenant (the joined one for guests) makes lifetime differ between establishment and extension.
        let lifetime = self.settings.sso_session_lifetime(home_tenant_id).await?;
        self.sso_sessions
            .extend_idle(&session_hash, now + lifetime.idle)
            .await?;
        self.audit
            .record(
                AuditEventType::SsoSessionResumed,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(session.user_id),
                None,
                None,
                ctx,
            )
            .await;

        let absolute_ttl_secs = session.absolute_ttl_secs();
        Ok(Some(RestoredSso {
            user_id: session.user_id,
            auth_time: session.auth_time,
            session_hash,
            authentication_methods: session.authentication_methods,
            authentication_strength: session.authentication_strength,
            mfa_completed_at: session.mfa_completed_at,
            absolute_ttl_secs,
        }))
    }
}
