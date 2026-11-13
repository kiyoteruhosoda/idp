//! Binds SSO sessions to a device key (Chrome's DBSC. task #887. ADR-0074).
//!
//! # Flow
//!
//! 1. **Registration**: in the sign-in response the web asks Chrome to bind; Chrome creates a key inside the TPM and sends
//!    a signature with the public key to `/dbsc/register`. The web passes it to [`SessionKeyBindingService::register`].
//! 2. **Refresh**: when the short Cookie (10 minutes) expires, Chrome resends a key signature at `/dbsc/refresh`
//!    ([`SessionKeyBindingService::refresh`]).
//! 3. **Entrance check**: for a request without a matching short Cookie, the web asks [`SessionKeyBindingService::binding_of`]
//!    whether it is bound, and if so strips the long Cookie (web side).
//!
//! # Lifetime
//!
//! Reset on every registration and refresh ([`lifetime_for`]). If bound and the device of that signed-in state (the
//! device mark of ADR-0071) is registered, `SSO_BOUND_TTL_SECS`; otherwise `SSO_ABSOLUTE_TTL_SECS`.
//!
//! # Signatures from a different key
//!
//! If a bound signed-in state receives a signature from a key different from the registered one (including re-registration),
//! that signed-in state is ended (refresh tokens too. ADR-0044), audited, and notified. It is a sign the Cookie was exfiltrated.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    RefreshTokenRepository, SessionKeyBindingRepository, SsoSessionRepository,
    UserDeviceRepository, UserRepository,
};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::session_key::{
    lifetime_for, verify_refresh, verify_registration, ProofError, SessionBinding,
    SessionKeyBinding,
};
use crate::domain::sso_session::{self, SsoSession};
use crate::domain::user::User;
use assay_contracts::session_key as contract;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;

/// Result of registration or refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyOutcome {
    /// Bound or refreshed. `remaining_secs` is the seconds until the signed-in state expires (the long Cookie's Max-Age).
    Bound {
        session_identifier: String,
        remaining_secs: u64,
    },
    /// Signature, challenge, or shape does not match (the binding is not changed).
    Rejected,
    /// Signed with a key different from the registered one. The signed-in state was ended.
    KeyMismatch,
    /// The signed-in state is missing, expired, or the identifier differs.
    SessionGone,
}

pub struct SessionKeyBindingService {
    bindings: Arc<dyn SessionKeyBindingRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    devices: Arc<dyn UserDeviceRepository>,
    users: Arc<dyn UserRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// HMAC key for challenges (`CSRF_SECRET`. Purposes are separated on the contracts side).
    secret: [u8; 32],
}

#[derive(Deserialize)]
struct UnverifiedClaims {
    jti: Option<String>,
}

impl SessionKeyBindingService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bindings: Arc<dyn SessionKeyBindingRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        devices: Arc<dyn UserDeviceRepository>,
        users: Arc<dyn UserRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        secret: [u8; 32],
    ) -> Self {
        Self {
            bindings,
            sso_sessions,
            devices,
            users,
            refresh_tokens,
            settings,
            alerts,
            audit,
            clock,
            secret,
        }
    }

    /// Returns the identifier if bound (the web entrance check). `None` for missing or expired sessions.
    pub async fn binding_of(&self, sso_session_id: &str) -> Result<Option<String>, DomainError> {
        let session_hash = crypto::sha256_hex(sso_session_id);
        Ok(self
            .bindings
            .find(&session_hash)
            .await?
            .map(|b| b.session_identifier))
    }

    /// Registration (a signature Chrome sent along with its public key).
    pub async fn register(
        &self,
        sso_session_id: &str,
        proof: &str,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let now = self.clock.now();
        let Some((session, user)) = self.live_session(sso_session_id, now).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        let Some(challenge) = self.fresh_challenge(sso_session_id, proof, now) else {
            self.reject(&user, "stale_challenge", ctx).await;
            return Ok(SessionKeyOutcome::Rejected);
        };
        let key = match verify_registration(proof, &challenge) {
            Ok(key) => key,
            Err(e) => {
                self.reject(&user, e.as_str(), ctx).await;
                return Ok(SessionKeyOutcome::Rejected);
            }
        };
        if let Some(existing) = self.bindings.find(&session.session_hash).await? {
            if existing.key.thumbprint == key.thumbprint {
                // Re-registration with the same key (Chrome restarted, etc.). The binding stays as is.
                return self.renew(&session, &user, &existing, now).await;
            }
            return self.end_for_mismatch(&session, &user, now, ctx).await;
        }
        let binding = SessionKeyBinding {
            session_identifier: crypto::random_hex(16),
            key,
            bound_at: now,
        };
        if !self.bindings.bind(&session.session_hash, &binding).await? {
            // Another registration got in first concurrently. We cannot tell which key is right, so the one that got in wins.
            let Some(existing) = self.bindings.find(&session.session_hash).await? else {
                return Ok(SessionKeyOutcome::SessionGone);
            };
            if existing.key.thumbprint != binding.key.thumbprint {
                return self.end_for_mismatch(&session, &user, now, ctx).await;
            }
            return self.renew(&session, &user, &existing, now).await;
        }
        self.audit
            .record(
                AuditEventType::SessionKeyBound,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some(&format!(
                    "alg={} thumbprint={}",
                    binding.key.algorithm.as_str(),
                    binding.key.thumbprint
                )),
                ctx,
            )
            .await;
        self.renew(&session, &user, &binding, now).await
    }

    /// Refresh (a signature with the registered key when the short Cookie expired).
    pub async fn refresh(
        &self,
        sso_session_id: &str,
        session_identifier: &str,
        proof: &str,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let now = self.clock.now();
        let Some((session, user)) = self.live_session(sso_session_id, now).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        let Some(binding) = self.bindings.find(&session.session_hash).await? else {
            return Ok(SessionKeyOutcome::SessionGone);
        };
        if binding.session_identifier != session_identifier {
            return Ok(SessionKeyOutcome::SessionGone);
        }
        let Some(challenge) = self.fresh_challenge(sso_session_id, proof, now) else {
            // Stale challenge or malformed. The web issues a new challenge (not treated as a sign of exfiltration).
            return Ok(SessionKeyOutcome::Rejected);
        };
        match verify_refresh(proof, &binding.key, &challenge) {
            Ok(()) => {}
            Err(ProofError::BadSignature) => {
                return self.end_for_mismatch(&session, &user, now, ctx).await;
            }
            Err(e) => {
                self.reject(&user, e.as_str(), ctx).await;
                return Ok(SessionKeyOutcome::Rejected);
            }
        }
        self.bindings
            .record_refresh(&session.session_hash, now)
            .await?;
        self.renew(&session, &user, &binding, now).await
    }

    /// The live session and the user.
    async fn live_session(
        &self,
        sso_session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(SsoSession, User)>, DomainError> {
        let session_hash = crypto::sha256_hex(sso_session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(None);
        };
        if !session.is_valid_at(now) {
            return Ok(None);
        }
        let Some(user) = self.users.find_by_id(session.user_id).await? else {
            return Ok(None);
        };
        Ok(Some((session, user)))
    }

    /// Whether the signature's `jti` is a fresh challenge issued to this session. If so, returns that value.
    ///
    /// The signature is not verified here (verification is the domain's `verify_*`, which checks `jti` again).
    fn fresh_challenge(
        &self,
        sso_session_id: &str,
        proof: &str,
        now: DateTime<Utc>,
    ) -> Option<String> {
        let claims = jsonwebtoken::dangerous::insecure_decode::<UnverifiedClaims>(proof).ok()?;
        let jti = claims.claims.jti?;
        contract::challenge_is_fresh(&self.secret, sso_session_id, &jti, now.timestamp())
            .then_some(jti)
    }

    /// Resets the lifetime and returns the bound result.
    async fn renew(
        &self,
        session: &SsoSession,
        user: &User,
        binding: &SessionKeyBinding,
        now: DateTime<Utc>,
    ) -> Result<SessionKeyOutcome, DomainError> {
        let lifetime = self.settings.sso_session_lifetime(user.tenant_id).await?;
        let device_registered = match self.devices.session_device(&session.session_hash).await? {
            Some(device) => self.devices.find(user.id, &device).await?.is_some(),
            None => false,
        };
        let (idle, absolute) = lifetime_for(
            session.created_at,
            session.idle_expires_at,
            SessionBinding::DeviceKey,
            device_registered,
            lifetime.absolute,
            lifetime.bound,
        );
        if idle != session.idle_expires_at || absolute != session.absolute_expires_at {
            self.sso_sessions
                .set_lifetime(&session.session_hash, idle, absolute)
                .await?;
        }
        if !(idle > now && absolute > now) {
            // After shortening back from 30 days it had already expired (an old signed-in state after the device registration was revoked).
            return Ok(SessionKeyOutcome::SessionGone);
        }
        let remaining = (idle.min(absolute) - now).num_seconds().max(0);
        Ok(SessionKeyOutcome::Bound {
            session_identifier: binding.session_identifier.clone(),
            remaining_secs: u64::try_from(remaining).unwrap_or(0),
        })
    }

    /// A signature from a different key arrived: end the signed-in state, audit, and notify.
    async fn end_for_mismatch(
        &self,
        session: &SsoSession,
        user: &User,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> Result<SessionKeyOutcome, DomainError> {
        self.sso_sessions.delete(&session.session_hash).await?;
        self.refresh_tokens
            .revoke_all_for_session(user.id, &sso_session::sid_of(&session.session_hash), now)
            .await?;
        self.audit
            .record(
                AuditEventType::SessionKeyRejected,
                AuditResult::Failure,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some("key_mismatch"),
                ctx,
            )
            .await;
        self.alert(user, now, ctx).await;
        Ok(SessionKeyOutcome::KeyMismatch)
    }

    async fn reject(&self, user: &User, reason: &str, ctx: &RequestContext) {
        self.audit
            .record(
                AuditEventType::SessionKeyRejected,
                AuditResult::Failure,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }

    /// Notifies. Unlike ADR-0071's device notifications, sent regardless of the organization's settings (a strong sign of theft).
    async fn alert(&self, user: &User, now: DateTime<Utc>, ctx: &RequestContext) {
        let username = user
            .preferred_username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]));
        self.alerts
            .send(SecurityAlert {
                kind: SecurityAlertKind::SessionKeyMismatch,
                tenant_id: user.tenant_id,
                user_id: user.id,
                username,
                occurred_at: now,
                country: None,
                ip_address: ctx.ip_address.clone(),
                user_agent: ctx.user_agent.clone(),
                group_key: format!("key-{}", &user.sub.simple().to_string()[..16]),
            })
            .await;
    }
}
