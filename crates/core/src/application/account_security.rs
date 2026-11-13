//! The user's self-service security screen (G10).
//!
//! Handles three things common IdPs have but assay lacked:
//!
//! - **Listing and revoking signed-in sessions.** Lets a user who lost a device cut off other devices'
//!   sessions without going through an admin (until now only the current session could be logged out).
//! - **Reviewing and revoking connected apps (consent).** Once consented, users could not undo it, and
//!   `ClientConsentRepository::revoke` / `list_for_user` were implemented but had no caller.
//! - **Reissuing issued tokens** (ADR-0047). Swaps only the duplicate keys apps hold.
//!   A route to invalidate "keys that may have been handed out" without cutting integrations or devices; until now
//!   the only options were changing the password or removing apps one by one.
//!
//! # How sessions are referenced
//!
//! The primary key of `sso_sessions` is the SHA-256 of the cookie value, and there is no need to show it on screen.
//! A domain-separated irreversible display ID ([`crate::domain::sso_session::SsoSession::display_id`]) is
//! presented, and revocation requests are resolved by matching that value against **the user's own set of sessions**.
//! No route recovers `session_hash` from the value, so even a leaked display ID cannot cut another person's session.
//!
//! # What revoking consent deletes
//!
//! Deleting only the consent row leaves tokens issued under it alive (to the user: "I removed it but it is
//! still connected"). On revocation, that client's refresh tokens are also revoked. Access tokens are
//! self-contained JWTs, so they stay valid until their lifetime (default 15 minutes) ends; this is an accepted
//! design trade-off, and if immediacy is needed, use the mechanism that lists them in `revoked_access_tokens` (F5).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    ClientConsentRepository, ClientRepository, RefreshTokenRepository, SsoSessionRepository,
    UserRepository,
};
use crate::domain::sso_session;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationStrength;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// One login session shown on screen.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    /// Display ID used to reference it in revocation requests (an irreversible derivation of `session_hash`).
    pub id: String,
    /// Whether this session is "the session of the browser in use now".
    pub current: bool,
    pub auth_time: DateTime<Utc>,
    /// Whether the second factor was completed (recorded by AP4; lets users see "this device has done MFA").
    pub multi_factor: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

/// One connected app shown on screen.
#[derive(Debug, Clone)]
pub struct ConnectedAppSummary {
    pub client_id: String,
    /// Display name (falls back to `client_id` if the client was deleted).
    pub app_name: String,
    /// Consented scopes (the stored value as is, including `openid`).
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Content of the security screen.
pub struct SecurityOverview {
    pub sessions: Vec<SessionSummary>,
    pub connected_apps: Vec<ConnectedAppSummary>,
}

pub enum SecurityOverviewOutcome {
    Ok(Box<SecurityOverview>),
    /// No SSO session, expired, or the user is disabled.
    SessionExpired,
    Internal(String),
}

pub enum RevokeSessionOutcome {
    /// Revoked (idempotent: includes when it was already gone).
    Ok,
    /// The given ID is not among the user's sessions (another person's session, or a resend from an old screen).
    NotFound,
    /// The session in use itself cannot be cut from this screen (the logout flow is used instead).
    CurrentSession,
    SessionExpired,
    Internal(String),
}

pub enum RevokeConsentOutcome {
    /// Revoked (idempotent: includes when there was no consent).
    Ok,
    SessionExpired,
    Internal(String),
}

pub enum ReissueTokensOutcome {
    /// Revoked. `revoked` is the number dropped, and **0 is also success** (there were no live tokens).
    /// The screen shows this differently as "nothing to revoke": returning only the same "done" would
    /// leave the user unable to tell whether it had no effect or there was nothing to begin with.
    Ok {
        revoked: u64,
    },
    SessionExpired,
    Internal(String),
}

pub struct AccountSecurityService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    consents: Arc<dyn ClientConsentRepository>,
    clients: Arc<dyn ClientRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountSecurityService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        consents: Arc<dyn ClientConsentRepository>,
        clients: Arc<dyn ClientRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            consents,
            clients,
            refresh_tokens,
            audit,
            clock,
        }
    }

    /// Returns the security screen content (valid session list + connected app list).
    pub async fn overview(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
    ) -> SecurityOverviewOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return SecurityOverviewOutcome::SessionExpired,
            Err(e) => return SecurityOverviewOutcome::Internal(e),
        };

        let sessions = match self.sso_sessions.list_for_user(user_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        // Drop expired rows from the screen without waiting for GC (do not make the user think they are "still alive").
        let sessions: Vec<SessionSummary> = sessions
            .into_iter()
            .filter(|s| s.is_valid_at(now))
            .map(|s| SessionSummary {
                id: s.display_id(),
                current: s.session_hash == current_hash,
                auth_time: s.auth_time,
                multi_factor: s.authentication_strength == AuthenticationStrength::MultiFactor,
                user_agent: s.user_agent.clone(),
                ip_address: s.ip_address.clone(),
                created_at: s.created_at,
                idle_expires_at: s.idle_expires_at,
                absolute_expires_at: s.absolute_expires_at,
            })
            .collect();

        let tenant_id = tenant.tenant_id();
        let consents = match self.consents.list_for_user(tenant_id, user_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        // Display names are looked up from the client list (one at a time would round-trip per consent, so do it once).
        let clients = match self.clients.list(tenant_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        let connected_apps: Vec<ConnectedAppSummary> = consents
            .into_iter()
            .map(|c| {
                let app_name = clients
                    .iter()
                    .find(|client| client.client_id == c.client_id)
                    .map(|client| client.app_name.clone())
                    .unwrap_or_else(|| c.client_id.clone());
                ConnectedAppSummary {
                    client_id: c.client_id,
                    app_name,
                    scopes: c.scopes,
                    granted_at: c.granted_at,
                    updated_at: c.updated_at,
                }
            })
            .collect();

        SecurityOverviewOutcome::Ok(Box::new(SecurityOverview {
            sessions,
            connected_apps,
        }))
    }

    /// Revokes the given session (limited to the user's own sessions).
    pub async fn revoke_session(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        target_display_id: &str,
        ctx: &RequestContext,
    ) -> RevokeSessionOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return RevokeSessionOutcome::SessionExpired,
            Err(e) => return RevokeSessionOutcome::Internal(e),
        };

        let sessions = match self.sso_sessions.list_for_user(user_id).await {
            Ok(rows) => rows,
            Err(e) => return RevokeSessionOutcome::Internal(e.to_string()),
        };
        // Match the display ID only within the user's own set of sessions. Other people's sessions are not
        // in this set at all, so even a guessed ID cannot cut them.
        let Some(target) = sessions
            .iter()
            .find(|s| s.display_id() == target_display_id)
        else {
            return RevokeSessionOutcome::NotFound;
        };
        if target.session_hash == current_hash {
            // Cutting the current session would leave only the cookie and make behavior hard to follow. Send to the logout flow.
            return RevokeSessionOutcome::CurrentSession;
        }

        if let Err(e) = self.sso_sessions.delete(&target.session_hash).await {
            return RevokeSessionOutcome::Internal(e.to_string());
        }

        // Also drop refresh tokens issued from that session (ADR-0044).
        //
        // Skipping this, the screen would say "signed this device out of the account" while
        // that device's apps **keep refreshing successfully** (access tokens expire in 15 minutes, but
        // refresh does not stop, so the window never closes). Deleting the session row alone is
        // not a logout.
        //
        // **Refuse on failure** (fail-closed). Silently returning success here would have the screen
        // affirm the worst outcome: "thought it was cut, but it is not".
        let sid = sso_session::sid_of(&target.session_hash);
        let revoked = match self
            .refresh_tokens
            .revoke_all_for_session(user_id, &sid, now)
            .await
        {
            Ok(count) => count,
            Err(e) => return RevokeSessionOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::SsoSessionTerminated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(&format!("self_service_revoke refresh_tokens={revoked}")),
                ctx,
            )
            .await;
        RevokeSessionOutcome::Ok
    }

    /// Revokes a connected app's consent and also revokes refresh tokens for that client.
    pub async fn revoke_consent(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        client_id: &str,
        ctx: &RequestContext,
    ) -> RevokeConsentOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return RevokeConsentOutcome::SessionExpired,
            Err(e) => return RevokeConsentOutcome::Internal(e),
        };
        let tenant_id = tenant.tenant_id();

        if let Err(e) = self.consents.revoke(tenant_id, user_id, client_id).await {
            return RevokeConsentOutcome::Internal(e.to_string());
        }
        // Deleting only the consent row leaves issued tokens alive. To make "removal" real from the user's view,
        // revoke refresh tokens issued **to the removed client**. Deleting per tenant would lock the user out of
        // the tenant's other apps just for removing one.
        if let Err(e) = self
            .refresh_tokens
            .revoke_all_for_user_and_client(tenant_id, user_id, client_id, now)
            .await
        {
            // Revoking the consent itself succeeded. Tokens remaining is made traceable in the operational log.
            tracing::error!(
                error = %e,
                "failed to revoke refresh tokens after a self-service consent revocation"
            );
        }

        self.audit
            .record(
                AuditEventType::ConsentRevoked,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                Some(client_id),
                Some("self_service"),
                ctx,
            )
            .await;
        RevokeConsentOutcome::Ok
    }

    /// Revokes every refresh token issued to the user (shown on screen as "reissue tokens"; ADR-0047).
    ///
    /// In substance it is a single [`RefreshTokenRepository::revoke_all_for_user`] call and **touches neither sessions
    /// nor consents**. It only swaps the duplicate keys apps hold, so the browser's login state
    /// remains, and each app re-obtains through SSO on its next refresh (to the user, most apps
    /// show no change). Cutting a device already has session revocation, and removing an app already has
    /// disconnecting. This operation is neither: it is for **invalidating keys that may have been handed out
    /// unnoticed, without knowing of anything specific**.
    ///
    /// **Not narrowed by tenant.** A refresh token is the user's credential, and like `sso_sessions`,
    /// one person may authorize apps in several tenants (same reason as decision 3 of ADR-0044). Narrowing to
    /// the screen's "connected apps", which shows only the current tenant, would leave **only the keys of unseen
    /// tenants alive**. A missed key betrays "I thought I swapped them", while an extra dropped key
    /// is merely re-obtained silently.
    ///
    /// **Unconsumed authorization codes are not touched.** Codes expire in tens of seconds and doing so would
    /// take down a login in progress in another tab. Even if dropped, a holder of a live session could get a
    /// new code right after pressing, so it would not protect what this operation wants to protect (that is session revocation's job).
    ///
    /// **Refuse on failure** (fail-closed). The screen remains and can be pressed again. Returning success here would
    /// have the screen affirm the worst outcome, "thought they were swapped but old keys are alive"
    /// (same standard as the self-service revocation of ADR-0044).
    pub async fn reissue_tokens(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        ctx: &RequestContext,
    ) -> ReissueTokensOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return ReissueTokensOutcome::SessionExpired,
            Err(e) => return ReissueTokensOutcome::Internal(e),
        };

        let revoked = match self.refresh_tokens.revoke_all_for_user(user_id, now).await {
            Ok(count) => count,
            Err(e) => return ReissueTokensOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::RefreshTokenRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(&format!("self_service_reissue refresh_tokens={revoked}")),
                ctx,
            )
            .await;
        ReissueTokensOutcome::Ok { revoked }
    }

    /// Resolves the user from the SSO session. An invalid session, a missing user, or a disabled one is `Ok(None)`
    /// (same decision as other self-service paths; follows `AccountProfileService::resolve_active_user`).
    async fn resolve_active_user_id(
        &self,
        session_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Uuid>, String> {
        let user_id = match self.sso_sessions.find_by_hash(session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s.user_id,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(user_id)),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Helper that only handles typing of the tenant boundary (to pass `TenantId` from Presentation).
impl AccountSecurityService {
    pub fn tenant_context(tenant_id: TenantId) -> TenantContext {
        TenantContext::new(tenant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::user::User;
    use crate::domain::values::{AuthenticationMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::{Duration, TimeZone};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    fn tenant_id() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn user_id() -> Uuid {
        Uuid::from_u128(42)
    }

    fn session(raw_cookie: &str, methods: Vec<AuthenticationMethod>, valid: bool) -> SsoSession {
        let mut s = SsoSession::establish(
            crypto::sha256_hex(raw_cookie),
            user_id(),
            now(),
            Duration::hours(1),
            Duration::hours(8),
            methods,
            Some("Mozilla/5.0".to_string()),
            Some("203.0.113.10".to_string()),
        );
        if !valid {
            s.idle_expires_at = now() - Duration::minutes(1);
        }
        s
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        rows: Mutex<Vec<SsoSession>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, hash: &str) -> DomainResult<Option<SsoSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.session_hash == hash)
                .cloned())
        }
        async fn list_for_user(&self, uid: Uuid) -> DomainResult<Vec<SsoSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.user_id == uid)
                .cloned()
                .collect())
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, hash: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.session_hash != hash);
            Ok(())
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeUsers {
        active: bool,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// This test does not go through the login failure path (SEC13 is verified in login / mfa_login).
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
                tenant_id: tenant_id(),
                sub: Uuid::from_u128(7),
                email: "user@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("user".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: String::new(),
                must_change_password: false,
                password_changed_at: None,
                status: if self.active {
                    UserStatus::Active
                } else {
                    UserStatus::Disabled
                },
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

    #[derive(Default)]
    struct FakeConsents {
        rows: Mutex<Vec<ClientConsent>>,
    }
    #[async_trait]
    impl ClientConsentRepository for FakeConsents {
        async fn find(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
        ) -> DomainResult<Option<ClientConsent>> {
            unreachable!()
        }
        async fn upsert(&self, _c: &ClientConsent) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, client_id: &str) -> DomainResult<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|c| c.client_id != client_id);
            Ok(())
        }
        async fn list_for_user(&self, _t: TenantId, _u: Uuid) -> DomainResult<Vec<ClientConsent>> {
            Ok(self.rows.lock().unwrap().clone())
        }
    }

    #[derive(Default)]
    struct FakeClients;
    #[async_trait]
    impl ClientRepository for FakeClients {
        async fn find_by_client_id(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<crate::domain::client::Client>> {
            unreachable!()
        }
        async fn create(&self, _c: &crate::domain::client::Client) -> DomainResult<()> {
            unreachable!()
        }
        async fn list(&self, _t: TenantId) -> DomainResult<Vec<crate::domain::client::Client>> {
            // Reproduce the case where the display name cannot be looked up (deleted client).
            Ok(Vec::new())
        }
        async fn update(&self, _c: &crate::domain::client::Client) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// Where to make the repository fail (for checking fail-closed).
    #[derive(Default, Clone, Copy)]
    struct Failures {
        session_revoke: bool,
        user_revoke: bool,
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        /// `(tenant, user, client)` requested for revocation. The client is recorded too, to see whether
        /// disconnecting is narrowed to the client.
        revoked: Mutex<Vec<(TenantId, Uuid, String)>>,
        /// `(user, sid)` requested for per-session revocation (ADR-0044).
        revoked_sessions: Mutex<Vec<(Uuid, String)>>,
        /// Users requested for per-user revocation (token reissue of ADR-0047).
        revoked_users: Mutex<Vec<Uuid>>,
        failures: Failures,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn revoke_family(
            &self,
            _t: TenantId,
            _family: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _t: TenantId, _h: &str) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _at: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, u: Uuid, _at: DateTime<Utc>) -> DomainResult<u64> {
            if self.failures.user_revoke {
                return Err(crate::domain::error::DomainError::Repository("boom".into()));
            }
            self.revoked_users.lock().unwrap().push(u);
            Ok(3)
        }
        async fn count_active_for_user(&self, _u: Uuid, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_all_for_session(
            &self,
            u: Uuid,
            sid: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            if self.failures.session_revoke {
                return Err(crate::domain::error::DomainError::Repository("boom".into()));
            }
            self.revoked_sessions
                .lock()
                .unwrap()
                .push((u, sid.to_string()));
            Ok(1)
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            // Disconnecting must not call the per-tenant full revocation (it would take down other apps).
            unreachable!("consent revocation must not revoke every client in the tenant")
        }
        async fn revoke_all_for_user_and_client(
            &self,
            t: TenantId,
            u: Uuid,
            c: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.revoked.lock().unwrap().push((t, u, c.to_string()));
            Ok(())
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

    struct Harness {
        service: AccountSecurityService,
        sessions: Arc<FakeSsoSessions>,
        consents: Arc<FakeConsents>,
        refresh_tokens: Arc<FakeRefreshTokens>,
    }

    fn harness(active_user: bool) -> Harness {
        harness_with(active_user, Failures::default())
    }

    fn harness_with(active_user: bool, failures: Failures) -> Harness {
        let sessions = Arc::new(FakeSsoSessions::default());
        let consents = Arc::new(FakeConsents::default());
        let refresh_tokens = Arc::new(FakeRefreshTokens {
            failures,
            ..Default::default()
        });
        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let service = AccountSecurityService::new(
            sessions.clone(),
            Arc::new(FakeUsers {
                active: active_user,
            }),
            consents.clone(),
            Arc::new(FakeClients),
            refresh_tokens.clone(),
            Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone())),
            clock,
        );
        Harness {
            service,
            sessions,
            consents,
            refresh_tokens,
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn overview_lists_valid_sessions_and_marks_the_current_one() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session(
                "other-cookie",
                vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
                true,
            ),
            session(
                "expired-cookie",
                vec![AuthenticationMethod::Password],
                false,
            ),
        ]);
        h.consents.rows.lock().unwrap().push(ClientConsent {
            user_id: user_id(),
            tenant_id: tenant_id(),
            client_id: "deleted-app".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            granted_at: now(),
            updated_at: now(),
        });

        let SecurityOverviewOutcome::Ok(overview) = h
            .service
            .overview(TenantContext::new(tenant_id()), "current-cookie")
            .await
        else {
            panic!("expected an overview");
        };

        // Expired ones are not shown.
        assert_eq!(overview.sessions.len(), 2);
        let current = overview.sessions.iter().find(|s| s.current).unwrap();
        assert!(!current.multi_factor);
        let other = overview.sessions.iter().find(|s| !s.current).unwrap();
        assert!(other.multi_factor, "an MFA-completed session shows as such");
        // The display ID is not the session_hash itself.
        assert_ne!(current.id, crypto::sha256_hex("current-cookie"));

        // If the client cannot be looked up, client_id is used as the display name.
        assert_eq!(overview.connected_apps.len(), 1);
        assert_eq!(overview.connected_apps[0].app_name, "deleted-app");
    }

    #[tokio::test]
    async fn revoking_another_session_deletes_only_that_row() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session("other-cookie", vec![AuthenticationMethod::Password], true),
        ]);
        let other_id =
            session("other-cookie", vec![AuthenticationMethod::Password], true).display_id();

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &other_id,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::Ok
        ));
        let rows = h.sessions.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_hash, crypto::sha256_hex("current-cookie"));
    }

    /// Cutting a session also drops refresh tokens issued from that session (ADR-0044).
    ///
    /// If this were missing, the screen would say "signed this device out" while that device's
    /// apps keep refreshing (access tokens expire in 15 minutes, but refresh
    /// does not stop, so the window never closes). Deleting the row alone is not a logout.
    #[tokio::test]
    async fn revoking_a_session_also_revokes_its_refresh_tokens() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session("other-cookie", vec![AuthenticationMethod::Password], true),
        ]);
        let other = session("other-cookie", vec![AuthenticationMethod::Password], true);

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &other.display_id(),
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::Ok
        ));

        // Revoked with **the sid of the cut session**. Calling with the display ID or the current session's
        // sid would drop something other than what was deleted.
        let revoked = h.refresh_tokens.revoked_sessions.lock().unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].1, other.sid());
        assert_ne!(
            revoked[0].1,
            session("current-cookie", vec![AuthenticationMethod::Password], true).sid(),
        );
    }

    /// If tokens could not be dropped, it does not count as cut (fail-closed).
    ///
    /// Returning success here would have the screen affirm "thought it was cut, but it is not".
    #[tokio::test]
    async fn a_failed_token_revocation_fails_the_whole_request() {
        let h = harness_with(
            true,
            Failures {
                session_revoke: true,
                ..Default::default()
            },
        );
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session("other-cookie", vec![AuthenticationMethod::Password], true),
        ]);
        let other_id =
            session("other-cookie", vec![AuthenticationMethod::Password], true).display_id();

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &other_id,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::Internal(_)
        ));
    }

    /// The session in use cannot be cut from this screen (sent to the logout flow).
    #[tokio::test]
    async fn revoking_the_current_session_is_refused() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        let current_id =
            session("current-cookie", vec![AuthenticationMethod::Password], true).display_id();

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &current_id,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::CurrentSession
        ));
        assert_eq!(h.sessions.rows.lock().unwrap().len(), 1);
    }

    /// Bringing another person's session display ID does not cut it (matched only against the user's own set).
    #[tokio::test]
    async fn a_session_id_that_is_not_ours_is_not_found() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        let foreign =
            crate::domain::sso_session::display_id_of(&crypto::sha256_hex("someone-else"));

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &foreign,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::NotFound
        ));
        assert_eq!(h.sessions.rows.lock().unwrap().len(), 1);
    }

    /// Revoking consent deletes the consent row and also revokes the tenant's refresh tokens.
    #[tokio::test]
    async fn revoking_a_consent_also_revokes_refresh_tokens_in_that_tenant() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        h.consents.rows.lock().unwrap().push(ClientConsent {
            user_id: user_id(),
            tenant_id: tenant_id(),
            client_id: "app-a".to_string(),
            scopes: vec!["openid".to_string()],
            granted_at: now(),
            updated_at: now(),
        });

        assert!(matches!(
            h.service
                .revoke_consent(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    "app-a",
                    &ctx()
                )
                .await,
            RevokeConsentOutcome::Ok
        ));
        assert!(h.consents.rows.lock().unwrap().is_empty());
        // Only the removed client's tokens are revoked (other apps in the same tenant remain).
        assert_eq!(
            *h.refresh_tokens.revoked.lock().unwrap(),
            vec![(tenant_id(), user_id(), "app-a".to_string())]
        );
    }

    /// Even if a disabled user's session remains, no operation is allowed (same as other self-service paths).
    #[tokio::test]
    async fn a_disabled_user_cannot_use_the_screen() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        assert!(matches!(
            h.service
                .overview(TenantContext::new(tenant_id()), "current-cookie")
                .await,
            SecurityOverviewOutcome::SessionExpired
        ));
    }

    /// Token reissue drops all of the user's tokens and **touches nothing else** (ADR-0047).
    ///
    /// If sessions disappeared too, a user who "just wants to swap app keys" would be locked out, and if consents
    /// disappeared, the consent screen would appear on the next login. Neither is something this operation promises.
    #[tokio::test]
    async fn reissuing_tokens_touches_only_the_tokens() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session("other-cookie", vec![AuthenticationMethod::Password], true),
        ]);
        h.consents.rows.lock().unwrap().push(ClientConsent {
            user_id: user_id(),
            tenant_id: tenant_id(),
            client_id: "app-a".to_string(),
            scopes: vec!["openid".to_string()],
            granted_at: now(),
            updated_at: now(),
        });

        assert!(matches!(
            h.service
                .reissue_tokens(TenantContext::new(tenant_id()), "current-cookie", &ctx())
                .await,
            // The number dropped is returned as is (so the screen can show "nothing to revoke").
            ReissueTokensOutcome::Ok { revoked: 3 }
        ));

        // Drop once per user. Per-client and per-session revocation are not used
        // (narrowing by tenant or session would leave unseen keys alive).
        assert_eq!(
            *h.refresh_tokens.revoked_users.lock().unwrap(),
            vec![user_id()]
        );
        assert!(h.refresh_tokens.revoked.lock().unwrap().is_empty());
        assert!(h.refresh_tokens.revoked_sessions.lock().unwrap().is_empty());
        // Devices and integrations remain.
        assert_eq!(h.sessions.rows.lock().unwrap().len(), 2);
        assert_eq!(h.consents.rows.lock().unwrap().len(), 1);
    }

    /// If they could not be dropped, do not claim success (fail-closed). The screen remains and can be pressed again.
    #[tokio::test]
    async fn a_failed_reissue_is_not_reported_as_success() {
        let h = harness_with(
            true,
            Failures {
                user_revoke: true,
                ..Default::default()
            },
        );
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));

        assert!(matches!(
            h.service
                .reissue_tokens(TenantContext::new(tenant_id()), "current-cookie", &ctx())
                .await,
            ReissueTokensOutcome::Internal(_)
        ));
    }

    /// A disabled user cannot reissue either (same decision as the screen and revocation).
    #[tokio::test]
    async fn a_disabled_user_cannot_reissue_tokens() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));

        assert!(matches!(
            h.service
                .reissue_tokens(TenantContext::new(tenant_id()), "current-cookie", &ctx())
                .await,
            ReissueTokensOutcome::SessionExpired
        ));
        assert!(h.refresh_tokens.revoked_users.lock().unwrap().is_empty());
    }
}
