//! Invitation and membership use case (ADR-0009 §3).
//!
//! The only way for a user to join a tenant other than their home tenant is an **invitation** (like Entra ID's B2B guests).
//! When a host tenant's admin creates an invitation, a one-time **invitation token** is returned in the response
//! (the same "return once, the admin notifies the person separately" pattern as `generated_password`. Only the token's
//! hash is stored, and it is never written to logs or the audit log). The invitee presents the token to the accept endpoint
//! with **a session logged in at their home tenant**, and the membership becomes `ACTIVE`. Identity is confirmed
//! by possession of the token and the logged-in session.
//!
//! All a host tenant's admin can do to a guest is "remove the membership" and "grant/revoke permissions scoped to
//! the host tenant"; they can't touch the guest's `users` record (password, state, MFA,
//! profile) (only the home tenant's admins and the person can. §3). Decisions and validation are completed in this
//! Application layer, and only the result is returned to Presentation (CLAUDE.md "Permission management"). The HTTP
//! endpoints (`/{tenant_id}/admin/invitations`, `/{tenant_id}/invitations/accept`,
//! `/{tenant_id}/admin/members/{user_id}`) are added to presentation in MT11.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::message::MessageKey;
use crate::domain::repositories::{
    RefreshTokenRepository, TenantMembershipRepository, UserPermissionRepository, UserRepository,
};
#[cfg(test)]
use crate::domain::system_setting::DeploymentState;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::{
    validate_email as domain_validate_email, MembershipStatus, MembershipType,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    #[error("not found")]
    NotFound,
    /// Already a member of the tenant (HOME/GUEST/INVITED).
    #[error("already a member")]
    AlreadyMember,
    /// The invitee reference is neither an email address nor an internal ID (UUID) (ADR-0061).
    #[error("validation error: {0}")]
    Validation(MessageKey),
    /// The accepter isn't the invited user, HOME can't be removed, etc.
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    /// The invitation token is invalid or expired.
    #[error("invalid or expired invitation")]
    InvalidOrExpired,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result of creating an invitation. `token` is the plaintext invitation token, returned **only this once** (only the hash is stored).
pub struct CreatedInvitation {
    /// Plaintext invitation token. If the mail doesn't arrive, the admin notifies the invitee separately (never in logs or audit).
    pub token: String,
    pub expires_at: DateTime<Utc>,
    /// Whether the invitation email (accept link) could be sent to the invitee (MT17). `false` if SMTP is unset or sending failed
    /// (the invitation itself is valid, and the admin conveys the token manually).
    pub email_sent: bool,
    /// The invitee's email address (for display; to confirm the destination). ⚠ **Set only when invited by email address**
    /// (= a copy of the value the caller entered). `None` when invited by internal ID (task #591) ——otherwise an ID alone
    /// could pull out the address of a user in another tenant.
    pub invitee_email: Option<String>,
}

/// Byte length of the invitation token (about 43 chars in base64url).
const INVITATION_TOKEN_BYTES: usize = 32;

pub struct InvitationService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    /// Used to revoke that tenant's refresh tokens when a guest is suspended (MT24).
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    /// Source of SMTP connection info (MT14 system settings; changes at runtime, so looked up for each send).
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Resolution of settings tenants can override (ADR-0058). Looked up every time.
    settings: Arc<dyn EffectiveTenantSettings>,
    /// Public base URL the accept link is built on (web screens; no trailing slash).
    console_base_url: String,
}

impl InvitationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
        console_base_url: String,
    ) -> Self {
        Self {
            users,
            memberships,
            permissions,
            refresh_tokens,
            system_settings,
            mailer,
            audit,
            clock,
            settings,
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Creates a guest invitation to the host tenant (`host`). The invited user must be an existing user (whose home is
    /// another tenant). If already a member (HOME/GUEST/INVITED), `AlreadyMember`.
    /// Returns the plaintext token **only once** (only the hash is stored).
    ///
    /// `invitee` is **an email address or an internal ID (UUID)** (ADR-0061). Telling them apart is enclosed in
    /// [`Self::resolve_invitee`]; the caller just passes a single input.
    pub async fn create_invitation(
        &self,
        host: TenantContext,
        invitee: &str,
        invited_by: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<CreatedInvitation, InvitationError> {
        let host_id = host.tenant_id();

        // The invited user must exist. A user whose home is host is already a HOME member and
        // falls to `AlreadyMember` in the membership existence check below.
        let (invitee, named_by_email) = self.resolve_invitee(invitee).await?;
        let target_user_id = invitee.id;

        // Don't invite twice if a membership (HOME/GUEST/INVITED) already exists.
        match self.memberships.find(host_id, target_user_id).await {
            Ok(Some(_)) => return Err(InvitationError::AlreadyMember),
            Ok(None) => {}
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        }

        let now = self.clock.now();
        let token = crypto::random_token(INVITATION_TOKEN_BYTES);
        // The lifetime is the inviting host tenant's value (the invitation is a membership row of the host tenant. ADR-0058).
        // The accepting side looks at the stored `expires_at`, so issuance and verification can't disagree.
        let invitation_ttl = self
            .settings
            .invitation_ttl(host_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;
        let expires_at = now + invitation_ttl;
        let membership = TenantMembership {
            tenant_id: host_id,
            user_id: target_user_id,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Invited,
            // `tenant_memberships.invited_by` is a user ID column, so when a machine invites there's nowhere
            // to record it (who invited is kept in the audit log's `reason` as `actor_client=`).
            invited_by: invited_by.user_id(),
            invitation_token_hash: Some(crypto::sha256_hex(&token)),
            invitation_expires_at: Some(expires_at),
            created_at: now,
            updated_at: now,
        };
        self.memberships
            .create(&membership)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        // Only the invitee's internal ID is recorded in the audit (the invitation token isn't output. §3).
        self.audit
            .record(
                AuditEventType::TenantInvitationCreated,
                AuditResult::Success,
                Some(host_id),
                invited_by.user_id(),
                invited_by.client_id(),
                Some(&format!("invitee={target_user_id}")),
                ctx,
            )
            .await;

        // Deliver the accept link by email (MT17). Even if SMTP is unset or sending fails, the invitation is valid;
        // best-effort (the result is returned in `email_sent`, and the admin can fall back to conveying it manually).
        let email_sent = self
            .deliver_invitation_email(&invitee.email, host_id, &token, expires_at)
            .await;

        Ok(CreatedInvitation {
            token,
            expires_at,
            email_sent,
            invitee_email: named_by_email.then_some(invitee.email),
        })
    }

    /// Decides who to invite (ADR-0061). The input is an email address or an internal ID (UUID).
    ///
    /// **UUID is read first.** Only strings that aren't valid email addresses come here, so the order doesn't really
    /// matter, but trying it first avoids misreading the intent of "pasted an ID".
    ///
    /// Lookup by email only succeeds when there is **exactly one person across tenants**; zero and several both give the same
    /// `NotFound` ([`UserRepository::find_active_user_by_email_across_tenants`]).
    /// ⚠ **Don't distinguish several as "ambiguous"** —— the host tenant's admin can't see the other tenant's roster,
    /// so distinguishing would reveal only that "other users with this address exist".
    /// The way out (referring by internal ID) is explained on screen.
    ///
    /// The returned bool is "whether referred to by email address" (whether the address may be put in the response. task #591).
    async fn resolve_invitee(&self, input: &str) -> Result<(User, bool), InvitationError> {
        let input = input.trim();
        if let Ok(id) = Uuid::parse_str(input) {
            return match self.users.find_by_id(id).await {
                Ok(Some(user)) => Ok((user, false)),
                Ok(None) => Err(InvitationError::NotFound),
                Err(e) => Err(InvitationError::Internal(e.to_string())),
            };
        }
        if domain_validate_email(input).is_err() {
            return Err(InvitationError::Validation(MessageKey::new(
                "api-invitation-invitee-invalid",
            )));
        }
        match self
            .users
            .find_active_user_by_email_across_tenants(input)
            .await
        {
            Ok(Some(user)) => Ok((user, true)),
            Ok(None) => Err(InvitationError::NotFound),
            Err(e) => Err(InvitationError::Internal(e.to_string())),
        }
    }

    /// Delivers the invitation email (accept link). `true` on success. SMTP unset quietly gives `false`;
    /// a send failure logs a warning (no destination, to avoid PII, and no internal info about the invitee).
    /// Until MT19 (API i18n), the wording is fixed text in both Japanese and English.
    async fn deliver_invitation_email(
        &self,
        to: &str,
        host_id: TenantId,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> bool {
        // The invitation arrives under the inviting tenant's name (ADR-0058 §8).
        let server = match self.system_settings.smtp_server_for(host_id).await {
            Ok(Some(server)) => server,
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load SMTP settings; invitation falls back to manual token delivery");
                return false;
            }
        };
        // The token is base64url (URL-safe), so it can be concatenated as-is.
        let accept_url = format!(
            "{}/{}/invitations/accept?token={}",
            self.console_base_url, host_id, token
        );
        let mail = OutgoingEmail {
            to: to.to_string(),
            subject: "ゲスト招待のお知らせ / You are invited as a guest".to_string(),
            body_text: format!(
                "テナントへのゲストとして招待されました。\n\
                 所属元テナントでログインした状態で、次のリンクを開いて招待を承諾してください。\n\
                 \n\
                 You have been invited to join a tenant as a guest.\n\
                 While signed in at your home tenant, open the link below to accept the invitation.\n\
                 \n\
                 {accept_url}\n\
                 \n\
                 有効期限 / Expires at: {}\n",
                expires_at.to_rfc3339()
            ),
        };
        match self.mailer.send(&server, &mail).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "invitation email delivery failed; falling back to manual token delivery");
                false
            }
        }
    }

    /// Accepts an invitation. The accepter is a user **logged in at the home tenant** (`session_user_id`) who
    /// presents the token. Identity is confirmed by possession of the token + the logged-in session (§3).
    /// A token that isn't an invitation of this tenant (`tenant`), is expired, or doesn't exist is uniformly `InvalidOrExpired`;
    /// if the accepter isn't the invitee, `Forbidden`.
    pub async fn accept_invitation(
        &self,
        tenant: TenantContext,
        session_user_id: Uuid,
        token: &str,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        if token.is_empty() {
            return Err(InvitationError::InvalidOrExpired);
        }
        let token_hash = crypto::sha256_hex(token);
        let membership = match self
            .memberships
            .find_by_invitation_token_hash(&token_hash)
            .await
        {
            Ok(Some(m)) => m,
            Ok(None) => return Err(InvitationError::InvalidOrExpired),
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        };

        // The token must be an invitation of this tenant (don't let it be used at another tenant's accept endpoint).
        if membership.tenant_id != tenant.tenant_id() {
            return Err(InvitationError::InvalidOrExpired);
        }
        // The accepter must be the invited user (confirmed by the logged-in session. §3).
        if membership.user_id != session_user_id {
            return Err(InvitationError::Forbidden(MessageKey::new(
                "api-invitation-not-invitee",
            )));
        }
        // Expired invitations can't be accepted (stays INVITED).
        let now = self.clock.now();
        match membership.invitation_expires_at {
            Some(exp) if exp > now => {}
            _ => return Err(InvitationError::InvalidOrExpired),
        }

        self.memberships
            .activate(tenant.tenant_id(), session_user_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantInvitationAccepted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(session_user_id),
                None,
                None,
                ctx,
            )
            .await;

        Ok(())
    }

    /// Suspends a guest membership (MT24). Only GUEST `ACTIVE` (otherwise `Forbidden`).
    ///
    /// The difference from removal ([`revoke_membership`](Self::revoke_membership)) is that **it can be undone**.
    /// It sets `SUSPENDED` while keeping the membership row and the permission rows scoped to the tenant, stopping only access.
    /// Resuming restores the original state including permissions, so it suits temporary measures like leave or a paused contract.
    ///
    /// It also **revokes the refresh tokens issued in this tenant**. Suspension takes effect via `/authorize`'s
    /// membership check (`is_active_member`), but existing refresh tokens don't go through it and
    /// can keep refreshing, so without revoking them suspension would take effect only up to the refresh token's
    /// lifetime later (default 30 days).
    ///
    /// SSO sessions are **not revoked**. SSO sessions are shared per host (ADR-0009 §8), and deleting them
    /// would also take down the user's login at their home tenant. Suspension is a measure against one tenant and
    /// must not prevent use in other tenants. Access to this tenant stops at the next `/authorize`.
    pub async fn suspend_membership(
        &self,
        host: TenantContext,
        target_user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        let host_id = host.tenant_id();
        let membership = self.require_membership(host_id, target_user_id).await?;
        if !membership.can_be_suspended() {
            return Err(InvitationError::Forbidden(MessageKey::new(
                "api-membership-suspend-forbidden",
            )));
        }

        self.memberships
            .update_status(host_id, target_user_id, MembershipStatus::Suspended)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        // Revoke this tenant's refresh tokens (other tenants' are kept). If revocation fails,
        // suspension wouldn't take effect, so success is not returned (fail-closed). The membership is already
        // SUSPENDED, but re-running isn't idempotent (already suspended is Forbidden), so operations recover by removing it or
        // resuming -> suspending again.
        self.refresh_tokens
            .revoke_all_for_user_in_tenant(host_id, target_user_id, self.clock.now())
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantMembershipSuspended,
                AuditResult::Success,
                Some(host_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("member={target_user_id}")),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Resumes a suspended guest membership (MT24). Only a `SUSPENDED` GUEST.
    /// Permission rows remain during suspension, so returning to `ACTIVE` restores the pre-suspension state.
    pub async fn resume_membership(
        &self,
        host: TenantContext,
        target_user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        let host_id = host.tenant_id();
        let membership = self.require_membership(host_id, target_user_id).await?;
        if !membership.can_be_resumed() {
            return Err(InvitationError::Forbidden(MessageKey::new(
                "api-membership-resume-forbidden",
            )));
        }

        self.memberships
            .update_status(host_id, target_user_id, MembershipStatus::Active)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantMembershipResumed,
                AuditResult::Success,
                Some(host_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("member={target_user_id}")),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Fetches the tenant's membership row. Missing is `NotFound` (prevents cross-tenant existence guessing).
    async fn require_membership(
        &self,
        host_id: TenantId,
        target_user_id: Uuid,
    ) -> Result<TenantMembership, InvitationError> {
        match self.memberships.find(host_id, target_user_id).await {
            Ok(Some(m)) => Ok(m),
            Ok(None) => Err(InvitationError::NotFound),
            Err(e) => Err(InvitationError::Internal(e.to_string())),
        }
    }

    /// Removes a guest membership (expelling the guest. §3). HOME can't be removed (`Forbidden`).
    /// On removal, that user's permission rows scoped to the tenant are also deleted (§3).
    ///
    /// The order is fail-closed: **revoke permissions -> delete membership**. The admin access check (`RequirePerms`)
    /// looks only at permission rows, so if revoking permissions fails, the whole operation fails (the membership stays).
    /// In the reverse order, if cleaning up permissions failed, an expelled guest would keep admin permissions.
    pub async fn revoke_membership(
        &self,
        host: TenantContext,
        target_user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        let host_id = host.tenant_id();
        let membership = self.require_membership(host_id, target_user_id).await?;
        if membership.is_home() {
            return Err(InvitationError::Forbidden(MessageKey::new(
                "api-member-home-cannot-remove",
            )));
        }

        // Bulk-delete the permission rows scoped to the tenant (§3). On failure, stop here and
        // don't delete the membership (fail-closed; cache invalidation is on the repository side).
        self.permissions
            .revoke_all_for_user_in_tenant(host_id, target_user_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.memberships
            .delete(host_id, target_user_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantMembershipRevoked,
                AuditResult::Success,
                Some(host_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("member={target_user_id}")),
                ctx,
            )
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::mailer::SmtpServerConfig;
    use crate::domain::repositories::{AuditLogSink, SystemSettingsRepository};
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::tenant::TenantId;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::sync::Mutex;

    /// Encryption key for secret values in tests (used to verify decryption of the SMTP password).
    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct FakeUsers {
        /// It can hold several so we can create the situation of **users with the same email address in two
        /// tenants** (ADR-0061).
        users: Vec<User>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// These tests don't go through the login failure path (SEC13 verification is in login / mfa_login).
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
            Ok(self.users.iter().find(|u| u.id == id).cloned())
        }
        /// Answers by the same rule as the real one (sqlx implementation) —— returns only when exactly one ACTIVE user matches,
        /// `None` for zero or several (ADR-0061).
        async fn find_active_user_by_email_across_tenants(
            &self,
            email: &str,
        ) -> DomainResult<Option<User>> {
            let mut matched = self
                .users
                .iter()
                .filter(|u| u.email == email && u.status == UserStatus::Active);
            let first = matched.next();
            match (first, matched.next()) {
                (Some(user), None) => Ok(Some(user.clone())),
                _ => Ok(None),
            }
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _u: &str) -> DomainResult<Option<User>> {
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
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// A fake recording per-tenant refresh token revocation (MT24).
    #[derive(Default)]
    struct FakeRefreshTokens {
        revoked: Mutex<Vec<(TenantId, Uuid)>>,
        fail: Mutex<bool>,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn revoke_all_for_session(
            &self,
            _u: Uuid,
            _sid: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_family(
            &self,
            _t: TenantId,
            _family: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn create(
            &self,
            _t: &crate::domain::refresh_token::RefreshToken,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(
            &self,
            _tenant: TenantId,
            _h: &str,
        ) -> DomainResult<Option<crate::domain::refresh_token::RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, _u: Uuid, _now: DateTime<Utc>) -> DomainResult<u64> {
            // Guest suspension revokes per tenant (doesn't take down the whole user).
            unreachable!()
        }
        async fn count_active_for_user(&self, _u: Uuid, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            if *self.fail.lock().unwrap() {
                return Err(DomainError::Repository("connection lost".into()));
            }
            self.revoked.lock().unwrap().push((tenant_id, user_id));
            Ok(())
        }
        async fn revoke_all_for_user_and_client(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeMemberships {
        rows: Mutex<Vec<TenantMembership>>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn update_status(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            status: MembershipStatus,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let row = rows
                .iter_mut()
                .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
                .ok_or_else(|| DomainError::Repository("membership not found".into()))?;
            row.status = status;
            Ok(())
        }
        async fn create(&self, membership: &TenantMembership) -> DomainResult<()> {
            self.rows.lock().unwrap().push(membership.clone());
            Ok(())
        }
        async fn find(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Option<TenantMembership>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
                .cloned())
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
        async fn find_by_invitation_token_hash(
            &self,
            token_hash: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|m| {
                    m.status == MembershipStatus::Invited
                        && m.invitation_token_hash.as_deref() == Some(token_hash)
                })
                .cloned())
        }
        async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(m) = rows
                .iter_mut()
                .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
            {
                m.status = MembershipStatus::Active;
                m.invitation_token_hash = None;
                m.invitation_expires_at = None;
            }
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|m| !(m.tenant_id == tenant_id && m.user_id == user_id));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakePermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        /// Makes bulk revocation fail (for verifying that a cleanup failure aborts the whole operation).
        fail_revoke_all: bool,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_scoped_codes_for_user(
            &self,
            user_id: Uuid,
        ) -> DomainResult<Vec<(TenantId, String)>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, u, _)| *u == user_id)
                .map(|(t, _, c)| (*t, c.clone()))
                .collect())
        }
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec![])
        }
        async fn list_codes_for_user(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, u, _)| *t == tenant_id && *u == user_id)
                .map(|(_, _, c)| c.clone())
                .collect())
        }
        async fn has_permission(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn grant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> DomainResult<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(t, u, c)| !(*t == tenant_id && *u == user_id && c == code));
            Ok(())
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            if self.fail_revoke_all {
                return Err(crate::domain::error::DomainError::Repository(
                    "simulated failure".to_string(),
                ));
            }
            let mut granted = self.granted.lock().unwrap();
            let revoked: Vec<String> = granted
                .iter()
                .filter(|(t, u, _)| *t == tenant_id && *u == user_id)
                .map(|(_, _, c)| c.clone())
                .collect();
            granted.retain(|(t, u, _)| !(*t == tenant_id && *u == user_id));
            Ok(revoked)
        }
    }

    fn test_user(id: Uuid, home: TenantId) -> User {
        User {
            id,
            tenant_id: home,
            sub: Uuid::new_v4(),
            email: "guest@other.example.com".to_string(),
            email_verified: true,
            preferred_username: Some("guest".to_string()),
            name: None,
            language: None,
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// In-memory fake of system settings (toggles whether SMTP settings exist).
    #[derive(Default)]
    struct FakeSettingsRepo {
        rows: Mutex<Vec<SystemSetting>>,
    }
    #[async_trait]
    impl SystemSettingsRepository for FakeSettingsRepo {
        async fn load_all(&self) -> DomainResult<Vec<SystemSetting>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|s| s.key == setting.key) {
                Some(row) => *row = setting.clone(),
                None => rows.push(setting.clone()),
            }
            Ok(())
        }
    }

    /// A fake mailer recording what was sent (connection info + mail).
    #[derive(Default)]
    struct FakeMailer {
        sent: Mutex<Vec<(SmtpServerConfig, OutgoingEmail)>>,
        fail: bool,
    }
    #[async_trait]
    impl Mailer for FakeMailer {
        async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> DomainResult<()> {
            if self.fail {
                return Err(crate::domain::error::DomainError::Repository(
                    "simulated smtp failure".to_string(),
                ));
            }
            self.sent
                .lock()
                .unwrap()
                .push((server.clone(), mail.clone()));
            Ok(())
        }
    }

    /// Fake settings with SMTP configured (the password is stored encrypted with TEST_KEY).
    fn smtp_configured_settings() -> Arc<FakeSettingsRepo> {
        let repo = Arc::new(FakeSettingsRepo::default());
        let mut rows = vec![
            ("smtp.host", "smtp.example.com".to_string(), false),
            ("smtp.port", "587".to_string(), false),
            ("smtp.username", "mailer".to_string(), false),
            (
                "smtp.from_address",
                "noreply@example.com".to_string(),
                false,
            ),
            ("smtp.use_tls", "true".to_string(), false),
        ];
        rows.push((
            "smtp.password",
            crypto::encrypt(b"mail-secret", &TEST_KEY).unwrap(),
            true,
        ));
        *repo.rows.lock().unwrap() = rows
            .into_iter()
            .map(|(k, v, secret)| SystemSetting {
                key: k.to_string(),
                value: v,
                is_secret: secret,
            })
            .collect();
        repo
    }

    fn service_with_mail(
        user: Option<User>,
        memberships: Arc<FakeMemberships>,
        permissions: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
        settings: Arc<FakeSettingsRepo>,
        mailer: Arc<FakeMailer>,
        refresh_tokens: Arc<FakeRefreshTokens>,
    ) -> InvitationService {
        service_with_users(
            user.into_iter().collect(),
            memberships,
            permissions,
            sink,
            settings,
            mailer,
            refresh_tokens,
        )
    }

    /// Version holding several users (used by tests that create email address ambiguity).
    #[allow(clippy::too_many_arguments)]
    fn service_with_users(
        users: Vec<User>,
        memberships: Arc<FakeMemberships>,
        permissions: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
        settings: Arc<FakeSettingsRepo>,
        mailer: Arc<FakeMailer>,
        refresh_tokens: Arc<FakeRefreshTokens>,
    ) -> InvitationService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(now()))));
        let system_settings = Arc::new(SystemSettingsService::new(
            settings,
            Arc::new(crate::application::system_settings::NoTenantSettings),
            TEST_KEY,
            DeploymentState::default(),
            audit.clone(),
            Arc::new(FixedClock(now())),
        ));
        InvitationService::new(
            Arc::new(FakeUsers { users }),
            memberships,
            permissions,
            refresh_tokens,
            system_settings,
            mailer,
            audit,
            Arc::new(FixedClock(now())),
            crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                "INVITATION_TTL_SECS",
                "3600",
            )]),
            "https://idp.example.com".to_string(),
        )
    }

    fn service(
        user: Option<User>,
        memberships: Arc<FakeMemberships>,
        permissions: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> InvitationService {
        service_with_mail(
            user,
            memberships,
            permissions,
            sink,
            Arc::new(FakeSettingsRepo::default()),
            Arc::new(FakeMailer::default()),
            Arc::new(FakeRefreshTokens::default()),
        )
    }

    #[tokio::test]
    async fn create_then_accept_activates_membership() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let admin = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            sink.clone(),
        );

        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(admin),
                &ctx(),
            )
            .await
            .expect("invitation created");
        assert!(!created.token.is_empty());
        // Only the hash is stored (no plaintext kept).
        let stored_hash = memberships.rows.lock().unwrap()[0]
            .invitation_token_hash
            .clone()
            .unwrap();
        assert_eq!(stored_hash, crypto::sha256_hex(&created.token));
        assert_ne!(stored_hash, created.token);

        // The invitee presents the token and accepts -> ACTIVE.
        svc.accept_invitation(TenantContext::new(host), guest, &created.token, &ctx())
            .await
            .expect("accepted");
        let row = memberships.rows.lock().unwrap()[0].clone();
        assert_eq!(row.status, MembershipStatus::Active);
        assert!(row.invitation_token_hash.is_none());

        let kinds: Vec<_> = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type)
            .collect();
        assert_eq!(
            kinds,
            vec![
                AuditEventType::TenantInvitationCreated,
                AuditEventType::TenantInvitationAccepted
            ]
        );
        // The invitation token hasn't leaked into the audit.
        assert!(sink.events.lock().unwrap().iter().all(|e| {
            e.reason
                .as_deref()
                .map(|r| !r.contains(&created.token))
                .unwrap_or(true)
        }));
    }

    #[tokio::test]
    async fn create_sends_invitation_email_when_smtp_configured() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let mailer = Arc::new(FakeMailer::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service_with_mail(
            Some(test_user(guest, home)),
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            sink.clone(),
            smtp_configured_settings(),
            mailer.clone(),
            Arc::new(FakeRefreshTokens::default()),
        );

        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");
        assert!(created.email_sent);
        // ⚠ Invited by internal ID, so the address isn't in the response (task #591). The mail was delivered.
        assert_eq!(created.invitee_email, None);

        let sent = mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let (server, mail) = &sent[0];
        // Connection info is resolved from system settings, and the password is passed decrypted.
        assert_eq!(server.host, "smtp.example.com");
        assert_eq!(server.port, Some(587));
        assert_eq!(server.password, "mail-secret");
        assert_eq!(server.from_address, "noreply@example.com");
        assert!(server.use_tls);
        // The destination is the invitee's email. The body contains the accept link (host tenant + token).
        assert_eq!(mail.to, "guest@other.example.com");
        let expected_url = format!(
            "https://idp.example.com/{}/invitations/accept?token={}",
            host, created.token
        );
        assert!(mail.body_text.contains(&expected_url));
        // The token isn't output to the audit log (only in the mail body).
        assert!(sink.events.lock().unwrap().iter().all(|e| {
            e.reason
                .as_deref()
                .map(|r| !r.contains(&created.token))
                .unwrap_or(true)
        }));
    }

    #[tokio::test]
    async fn create_falls_back_to_manual_delivery_when_smtp_unconfigured() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let mailer = Arc::new(FakeMailer::default());
        let svc = service_with_mail(
            Some(test_user(guest, home)),
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
            Arc::new(FakeSettingsRepo::default()), // SMTP not configured
            mailer.clone(),
            Arc::new(FakeRefreshTokens::default()),
        );

        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");
        // The invitation is valid and no mail is sent (the token is conveyed manually).
        assert!(!created.email_sent);
        assert!(!created.token.is_empty());
        assert!(mailer.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_succeeds_even_when_email_delivery_fails() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let svc = service_with_mail(
            Some(test_user(guest, home)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
            smtp_configured_settings(),
            Arc::new(FakeMailer {
                fail: true,
                ..Default::default()
            }),
            Arc::new(FakeRefreshTokens::default()),
        );

        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created despite mail failure");
        // best-effort: even if sending fails, the invitation (INVITED row) remains and email_sent = false is reported.
        assert!(!created.email_sent);
        assert_eq!(memberships.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_rejects_existing_member() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_home(host, guest, now()));
        let svc = service(
            Some(test_user(guest, home)),
            memberships,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::AlreadyMember)
        ));
    }

    /// **The invitee can be referred to by email address** (ADR-0061).
    ///
    /// A host tenant's admin can't see the other tenant's roster, so the purpose of this path is
    /// inviting without knowing the internal ID.
    #[tokio::test]
    async fn create_accepts_an_email_address_as_the_invitee() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );

        let created = svc
            .create_invitation(
                TenantContext::new(host),
                "guest@other.example.com",
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("invitation is created");

        assert_eq!(
            created.invitee_email.as_deref(),
            Some("guest@other.example.com")
        );
        // The invited person is the same as when referred to by ID (checked by where the membership points).
        assert!(memberships.find(host, guest).await.unwrap().is_some());
    }

    /// When users with the same email address are in two tenants, **no one is invited**.
    ///
    /// `users.email` is only unique within a tenant, so which one to invite can't be decided.
    /// ⚠ **Don't distinguish it as "ambiguous"** —— distinguishing would reveal to the host tenant's admin only that
    /// "a user with this address exists in other tenants too". It is the same `NotFound` as not found.
    #[tokio::test]
    async fn create_refuses_an_email_shared_by_two_tenants() {
        let host: TenantId = Uuid::now_v7().into();
        let one: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let svc = service_with_users(
            vec![
                test_user(Uuid::new_v4(), one),
                test_user(Uuid::new_v4(), other),
            ],
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
            Arc::new(FakeSettingsRepo::default()),
            Arc::new(FakeMailer::default()),
            Arc::new(FakeRefreshTokens::default()),
        );

        assert!(matches!(
            svc.create_invitation(
                TenantContext::new(host),
                "guest@other.example.com",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::NotFound)
        ));
    }

    /// Input that is neither an email address nor an internal ID is refused before talking about existence.
    #[tokio::test]
    async fn create_rejects_an_invitee_that_is_neither_an_email_nor_an_id() {
        let host: TenantId = Uuid::now_v7().into();
        let svc = service(
            None,
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_invitation(
                TenantContext::new(host),
                "guest",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn create_rejects_unknown_user() {
        let host: TenantId = Uuid::now_v7().into();
        let svc = service(
            None,
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_invitation(
                TenantContext::new(host),
                &Uuid::new_v4().to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::NotFound)
        ));
    }

    #[tokio::test]
    async fn accept_requires_the_invited_user() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let svc = service(
            Some(test_user(guest, home)),
            memberships,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();

        // Can't accept with another user's session.
        assert!(matches!(
            svc.accept_invitation(
                TenantContext::new(host),
                Uuid::new_v4(),
                &created.token,
                &ctx()
            )
            .await,
            Err(InvitationError::Forbidden(_))
        ));
        // Also refused when the token is presented on another tenant's accept path.
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            svc.accept_invitation(TenantContext::new(other), guest, &created.token, &ctx())
                .await,
            Err(InvitationError::InvalidOrExpired)
        ));
    }

    #[tokio::test]
    async fn accept_rejects_expired_token() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        // Create an expiry with a TTL-0 service.
        let audit = Arc::new(AuditService::new(
            Arc::new(CapturingSink::default()),
            Arc::new(FixedClock(now())),
        ));
        let system_settings = Arc::new(SystemSettingsService::new(
            Arc::new(FakeSettingsRepo::default()),
            Arc::new(crate::application::system_settings::NoTenantSettings),
            TEST_KEY,
            DeploymentState::default(),
            audit.clone(),
            Arc::new(FixedClock(now())),
        ));
        let svc = InvitationService::new(
            Arc::new(FakeUsers {
                users: vec![test_user(guest, home)],
            }),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(FakeRefreshTokens::default()),
            system_settings,
            Arc::new(FakeMailer::default()),
            audit,
            Arc::new(FixedClock(now())),
            // The global value stays 1 hour; only the inviting host tenant sets 0 seconds (the expiry value is the host's).
            {
                let settings = crate::application::tenant_settings::testing::tenant_settings();
                settings.set_global("INVITATION_TTL_SECS", "3600");
                settings.set_tenant(host, "INVITATION_TTL_SECS", "0");
                settings.service
            },
            "https://idp.example.com".to_string(),
        );
        let created = svc
            .create_invitation(
                TenantContext::new(host),
                &guest.to_string(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        // expires_at == now (not `> now`) -> treated as expired.
        assert!(matches!(
            svc.accept_invitation(TenantContext::new(host), guest, &created.token, &ctx())
                .await,
            Err(InvitationError::InvalidOrExpired)
        ));
    }

    #[tokio::test]
    async fn revoke_removes_guest_and_scoped_permissions() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships.rows.lock().unwrap().push(TenantMembership {
            tenant_id: host,
            user_id: guest,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Active,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now(),
            updated_at: now(),
        });
        let permissions = Arc::new(FakePermissions::default());
        permissions
            .granted
            .lock()
            .unwrap()
            .push((host, guest, "idp.tenant.admin".to_string()));
        // Permissions scoped to another tenant are kept.
        let other: TenantId = Uuid::now_v7().into();
        permissions
            .granted
            .lock()
            .unwrap()
            .push((other, guest, "idp.tenant.admin".to_string()));
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            permissions.clone(),
            Arc::new(CapturingSink::default()),
        );

        svc.revoke_membership(
            TenantContext::new(host),
            guest,
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("revoked");
        assert!(memberships.rows.lock().unwrap().is_empty());
        // host-scoped permissions are gone, other-scoped ones remain.
        let remaining = permissions.granted.lock().unwrap().clone();
        assert_eq!(
            remaining,
            vec![(other, guest, "idp.tenant.admin".to_string())]
        );
    }

    #[tokio::test]
    async fn revoke_aborts_when_permission_cleanup_fails() {
        // If cleaning up permissions fails, the whole operation fails and the membership stays (fail-closed).
        // Otherwise an expelled guest would keep admin access through permission rows.
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships.rows.lock().unwrap().push(TenantMembership {
            tenant_id: host,
            user_id: guest,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Active,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now(),
            updated_at: now(),
        });
        let permissions = Arc::new(FakePermissions {
            fail_revoke_all: true,
            ..Default::default()
        });
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            permissions,
            Arc::new(CapturingSink::default()),
        );

        assert!(matches!(
            svc.revoke_membership(
                TenantContext::new(host),
                guest,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Internal(_))
        ));
        // The membership isn't deleted (as long as permissions remain, they stay a member too).
        assert_eq!(memberships.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoke_forbids_home_membership() {
        let host: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_home(host, user, now()));
        let svc = service(
            Some(test_user(user, host)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.revoke_membership(
                TenantContext::new(host),
                user,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Forbidden(_))
        ));
        // HOME remains.
        assert_eq!(memberships.rows.lock().unwrap().len(), 1);
    }

    /// MT24: suspension sets `SUSPENDED` while keeping the membership and permissions, and revokes that tenant's
    /// refresh tokens. Resuming restores the pre-suspension state (including permissions).
    #[tokio::test]
    async fn suspends_and_resumes_guest_keeping_membership_and_permissions() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_active_guest(host, guest, now()));
        let permissions = Arc::new(FakePermissions::default());
        permissions
            .granted
            .lock()
            .unwrap()
            .push((host, guest, "idp.tenant.admin".to_string()));
        let refresh_tokens = Arc::new(FakeRefreshTokens::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service_with_mail(
            Some(test_user(guest, home)),
            memberships.clone(),
            permissions.clone(),
            sink.clone(),
            Arc::new(FakeSettingsRepo::default()),
            Arc::new(FakeMailer::default()),
            refresh_tokens.clone(),
        );

        svc.suspend_membership(
            TenantContext::new(host),
            guest,
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("suspend");

        let row = memberships.rows.lock().unwrap()[0].clone();
        assert!(row.is_suspended());
        assert!(!row.is_active(), "suspended guests must not pass is_active");
        // Unlike removal (deletion), both the membership and permissions remain.
        assert_eq!(memberships.rows.lock().unwrap().len(), 1);
        assert_eq!(permissions.granted.lock().unwrap().len(), 1);
        // Only this tenant's refresh tokens are revoked.
        assert_eq!(*refresh_tokens.revoked.lock().unwrap(), vec![(host, guest)]);
        assert_eq!(
            sink.events.lock().unwrap()[0].event_type,
            AuditEventType::TenantMembershipSuspended
        );

        // Resuming returns to ACTIVE, with permissions intact.
        svc.resume_membership(
            TenantContext::new(host),
            guest,
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("resume");
        assert!(memberships.rows.lock().unwrap()[0].is_active());
        assert_eq!(permissions.granted.lock().unwrap().len(), 1);
        assert_eq!(
            sink.events.lock().unwrap()[1].event_type,
            AuditEventType::TenantMembershipResumed
        );
    }

    /// HOME, invited, double suspension and resuming a non-suspended one are all refused (the domain owns whether a transition is allowed).
    #[tokio::test]
    async fn suspend_and_resume_reject_invalid_transitions() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_home(host, user, now()));
        let svc = service(
            Some(test_user(user, host)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );

        // HOME can't be suspended (stopping the home tenant would leave nowhere to log in).
        assert!(matches!(
            svc.suspend_membership(
                TenantContext::new(host),
                user,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Forbidden(_))
        ));
        // Trying to resume an ACTIVE one is refused too.
        assert!(matches!(
            svc.resume_membership(
                TenantContext::new(host),
                user,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Forbidden(_))
        ));
        // Without a membership, NotFound (prevents cross-tenant existence guessing).
        assert!(matches!(
            svc.suspend_membership(
                TenantContext::new(Uuid::now_v7().into()),
                user,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::NotFound)
        ));
        // Invited (not yet accepted) has no access yet, so it isn't a suspension target.
        let invited = Uuid::new_v4();
        memberships.rows.lock().unwrap().push(TenantMembership {
            tenant_id: host,
            user_id: invited,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Invited,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now(),
            updated_at: now(),
        });
        assert!(matches!(
            svc.suspend_membership(
                TenantContext::new(host),
                invited,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Forbidden(_))
        ));
        let _ = home;
    }

    /// If revoking refresh tokens fails, suspension doesn't return success (prevents the mix-up of being suspended
    /// yet still able to access with tokens).
    #[tokio::test]
    async fn suspend_fails_when_tenant_refresh_tokens_cannot_be_revoked() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_active_guest(host, guest, now()));
        let refresh_tokens = Arc::new(FakeRefreshTokens::default());
        *refresh_tokens.fail.lock().unwrap() = true;
        let sink = Arc::new(CapturingSink::default());
        let svc = service_with_mail(
            Some(test_user(guest, home)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            sink.clone(),
            Arc::new(FakeSettingsRepo::default()),
            Arc::new(FakeMailer::default()),
            refresh_tokens,
        );

        assert!(matches!(
            svc.suspend_membership(
                TenantContext::new(host),
                guest,
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(InvitationError::Internal(_))
        ));
        // On failure, no success is left in the audit.
        assert!(sink.events.lock().unwrap().is_empty());
    }
}
