//! Verification of WebAuthn assertions (discoverable credentials).
//!
//! A passkey "login" has two layers: the **ceremony** (issue a challenge, verify the assertion the
//! browser returns, and settle "which user this is"), followed by **per-login-path handling**
//! (continuing the OIDC authorization flow, checking admin console permissions, issuing portal SSO).
//!
//! This module owns only the former. There are three screens that accept passkeys:
//! [`crate::application::passkey_authentication`] (OIDC authorization flow),
//! [`crate::application::admin_login`] (admin console), and
//! [`crate::application::portal_login`] (portal), and **the ceremony is identical for all of them**.
//! Copying it into three places would let dangerous-to-miss steps such as the authenticator registry
//! suspension check (AP9) and the signature counter update drift per path, so this is the single source.
//!
//! Challenges are separated by purpose via [`PasskeyFlow`]. OIDC-path challenges are bound to
//! `auth_session_id` ([`PasskeyFlow::Oidc`]); direct-login (admin console, portal) challenges carry no
//! binding ([`PasskeyFlow::Direct`]). Re-authentication right before a sensitive operation (AP5) is
//! neither, and is separated by the type itself ([`PasskeyFlow::StepUp`]) — it creates no session, so
//! `auth_session_id_hash` cannot express the purpose. A challenge that does not match the flow expected
//! at completion is rejected with [`PasskeyAssertionError::WrongFlow`], preventing cross-path reuse.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authenticator_management::is_blocked_in_registry;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::clock::Clock;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    PasskeyChallengeRepository, TenantMembershipRepository, UserAuthenticatorRepository,
    UserRepository, WebAuthnCredentialRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::webauthn_port::WebAuthnPort;
use chrono::Duration;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PublicKeyCredential,
};

/// Challenge lifetime (5 minutes).
const CHALLENGE_TTL: StdDuration = StdDuration::from_secs(300);

/// The path trying to use the passkey. Must match between challenge issuance and completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyFlow {
    /// Login inside the OIDC authorization flow. Bound to `auth_session_id`.
    Oidc,
    /// Direct login outside the authorization flow (admin console, portal). No `auth_session_id`.
    Direct,
    /// Re-authentication right before a sensitive operation (AP5). **Creates no session; elevates an existing one.**
    /// Separated from the two login flows by `challenge_type`.
    StepUp,
}

impl PasskeyFlow {
    /// Challenge type this path issues and consumes.
    fn challenge_type(self) -> PasskeyChallengeType {
        match self {
            Self::Oidc | Self::Direct => PasskeyChallengeType::Authenticate,
            Self::StepUp => PasskeyChallengeType::StepUp,
        }
    }
}

/// Assertion verification failure. Callers map it to their own path's outcome.
#[derive(Debug)]
pub enum PasskeyAssertionError {
    /// Challenge not found, expired, or already used.
    ChallengeNotFound,
    /// The challenge's purpose differs from the expected path.
    WrongFlow,
    /// Invalid credential (missing, verification failed, suspended, not a tenant member, account disabled).
    /// Reasons are not distinguished, to avoid enumeration.
    InvalidCredential,
    Internal(String),
}

/// Owner of a passkey that passed verification.
#[derive(Debug)]
pub struct VerifiedPasskeyUser {
    pub user_id: Uuid,
    /// The user's home tenant. The SSO session lifetime is determined by this tenant's values (ADR-0058),
    /// so callers need not look the user up again.
    pub home_tenant_id: TenantId,
    /// `auth_sessions.id_hash` carried by an OIDC-path challenge (always `None` for `Direct`).
    pub auth_session_id_hash: Option<String>,
}

pub struct PasskeyAssertionService {
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    /// Authenticator registry (AP9). Suspension and revocation live only here, so it is always checked at authentication.
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    webauthn: Arc<dyn WebAuthnPort>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PasskeyAssertionService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        webauthn: Arc<dyn WebAuthnPort>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            webauthn_credentials,
            authenticators,
            passkey_challenges,
            users,
            memberships,
            webauthn,
            audit,
            clock,
        }
    }

    /// Start authentication. Passing `auth_session_id` yields a challenge for continuing the OIDC flow;
    /// omitting it yields a challenge for direct login.
    ///
    /// Returns: `(challenge_id, options_json)`
    pub async fn begin(
        &self,
        auth_session_id: Option<&str>,
    ) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_for(PasskeyFlow::Direct, auth_session_id).await
    }

    /// Start re-authentication (AP5). Separated from login challenges by type, so **a challenge issued on
    /// this path cannot be used to log in** (and vice versa).
    ///
    /// Returns: `(challenge_id, options_json)`
    pub async fn begin_step_up(&self) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_for(PasskeyFlow::StepUp, None).await
    }

    /// Create one challenge for the given purpose. `Oidc` vs `Direct` is expressed by the presence of
    /// `auth_session_id`, so the login paths get the same result whichever they pass.
    async fn begin_for(
        &self,
        flow: PasskeyFlow,
        auth_session_id: Option<&str>,
    ) -> Result<(Uuid, serde_json::Value), String> {
        let now = self.clock.now();

        let (crc, state) = self
            .webauthn
            .begin_authentication()
            .map_err(|e| format!("begin_authentication failed: {e}"))?;

        let state_json =
            serde_json::to_string(&state).map_err(|e| format!("serialize state: {e}"))?;

        let challenge_id = Uuid::new_v4();
        let challenge = PasskeyChallenge {
            id: challenge_id,
            user_id: None,
            challenge_type: flow.challenge_type(),
            state_json,
            auth_session_id_hash: auth_session_id
                .map(|id| AuthSessionIdHash::of_plain(id).into_string()),
            expires_at: now + Duration::from_std(CHALLENGE_TTL).unwrap(),
            created_at: now,
        };
        self.passkey_challenges
            .create(&challenge)
            .await
            .map_err(|e| e.to_string())?;

        let options_json =
            serde_json::to_value(&crc).map_err(|e| format!("serialize options: {e}"))?;

        Ok((challenge_id, options_json))
    }

    /// Verify an assertion and settle its owner. The challenge is used up in one go (success or not).
    pub async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential_value: serde_json::Value,
        flow: PasskeyFlow,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError> {
        let now = self.clock.now();

        // 1. Fetch and consume the challenge.
        let challenge = match self.passkey_challenges.find_by_id(challenge_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err(PasskeyAssertionError::ChallengeNotFound),
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };
        if challenge.expires_at <= now {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return Err(PasskeyAssertionError::ChallengeNotFound);
        }
        // Delete the challenge first (replay protection). ⚠ **Only the side that deleted it proceeds** (task #586).
        // If two requests arrive concurrently with the same challenge, both pass the fetch above. The side that
        // failed to delete is reusing a challenge the other already used (synced passkeys keep the counter at 0,
        // so the counter cannot stop a resent signature).
        match self.passkey_challenges.delete(challenge_id).await {
            Ok(true) => {}
            Ok(false) => return Err(PasskeyAssertionError::ChallengeNotFound),
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        }

        // 1.5. Check that the purpose matches. Login and re-authentication are split by `challenge_type`; the two
        //      login paths (authorization flow, direct) are split by presence of `auth_session_id_hash`.
        let flow_matches = challenge.challenge_type == flow.challenge_type()
            && match flow {
                PasskeyFlow::Oidc => challenge.auth_session_id_hash.is_some(),
                PasskeyFlow::Direct | PasskeyFlow::StepUp => {
                    challenge.auth_session_id_hash.is_none()
                }
            };
        if !flow_matches {
            return Err(PasskeyAssertionError::WrongFlow);
        }

        // 2. Restore the DiscoverableAuthentication state.
        let auth_state: DiscoverableAuthentication =
            match serde_json::from_str(&challenge.state_json) {
                Ok(s) => s,
                Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
            };

        // 3. Deserialize the credential from the browser.
        let public_key_credential: PublicKeyCredential =
            match serde_json::from_value(credential_value) {
                Ok(c) => c,
                Err(_) => return Err(PasskeyAssertionError::InvalidCredential),
            };

        // 4. Look up the registered credential by credential_id.
        let stored_cred = match self
            .webauthn_credentials
            .find_by_credential_id(public_key_credential.id.as_str())
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return Err(PasskeyAssertionError::InvalidCredential),
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };

        let passkey: Passkey = match serde_json::from_str(&stored_cred.passkey_json) {
            Ok(p) => p,
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };

        let user_id = stored_cred.user_id;
        let cred_row_id = stored_cred.id;

        // Check that this particular credential is not stopped in the registry (AP9). The public-key lookup only
        // sees "non-revoked rows", so this check is the only thing that enforces **suspension**. A user can
        // have several passkeys, so only the stopped one is blocked.
        match is_blocked_in_registry(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::WebAuthn,
            Some(cred_row_id),
        )
        .await
        {
            Ok(true) => return Err(PasskeyAssertionError::InvalidCredential),
            Ok(false) => {}
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        }

        // 5. WebAuthn verification.
        let dk = DiscoverableKey::from(&passkey);
        let auth_result =
            match self
                .webauthn
                .finish_authentication(&public_key_credential, auth_state, &[dk])
            {
                Ok(r) => r,
                Err(_) => {
                    self.audit
                        .record(
                            AuditEventType::LoginFailed,
                            AuditResult::Failure,
                            Some(tenant_id),
                            Some(user_id),
                            None,
                            Some("invalid_passkey"),
                            ctx,
                        )
                        .await;
                    return Err(PasskeyAssertionError::InvalidCredential);
                }
            };

        // 6. Update sign_count and save passkey_json (persist to the DB if anything changed).
        let mut updated_passkey = passkey;
        if updated_passkey
            .update_credential(&auth_result)
            .unwrap_or(false)
        {
            let new_json = match serde_json::to_string(&updated_passkey) {
                Ok(j) => j,
                Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
            };
            if let Err(e) = self
                .webauthn_credentials
                .update_passkey(cred_row_id, &new_json, now)
                .await
            {
                return Err(PasskeyAssertionError::Internal(e.to_string()));
            }
        }

        // 7. Check that the user is active and has an ACTIVE membership (HOME or GUEST) in the flow's tenant.
        //    WebAuthn credentials have no tenant column and are resolved per host, so the tenant boundary
        //    is enforced by this application-layer link (ADR-0009 §8; same check as SSO restore in `authorize`).
        //    Non-member, inactive, and unknown all fall to `InvalidCredential` (reasons not split, to avoid enumeration).
        let home_tenant_id = ensure_active_member(
            self.users.as_ref(),
            self.memberships.as_ref(),
            tenant_id,
            user_id,
        )
        .await?;

        Ok(VerifiedPasskeyUser {
            user_id,
            home_tenant_id,
            auth_session_id_hash: challenge.auth_session_id_hash,
        })
    }
}

/// What re-authentication (AP5) requires of passkeys.
///
/// [`StepUpService`](crate::application::step_up::StepUpService) looks only at these two rather than the
/// whole ceremony implementation **so that testing the re-authentication decision does not require
/// assembling the full ceremony** (four repositories — credentials, challenges, registry, tenant membership —
/// plus a WebAuthn implementation). The only implementation is [`PasskeyAssertionService`], so the ceremony
/// itself stays in one place along with the three login paths (ADR-0040 decision 1).
#[async_trait::async_trait]
pub trait PasskeyStepUpCeremony: Send + Sync {
    /// Issue one challenge for re-authentication.
    async fn begin(&self) -> Result<(Uuid, serde_json::Value), String>;

    /// Verify an assertion and settle its owner. **Whether the owner is the session's user is checked by the caller**
    /// (the ceremony answers only "whose passkey is this").
    async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError>;
}

#[async_trait::async_trait]
impl PasskeyStepUpCeremony for PasskeyAssertionService {
    async fn begin(&self) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_step_up().await
    }

    async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError> {
        PasskeyAssertionService::verify(
            self,
            tenant_id,
            challenge_id,
            credential,
            PasskeyFlow::StepUp,
            ctx,
        )
        .await
    }
}

/// Verify that the credential owner is an ACTIVE member (HOME or GUEST) of the flow's tenant and an active
/// account. Not a member, inactive, unknown, or failure all fall to `InvalidCredential` / `Internal`
/// (tenant boundary enforcement, ADR-0009 §8). Split out of the service so it can be unit tested.
async fn ensure_active_member(
    users: &dyn UserRepository,
    memberships: &dyn TenantMembershipRepository,
    tenant_id: TenantId,
    user_id: Uuid,
) -> Result<TenantId, PasskeyAssertionError> {
    let home_tenant_id = match users.find_by_id(user_id).await {
        Ok(Some(u)) if u.is_active() => u.tenant_id,
        Ok(_) => return Err(PasskeyAssertionError::InvalidCredential),
        Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
    };
    match memberships.is_active_member(tenant_id, user_id).await {
        Ok(true) => Ok(home_tenant_id),
        Ok(false) => Err(PasskeyAssertionError::InvalidCredential),
        Err(e) => Err(PasskeyAssertionError::Internal(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    fn active_user(id: Uuid, tenant_id: TenantId) -> User {
        let t = Utc.with_ymd_and_hms(2026, 7, 17, 0, 0, 0).unwrap();
        User {
            id,
            tenant_id,
            sub: Uuid::new_v4(),
            email: "u@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
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
            created_at: t,
            updated_at: t,
        }
    }

    /// Fake returning a single user (`None` means not found).
    struct FakeUsers(Option<User>);
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// This test never goes through the login failure path (SEC13 is verified in login / mfa_login).
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
            Ok(self.0.clone().filter(|u| u.id == id))
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
            _l: Option<chrono::DateTime<Utc>>,
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
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// Fake that fixes the return value of `is_active_member` for a given tenant.
    struct FakeMemberships {
        tenant_id: TenantId,
        is_member: DomainResult<bool>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, t: TenantId, _u: Uuid) -> DomainResult<bool> {
            assert_eq!(
                t, self.tenant_id,
                "membership check must use the flow tenant"
            );
            match &self.is_member {
                Ok(v) => Ok(*v),
                Err(e) => Err(DomainError::Repository(e.to_string())),
            }
        }
        async fn find_by_invitation_token_hash(
            &self,
            _h: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn activate(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn ids() -> (Uuid, TenantId) {
        (Uuid::new_v4(), Uuid::now_v7().into())
    }

    /// Sink that just discards audit events (this module's tests do not check audit content).
    struct DiscardingSink;
    #[async_trait]
    impl crate::domain::repositories::AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct FixedClock(chrono::DateTime<Utc>);
    impl crate::domain::clock::Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            self.0
        }
    }

    /// Fake that returns one challenge and records whether it was deleted.
    struct FakeChallenges {
        challenge: std::sync::Mutex<Option<PasskeyChallenge>>,
        deleted: std::sync::Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl crate::domain::repositories::PasskeyChallengeRepository for FakeChallenges {
        async fn create(&self, _c: &PasskeyChallenge) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<PasskeyChallenge>> {
            Ok(self
                .challenge
                .lock()
                .unwrap()
                .clone()
                .filter(|c| c.id == id))
        }
        async fn delete(&self, id: Uuid) -> DomainResult<bool> {
            // Only the first delete succeeds (the second models another concurrent request deleting it first; task #586).
            let mut deleted = self.deleted.lock().unwrap();
            let first = !deleted.contains(&id);
            deleted.push(id);
            Ok(first)
        }
        async fn delete_expired(&self, _now: chrono::DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
    }

    /// Fake guaranteeing that nothing goes past the flow check (panics if called).
    struct UnreachableCredentials;
    #[async_trait]
    impl WebAuthnCredentialRepository for UnreachableCredentials {
        async fn create(
            &self,
            _c: &crate::domain::webauthn_credential::WebAuthnCredential,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(
            &self,
            _id: Uuid,
        ) -> DomainResult<Option<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!()
        }
        async fn find_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> DomainResult<Option<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!("the flow check must reject before the credential lookup")
        }
        async fn list_by_user_id(
            &self,
            _user_id: Uuid,
        ) -> DomainResult<Vec<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!()
        }
        async fn update_passkey(
            &self,
            _id: Uuid,
            _passkey_json: &str,
            _last_used_at: chrono::DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _user_id: Uuid) -> DomainResult<u64> {
            unreachable!()
        }
    }

    /// Registry fake with only default implementations (not reached in these tests).
    struct UnreachableAuthenticators;
    #[async_trait]
    impl UserAuthenticatorRepository for UnreachableAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct UnreachableWebAuthn;
    impl WebAuthnPort for UnreachableWebAuthn {
        fn begin_registration(
            &self,
            _user_id: Uuid,
            _user_name: &str,
            _user_display_name: &str,
            _exclude: &[Passkey],
        ) -> Result<
            (
                webauthn_rs::prelude::CreationChallengeResponse,
                webauthn_rs::prelude::PasskeyRegistration,
            ),
            String,
        > {
            unreachable!()
        }
        fn finish_registration(
            &self,
            _credential: &webauthn_rs::prelude::RegisterPublicKeyCredential,
            _state: &webauthn_rs::prelude::PasskeyRegistration,
        ) -> Result<Passkey, String> {
            unreachable!()
        }
        fn begin_authentication(
            &self,
        ) -> Result<
            (
                webauthn_rs::prelude::RequestChallengeResponse,
                DiscoverableAuthentication,
            ),
            String,
        > {
            unreachable!()
        }
        fn finish_authentication(
            &self,
            _credential: &PublicKeyCredential,
            _state: DiscoverableAuthentication,
            _creds: &[DiscoverableKey],
        ) -> Result<webauthn_rs::prelude::AuthenticationResult, String> {
            unreachable!()
        }
    }

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 29, 12, 0, 0).unwrap()
    }

    /// Build a service that knows only one authentication challenge with the given `auth_session_id_hash`.
    fn service_with_challenge(
        auth_session_id_hash: Option<&str>,
        expires_at: chrono::DateTime<Utc>,
    ) -> (PasskeyAssertionService, Uuid, Arc<FakeChallenges>) {
        let challenge_id = Uuid::new_v4();
        let challenges = Arc::new(FakeChallenges {
            challenge: std::sync::Mutex::new(Some(PasskeyChallenge {
                id: challenge_id,
                user_id: None,
                challenge_type: PasskeyChallengeType::Authenticate,
                // The flow check runs before this JSON is read, so its content does not matter.
                state_json: "not-a-discoverable-authentication".to_string(),
                auth_session_id_hash: auth_session_id_hash.map(|s| s.to_string()),
                expires_at,
                created_at: fixed_now(),
            })),
            deleted: std::sync::Mutex::new(Vec::new()),
        });
        let service = PasskeyAssertionService::new(
            Arc::new(UnreachableCredentials),
            Arc::new(UnreachableAuthenticators),
            challenges.clone(),
            Arc::new(FakeUsers(None)),
            Arc::new(FakeMemberships {
                tenant_id: Uuid::now_v7().into(),
                is_member: Ok(true),
            }),
            Arc::new(UnreachableWebAuthn),
            Arc::new(crate::application::audit::AuditService::new(
                Arc::new(DiscardingSink),
                Arc::new(FixedClock(fixed_now())),
            )),
            Arc::new(FixedClock(fixed_now())),
        );
        (service, challenge_id, challenges)
    }

    fn request_context() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn an_authorization_flow_challenge_is_not_accepted_by_a_direct_login() {
        // A challenge issued for the authorization flow (bound to an auth_session) does not pass when
        // brought to the admin console / portal completion endpoint.
        let (service, challenge_id, challenges) = service_with_challenge(
            Some("auth-session-hash"),
            fixed_now() + Duration::minutes(5),
        );
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Direct,
                &request_context(),
            )
            .await
            .expect_err("a challenge bound to an auth session must not complete a direct login");
        assert!(matches!(err, PasskeyAssertionError::WrongFlow));
        // Even on a purpose mismatch the challenge is used up (so the right path cannot be tried with it).
        assert_eq!(
            challenges.deleted.lock().unwrap().as_slice(),
            [challenge_id]
        );
    }

    #[tokio::test]
    async fn a_direct_login_challenge_is_not_accepted_by_the_authorization_flow() {
        let (service, challenge_id, _) =
            service_with_challenge(None, fixed_now() + Duration::minutes(5));
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Oidc,
                &request_context(),
            )
            .await
            .expect_err("a direct-login challenge must not continue an authorization flow");
        assert!(matches!(err, PasskeyAssertionError::WrongFlow));
    }

    /// If another request using the same challenge concurrently deleted it first, signature verification is not reached (task #586).
    /// Synced passkeys keep the counter at 0, so the counter cannot stop a resent signature.
    #[tokio::test]
    async fn a_challenge_consumed_by_another_request_does_not_reach_verification() {
        let (service, challenge_id, challenges) =
            service_with_challenge(None, fixed_now() + Duration::minutes(5));
        challenges.deleted.lock().unwrap().push(challenge_id);
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Direct,
                &request_context(),
            )
            .await
            .expect_err("a consumed challenge must not be usable");
        assert!(matches!(err, PasskeyAssertionError::ChallengeNotFound));
    }

    #[tokio::test]
    async fn an_expired_challenge_is_rejected_before_the_flow_check() {
        let (service, challenge_id, challenges) =
            service_with_challenge(None, fixed_now() - Duration::seconds(1));
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Direct,
                &request_context(),
            )
            .await
            .expect_err("an expired challenge must not be usable");
        assert!(matches!(err, PasskeyAssertionError::ChallengeNotFound));
        assert_eq!(
            challenges.deleted.lock().unwrap().as_slice(),
            [challenge_id]
        );
    }

    #[tokio::test]
    async fn active_member_is_authorized() {
        let (uid, tid) = ids();
        let users = FakeUsers(Some(active_user(uid, tid)));
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Ok(true),
        };
        assert!(ensure_active_member(&users, &memberships, tid, uid)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn non_member_is_rejected_as_invalid_credential() {
        // Presenting a passkey in another tenant's flow is rejected unless the user is an ACTIVE member of that tenant
        // (tenant isolation, ADR-0009 §8).
        let (uid, home) = ids();
        let other_tenant: TenantId = Uuid::now_v7().into();
        let users = FakeUsers(Some(active_user(uid, home)));
        let memberships = FakeMemberships {
            tenant_id: other_tenant,
            is_member: Ok(false),
        };
        let outcome = ensure_active_member(&users, &memberships, other_tenant, uid)
            .await
            .expect_err("non-member must be rejected");
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
    }

    #[tokio::test]
    async fn inactive_user_is_rejected_without_touching_membership() {
        let (uid, tid) = ids();
        let mut user = active_user(uid, tid);
        user.status = UserStatus::Disabled;
        let users = FakeUsers(Some(user));
        // Panics if the membership check is reached (inactive users are rejected first).
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Err(DomainError::Repository("must not be called".to_string())),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("inactive user must be rejected");
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
    }

    #[tokio::test]
    async fn unknown_user_is_rejected() {
        let (uid, tid) = ids();
        let users = FakeUsers(None);
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Ok(true),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("unknown user must be rejected");
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
    }

    #[tokio::test]
    async fn membership_repository_error_maps_to_internal() {
        let (uid, tid) = ids();
        let users = FakeUsers(Some(active_user(uid, tid)));
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Err(DomainError::Repository("db down".to_string())),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("repository failure must not authorize");
        assert!(matches!(outcome, PasskeyAssertionError::Internal(_)));
    }
}
