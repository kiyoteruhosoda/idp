//! AuthSession aggregate (design spec §3.3).
//!
//! The temporary state of the authorization flow from `/authorize` to code issuance. Holds the accepted authorization request
//! ([`AuthorizationRequest`]) and **whose authentication has progressed how far** for that request
//! ([`AuthenticationProgress`]).
//!
//! # How state changes
//!
//! Only methods expressing this aggregate's intent change the state:
//!
//! | Method | What happens |
//! |---|---|
//! | [`AuthSession::start`] | Accepts the authorization request and starts the flow (issues the single-use handle passed to the web) |
//! | [`AuthSession::exchange_handoff`] | The web exchanges the handle for an `auth_session_id` |
//! | [`AuthSession::record_password_verification`] | Passed up to the password (waiting for the second step) |
//! | [`AuthSession::complete_authentication`] | Authentication completed |
//!
//! Each method returns a value representing the change ([`HandoffExchange`], etc.), and the repository persists it **in one statement**.
//! The aggregate decides the content of the change and the repository owns the atomicity of the write.
//!
//! # `auth_session_id` is re-keyed every time (SEC7)
//!
//! The id is regenerated at every authentication step (against session fixation). The re-keying is part of the same
//! change as recording the state ([`IdRotation`]), so there is never "a moment when the Cookie value issued before authentication still works after it".

use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::crypto;
use crate::domain::tenant::TenantId;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// Plaintext of `auth_session_id` (a random value of 128 bits or more that the web holds in a host-only Cookie).
///
/// This value is **a bearer credential itself** (presenting it allows operating an authorization session waiting for consent / MFA).
/// Only [`AuthSessionIdHash`] is stored in the DB, and the plaintext exists only during
/// the request/response (SEC6). It is not shown in `Debug` either.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSessionId(String);

impl AuthSessionId {
    /// Creates a new id.
    pub fn generate() -> Self {
        Self(crypto::random_hex(32))
    }

    /// Accepts the value presented by the web. Empty is the same as "not having one".
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    /// Hash used for storage and matching.
    pub fn hash(&self) -> AuthSessionIdHash {
        AuthSessionIdHash::of_plain(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The plaintext passed to the web.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for AuthSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthSessionId(<redacted>)")
    }
}

/// SHA-256 of `auth_session_id`. The DB primary key.
///
/// Like other bearer credentials (`sso_sessions.session_hash`, `authorization_codes.code_hash`,
/// `refresh_tokens.token_hash`, and `handle_hash` in the same table), only the hash is put in the DB (SEC6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthSessionIdHash(String);

impl AuthSessionIdHash {
    /// Derives from the plaintext.
    pub fn of_plain(plain: &str) -> Self {
        Self(crypto::sha256_hex(plain))
    }

    /// Accepts a stored hash value (a value kept in another table, such as a passkey challenge).
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Plaintext of the single-use handle for the web handoff (ADR-0018 decision 2).
///
/// Passed to the web in the 302 of `/authorize`; the web exchanges it for an `auth_session_id` at `/internal/authorize/resume`.
/// Single-use and short-lived, fixedly bound to the issuing authorization session (= its `code_challenge`).
#[derive(Clone, PartialEq, Eq)]
pub struct HandoffHandle(String);

impl HandoffHandle {
    fn generate() -> Self {
        Self(crypto::random_hex(32))
    }

    /// Accepts the value presented by the web. Empty is the same as "not having one".
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    pub fn hash(&self) -> HandoffHandleHash {
        HandoffHandleHash(crypto::sha256_hex(&self.0))
    }

    /// The plaintext passed to the web (carried in the URL).
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for HandoffHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandoffHandle(<redacted>)")
    }
}

/// SHA-256 of the handoff handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffHandleHash(String);

impl HandoffHandleHash {
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An unexchanged handle (hash and expiry). Disappears on exchange (single use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHandoff {
    handle_hash: HandoffHandleHash,
    /// Shorter-lived than the auth_session's own `expires_at`.
    expires_at: DateTime<Utc>,
}

impl PendingHandoff {
    pub fn handle_hash(&self) -> &HandoffHandleHash {
        &self.handle_hash
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// A completed authentication (who, when, with which SSO session, by what).
///
/// The authorization code is issued against this (the source of the ID Token's `sub` / `auth_time` / `sid` / `acr` /
/// `amr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    user_id: Uuid,
    auth_time: DateTime<Utc>,
    /// `sid` of the SSO session established (or restored) by the authentication (G5).
    sso_sid: Option<String>,
    /// The authentication methods actually verified (ADR-0043). `None` = not recorded (then `acr` / `amr` are not included).
    methods: Option<Vec<AuthenticationMethod>>,
}

impl Authentication {
    pub fn new(
        user_id: Uuid,
        auth_time: DateTime<Utc>,
        sso_sid: Option<String>,
        methods: Option<Vec<AuthenticationMethod>>,
    ) -> Self {
        Self {
            user_id,
            auth_time,
            sso_sid,
            methods,
        }
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn auth_time(&self) -> DateTime<Utc> {
        self.auth_time
    }

    pub fn sso_sid(&self) -> Option<&str> {
        self.sso_sid.as_deref()
    }

    pub fn methods(&self) -> Option<&[AuthenticationMethod]> {
        self.methods.as_deref()
    }
}

/// How far authentication has progressed for the authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationProgress {
    /// No one has authenticated yet.
    Anonymous,
    /// Passed up to the password (waiting for the second factor or a password change).
    PasswordVerified {
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    },
    /// Authentication completed (waiting for consent).
    Authenticated {
        authentication: Authentication,
        /// The time the password was verified before this authentication (`None` for methods not going through a password).
        password_verified_at: Option<DateTime<Utc>>,
    },
}

/// Re-keying of `auth_session_id` (SEC7).
///
/// The old id is `previous`; the new plaintext passed to the web is `issued`. The repository rewrites the old id's row to the new id
/// (it can never be looked up by the old id again).
#[derive(Debug, Clone)]
pub struct IdRotation {
    previous: AuthSessionIdHash,
    issued: AuthSessionId,
}

impl IdRotation {
    pub fn previous(&self) -> &AuthSessionIdHash {
        &self.previous
    }

    pub fn issued_hash(&self) -> AuthSessionIdHash {
        self.issued.hash()
    }

    /// The new `auth_session_id` passed to the web.
    pub fn into_issued(self) -> AuthSessionId {
        self.issued
    }
}

/// Handle exchange (single-use consumption and id re-keying persisted as one change).
///
/// On the handle path there is no plaintext id at hand (the DB only has the hash), so the `auth_session_id`
/// returned to the web has to be newly created at exchange time.
#[derive(Debug, Clone)]
pub struct HandoffExchange {
    consumed: HandoffHandleHash,
    rotation: IdRotation,
}

impl HandoffExchange {
    /// The handle to consume (persisted conditionally on "this handle still remains").
    pub fn consumed(&self) -> &HandoffHandleHash {
        &self.consumed
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// The handle cannot be exchanged (invalid, expired, or already exchanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffUnavailable;

/// Record of password verification (transition to waiting for the second step).
#[derive(Debug, Clone)]
pub struct PasswordVerification {
    user_id: Uuid,
    verified_at: DateTime<Utc>,
    rotation: IdRotation,
}

impl PasswordVerification {
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// Record of authentication completion.
#[derive(Debug, Clone)]
pub struct AuthenticationCompletion {
    authentication: Authentication,
    rotation: IdRotation,
}

impl AuthenticationCompletion {
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// AuthSession aggregate.
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// SHA-256 of `auth_session_id`. The plaintext is never stored here.
    id_hash: AuthSessionIdHash,
    /// The tenant that started the flow (`/{tenant_id}/authorize`. ADR-0009 §8).
    tenant_id: TenantId,
    request: AuthorizationRequest,
    handoff: Option<PendingHandoff>,
    progress: AuthenticationProgress,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Parts for rebuilding an [`AuthSession`] from persistence (in column order).
///
/// ⚠ Exists **only for the Infrastructure layer (repository implementations) and tests**.
#[derive(Debug, Clone)]
pub struct AuthSessionParts {
    pub id_hash: AuthSessionIdHash,
    pub tenant_id: TenantId,
    pub request: AuthorizationRequest,
    pub handle_hash: Option<HandoffHandleHash>,
    pub handle_expires_at: Option<DateTime<Utc>>,
    pub authenticated_user_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    pub password_verified_at: Option<DateTime<Utc>>,
    pub sso_sid: Option<String>,
    pub authentication_methods: Option<Vec<AuthenticationMethod>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthSession {
    /// Accepts the authorization request and starts the flow. Also issues the single-use handle passed to the web.
    ///
    /// The `auth_session_id` at this point is given to no one (only the handle goes to the web), so the generated
    /// plaintext is turned into the stored hash and discarded immediately. The `auth_session_id` the web receives is created by the handle exchange
    /// ([`Self::exchange_handoff`]).
    pub fn start(
        tenant_id: TenantId,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
        lifetime: Duration,
        handoff_lifetime: Duration,
    ) -> (Self, HandoffHandle) {
        let handle = HandoffHandle::generate();
        let session = Self {
            id_hash: AuthSessionId::generate().hash(),
            tenant_id,
            request,
            handoff: Some(PendingHandoff {
                handle_hash: handle.hash(),
                expires_at: now + handoff_lifetime,
            }),
            progress: AuthenticationProgress::Anonymous,
            expires_at: now + lifetime,
            created_at: now,
            updated_at: now,
        };
        (session, handle)
    }

    /// Restores from persisted values.
    ///
    /// The authentication progress is decided from the combination of columns. No user means `Anonymous`; with `auth_time`
    /// it is `Authenticated`; with only the password verification time it is `PasswordVerified`. A combination matching none
    /// (only a user) has no write path, so it is treated as `Anonymous`.
    pub fn reconstitute(parts: AuthSessionParts) -> Self {
        let progress = match (
            parts.authenticated_user_id,
            parts.auth_time,
            parts.password_verified_at,
        ) {
            (Some(user_id), Some(auth_time), password_verified_at) => {
                AuthenticationProgress::Authenticated {
                    authentication: Authentication::new(
                        user_id,
                        auth_time,
                        parts.sso_sid,
                        parts.authentication_methods,
                    ),
                    password_verified_at,
                }
            }
            (Some(user_id), None, Some(verified_at)) => AuthenticationProgress::PasswordVerified {
                user_id,
                verified_at,
            },
            _ => AuthenticationProgress::Anonymous,
        };
        let handoff = match (parts.handle_hash, parts.handle_expires_at) {
            (Some(handle_hash), Some(expires_at)) => Some(PendingHandoff {
                handle_hash,
                expires_at,
            }),
            _ => None,
        };
        Self {
            id_hash: parts.id_hash,
            tenant_id: parts.tenant_id,
            request: parts.request,
            handoff,
            progress,
            expires_at: parts.expires_at,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
        }
    }

    /// Decomposes into parts for persistence (the inverse of [`Self::reconstitute`]).
    pub fn to_parts(&self) -> AuthSessionParts {
        let (authenticated_user_id, auth_time, password_verified_at, sso_sid, methods) =
            match &self.progress {
                AuthenticationProgress::Anonymous => (None, None, None, None, None),
                AuthenticationProgress::PasswordVerified {
                    user_id,
                    verified_at,
                } => (Some(*user_id), None, Some(*verified_at), None, None),
                AuthenticationProgress::Authenticated {
                    authentication,
                    password_verified_at,
                } => (
                    Some(authentication.user_id),
                    Some(authentication.auth_time),
                    *password_verified_at,
                    authentication.sso_sid.clone(),
                    authentication.methods.clone(),
                ),
            };
        AuthSessionParts {
            id_hash: self.id_hash.clone(),
            tenant_id: self.tenant_id,
            request: self.request.clone(),
            handle_hash: self.handoff.as_ref().map(|h| h.handle_hash.clone()),
            handle_expires_at: self.handoff.as_ref().map(|h| h.expires_at),
            authenticated_user_id,
            auth_time,
            password_verified_at,
            sso_sid,
            authentication_methods: methods,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    pub fn id_hash(&self) -> &AuthSessionIdHash {
        &self.id_hash
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn request(&self) -> &AuthorizationRequest {
        &self.request
    }

    /// The client that made the authorization request (target for audit and policy).
    pub fn client_id(&self) -> &str {
        self.request.client_id()
    }

    pub fn handoff(&self) -> Option<&PendingHandoff> {
        self.handoff.as_ref()
    }

    pub fn progress(&self) -> &AuthenticationProgress {
        &self.progress
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Whether the web handoff handle is exchangeable at `now` (not yet exchanged and within expiry).
    pub fn handoff_is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.handoff.as_ref().is_some_and(|h| h.expires_at > now)
    }

    /// The user who identified themselves in this authorization session, whether authentication is in progress or complete.
    pub fn identified_user(&self) -> Option<Uuid> {
        match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { user_id, .. } => Some(*user_id),
            AuthenticationProgress::Authenticated { authentication, .. } => {
                Some(authentication.user_id)
            }
        }
    }

    /// The user whose password has been verified (used at the entrance of the second factor or password change).
    ///
    /// Authentications completed without a password (passkey, external IdP, SSO restore) do not count.
    pub fn password_verified_user(&self) -> Option<Uuid> {
        match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { user_id, .. } => Some(*user_id),
            AuthenticationProgress::Authenticated {
                authentication,
                password_verified_at,
            } => password_verified_at.map(|_| authentication.user_id),
        }
    }

    /// The completed authentication (the basis on which accepting consent issues a code).
    pub fn completed_authentication(&self) -> Option<&Authentication> {
        match &self.progress {
            AuthenticationProgress::Authenticated { authentication, .. } => Some(authentication),
            _ => None,
        }
    }

    /// Consumes the web handoff handle and issues the `auth_session_id` the web holds.
    ///
    /// `handle` is the handle by which this authorization session was looked up (already matched by the caller). Persistence is
    /// conditional on "the handle still remains" (only one of concurrent exchanges wins).
    pub fn exchange_handoff(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<HandoffExchange, HandoffUnavailable> {
        if !self.handoff_is_valid_at(now) || self.is_expired_at(now) {
            return Err(HandoffUnavailable);
        }
        let consumed = self.handoff.take().expect("validated above").handle_hash;
        Ok(HandoffExchange {
            consumed,
            rotation: self.rotate_id(),
        })
    }

    /// Records passing up to the password (waiting for the second factor or a password change).
    ///
    /// ⚠ **The previous authentication is not kept.** Even if someone's authentication already completed in the same authorization session,
    /// once another (or the same) user redoes authentication here, the previous one is no longer the basis of this flow.
    /// Keeping it would let accepting consent issue a code to a user who has not finished the second step.
    pub fn record_password_verification(
        &mut self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> PasswordVerification {
        self.progress = AuthenticationProgress::PasswordVerified {
            user_id,
            verified_at,
        };
        PasswordVerification {
            user_id,
            verified_at,
            rotation: self.rotate_id(),
        }
    }

    /// Records that authentication completed.
    pub fn complete_authentication(
        &mut self,
        authentication: Authentication,
    ) -> AuthenticationCompletion {
        let password_verified_at = match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { verified_at, .. } => Some(*verified_at),
            AuthenticationProgress::Authenticated {
                password_verified_at,
                ..
            } => *password_verified_at,
        };
        self.progress = AuthenticationProgress::Authenticated {
            authentication: authentication.clone(),
            password_verified_at,
        };
        AuthenticationCompletion {
            authentication,
            rotation: self.rotate_id(),
        }
    }

    fn rotate_id(&mut self) -> IdRotation {
        let issued = AuthSessionId::generate();
        let previous = std::mem::replace(&mut self.id_hash, issued.hash());
        IdRotation { previous, issued }
    }
}

/// Parts for quickly building authorization sessions in tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// An authorization session on the sign-in screen (no one has authenticated yet).
    pub fn awaiting_login(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AuthSession {
        AuthSession::reconstitute(parts(tenant_id, auth_session_id, request, now))
    }

    /// An authorization session that passed the password and is waiting for the second step.
    pub fn awaiting_second_step(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> AuthSession {
        AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user_id),
            password_verified_at: Some(now),
            ..parts(tenant_id, auth_session_id, request, now)
        })
    }

    fn parts(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AuthSessionParts {
        AuthSessionParts {
            id_hash: AuthSessionIdHash::of_plain(auth_session_id),
            tenant_id,
            request,
            handle_hash: None,
            handle_expires_at: None,
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            sso_sid: None,
            authentication_methods: None,
            expires_at: now + Duration::seconds(600),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_request::test_support::request;

    const HANDOFF_SECS: i64 = 60;

    fn started(now: DateTime<Utc>) -> (AuthSession, HandoffHandle) {
        AuthSession::start(
            Uuid::now_v7().into(),
            request("app", "https://client.example.com/cb"),
            now,
            Duration::minutes(10),
            Duration::seconds(HANDOFF_SECS),
        )
    }

    fn authentication(user_id: Uuid, at: DateTime<Utc>) -> Authentication {
        Authentication::new(
            user_id,
            at,
            Some("sid-1".to_string()),
            Some(vec![AuthenticationMethod::Password]),
        )
    }

    #[test]
    fn a_started_session_is_anonymous_and_bound_to_its_handle() {
        let now = Utc::now();
        let (session, handle) = started(now);
        assert_eq!(session.progress(), &AuthenticationProgress::Anonymous);
        assert_eq!(session.identified_user(), None);
        assert_eq!(
            session.handoff().map(|h| h.handle_hash().clone()),
            Some(handle.hash())
        );
        assert!(session.handoff_is_valid_at(now));
        assert!(!session.is_expired_at(now));
        assert!(session.is_expired_at(now + Duration::minutes(10)));
    }

    #[test]
    fn the_handle_is_single_use_and_short_lived() {
        let now = Utc::now();

        // An expired one cannot be exchanged.
        let (mut session, _) = started(now);
        assert_eq!(
            session
                .exchange_handoff(now + Duration::seconds(HANDOFF_SECS + 1))
                .unwrap_err(),
            HandoffUnavailable
        );

        // Exchange happens only once. Exchanging re-keys the id.
        let (mut session, handle) = started(now);
        let before = session.id_hash().clone();
        let exchange = session.exchange_handoff(now).expect("first exchange");
        assert_eq!(exchange.consumed(), &handle.hash());
        assert_eq!(exchange.rotation().previous(), &before);
        assert_eq!(session.id_hash(), &exchange.rotation().issued_hash());
        assert_eq!(
            exchange.into_issued().hash(),
            session.id_hash().clone(),
            "web receives the plaintext of the new id"
        );
        assert!(session.handoff().is_none());
        assert_eq!(
            session.exchange_handoff(now).unwrap_err(),
            HandoffUnavailable
        );
    }

    #[test]
    fn password_verification_waits_for_the_second_step() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        let before = session.id_hash().clone();

        let verification = session.record_password_verification(user, now);
        assert_eq!(verification.rotation().previous(), &before);
        assert_ne!(session.id_hash(), &before, "SEC7: the id rotates");
        assert_eq!(session.identified_user(), Some(user));
        assert_eq!(session.password_verified_user(), Some(user));
        assert_eq!(session.completed_authentication(), None);
    }

    #[test]
    fn completing_after_a_password_keeps_the_password_timestamp() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.record_password_verification(user, now);
        let completion = session.complete_authentication(authentication(user, now));

        assert_eq!(completion.authentication().user_id(), user);
        assert_eq!(
            session.completed_authentication(),
            Some(&authentication(user, now))
        );
        // Existing behavior that has allowed re-entering the MFA screen (the record of password verification remains).
        assert_eq!(session.password_verified_user(), Some(user));
    }

    #[test]
    fn a_passwordless_completion_is_not_password_verified() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.complete_authentication(authentication(user, now));
        assert_eq!(session.identified_user(), Some(user));
        assert_eq!(session.password_verified_user(), None);
    }

    /// ⚠ Once authentication is redone, the previous authentication is not a basis for consent.
    #[test]
    fn re_verifying_a_password_discards_the_previous_authentication() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        session.complete_authentication(authentication(first, now));

        session.record_password_verification(second, now);
        assert_eq!(session.completed_authentication(), None);
        assert_eq!(session.identified_user(), Some(second));
    }

    #[test]
    fn reconstitution_derives_the_progress_from_the_columns() {
        let now = Utc::now();
        let user = Uuid::now_v7();
        let base = || AuthSessionParts {
            id_hash: AuthSessionIdHash::of_plain("s"),
            tenant_id: Uuid::now_v7().into(),
            request: request("app", "https://client.example.com/cb"),
            handle_hash: Some(HandoffHandleHash::from_stored("h".to_string())),
            handle_expires_at: None,
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            sso_sid: None,
            authentication_methods: None,
            expires_at: now + Duration::minutes(10),
            created_at: now,
            updated_at: now,
        };

        // With only one of hash and expiry, it is not considered an exchangeable handle.
        let session = AuthSession::reconstitute(base());
        assert!(session.handoff().is_none());
        assert_eq!(session.progress(), &AuthenticationProgress::Anonymous);

        let session = AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user),
            password_verified_at: Some(now),
            ..base()
        });
        assert_eq!(
            session.progress(),
            &AuthenticationProgress::PasswordVerified {
                user_id: user,
                verified_at: now
            }
        );

        let session = AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user),
            auth_time: Some(now),
            sso_sid: Some("sid".to_string()),
            ..base()
        });
        assert_eq!(
            session.completed_authentication(),
            Some(&Authentication::new(
                user,
                now,
                Some("sid".to_string()),
                None
            ))
        );
        assert_eq!(session.password_verified_user(), None);
    }

    #[test]
    fn parts_round_trip_through_reconstitution() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.record_password_verification(user, now);
        session.complete_authentication(authentication(user, now));

        let restored = AuthSession::reconstitute(session.to_parts());
        assert_eq!(restored.id_hash(), session.id_hash());
        assert_eq!(restored.progress(), session.progress());
        assert_eq!(restored.request(), session.request());
        assert_eq!(restored.handoff(), session.handoff());
    }

    #[test]
    fn plaintext_ids_are_not_printed() {
        let id = AuthSessionId::generate();
        assert!(!format!("{id:?}").contains(id.as_str()));
        assert_eq!(AuthSessionId::from_presented(""), None);
    }
}
