//! Passkey (WebAuthn) registration use case.
//!
//! An SSO-authenticated user registers and deletes their own passkeys. Registration flow:
//! 1. `begin()` — generates and stores a challenge and returns the options JSON.
//! 2. `complete()` — verifies the credential from the browser and saves it to the DB.
//! 3. `delete()` — deletes a credential.
//! 4. `list()` — returns the list of registered credentials (for the management screen).

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    PasskeyChallengeRepository, SsoSessionRepository, WebAuthnCredentialRepository,
};
use crate::domain::webauthn_credential::WebAuthnCredential;
use crate::domain::webauthn_port::WebAuthnPort;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyRegistration, RegisterPublicKeyCredential};

/// Challenge expiry (5 minutes).
const CHALLENGE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum PasskeyRegistrationError {
    #[error("sso session expired or not found")]
    SessionExpired,
    #[error("challenge not found or expired")]
    ChallengeNotFound,
    #[error("invalid credential response: {0}")]
    InvalidCredential(String),
    #[error("duplicate credential id")]
    DuplicateCredential,
    #[error("credential not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DomainError> for PasskeyRegistrationError {
    fn from(e: DomainError) -> Self {
        PasskeyRegistrationError::Internal(e.to_string())
    }
}

/// For displaying the list of registered credentials.
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Suspended in the registry (AP9). The key-fetching path only looks at "not revoked rows", so
    /// suspended passkeys also appear in this list. **They appear but can't be used**, so the state is attached.
    pub suspended: bool,
}

pub struct PasskeyRegistrationService {
    /// The authenticator registry (AP9). Deletion and suspension change its state (the row itself is
    /// created by `WebAuthnCredentialRepository`. AP11b).
    authenticators:
        Arc<crate::application::authenticator_management::AuthenticatorManagementService>,
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    webauthn: Arc<dyn WebAuthnPort>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl PasskeyRegistrationService {
    pub fn new(
        authenticators: Arc<
            crate::application::authenticator_management::AuthenticatorManagementService,
        >,
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        webauthn: Arc<dyn WebAuthnPort>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            authenticators,
            webauthn_credentials,
            passkey_challenges,
            sso_sessions,
            webauthn,
            clock,
            ids,
        }
    }

    /// Starts registration.
    ///
    /// Returns: `(challenge_id, options_json)` — `challenge_id` is a temporary ID used by complete.
    /// `options_json` is the JSON passed to the browser's `navigator.credentials.create()`.
    pub async fn begin(
        &self,
        sso_session_id: &str,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        self.begin_for_user(user_id, user_name).await
    }

    /// Starts registration (for a user **whose identity is already resolved**).
    ///
    /// Besides the SSO session, it is also called from account setup links issued by an admin (ADR-0062).
    /// ⚠ **The basis for identity is outside this method** ——the caller confirms, by either a session or a one-time token,
    /// that "this `user_id` may be claimed" before passing it.
    pub async fn begin_for_user(
        &self,
        user_id: Uuid,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
        // Pass existing credentials to exclude_credentials to prevent double registration.
        let existing = self.webauthn_credentials.list_by_user_id(user_id).await?;
        let existing_passkeys: Vec<Passkey> = existing
            .iter()
            .filter_map(|c| serde_json::from_str::<Passkey>(&c.passkey_json).ok())
            .collect();

        let (ccr, reg_state) = self
            .webauthn
            .begin_registration(user_id, user_name, user_name, &existing_passkeys)
            .map_err(PasskeyRegistrationError::InvalidCredential)?;

        let state_json = serde_json::to_string(&reg_state)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        let now = self.clock.now();
        let challenge_id = Uuid::new_v4();
        let challenge = PasskeyChallenge {
            id: challenge_id,
            user_id: Some(user_id),
            challenge_type: PasskeyChallengeType::Register,
            state_json,
            auth_session_id_hash: None,
            expires_at: now + chrono::Duration::from_std(CHALLENGE_TTL).unwrap(),
            created_at: now,
        };
        self.passkey_challenges.create(&challenge).await?;

        let options_json = serde_json::to_value(&ccr)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        Ok((challenge_id, options_json))
    }

    /// Completes registration.
    pub async fn complete(
        &self,
        sso_session_id: &str,
        challenge_id: Uuid,
        name: &str,
        credential_value: serde_json::Value,
    ) -> Result<Uuid, PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        self.complete_for_user(user_id, challenge_id, name, credential_value)
            .await
    }

    /// Revokes a registered passkey (when it lost to the consumption of a setup link. task #586).
    pub async fn discard_for_user(
        &self,
        user_id: Uuid,
        credential_row_id: Uuid,
    ) -> Result<(), PasskeyRegistrationError> {
        self.webauthn_credentials
            .delete(credential_row_id, user_id)
            .await?;
        Ok(())
    }

    /// Completes registration (for a user **whose identity is already resolved**). The caller's responsibility is
    /// the same as [`Self::begin_for_user`].
    pub async fn complete_for_user(
        &self,
        user_id: Uuid,
        challenge_id: Uuid,
        name: &str,
        credential_value: serde_json::Value,
    ) -> Result<Uuid, PasskeyRegistrationError> {
        let now = self.clock.now();

        // Fetch and consume the challenge.
        let challenge = self
            .passkey_challenges
            .find_by_id(challenge_id)
            .await?
            .ok_or(PasskeyRegistrationError::ChallengeNotFound)?;

        // Reject challenges whose purpose and owner don't match (the kind is checked so challenges issued for login or
        // identity verification can't be used here; matching `user_id` alone can cross kinds).
        if challenge.expires_at <= now
            || challenge.challenge_type != PasskeyChallengeType::Register
            || challenge.user_id != Some(user_id)
        {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return Err(PasskeyRegistrationError::ChallengeNotFound);
        }

        // Restore the challenge state.
        let reg_state: PasskeyRegistration = serde_json::from_str(&challenge.state_json)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        // Deserialize and verify the credential from the browser.
        let reg_credential: RegisterPublicKeyCredential = serde_json::from_value(credential_value)
            .map_err(|e| PasskeyRegistrationError::InvalidCredential(e.to_string()))?;

        let passkey = self
            .webauthn
            .finish_registration(&reg_credential, &reg_state)
            .map_err(PasskeyRegistrationError::InvalidCredential)?;

        // credential_id is stored base64url-encoded.
        let credential_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            passkey.cred_id(),
        );
        let passkey_json = serde_json::to_string(&passkey)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        let cred_id = self.ids.new_id();
        let cred = WebAuthnCredential {
            id: cred_id,
            user_id,
            credential_id,
            passkey_json,
            name: name.trim().to_string(),
            created_at: now,
            last_used_at: None,
        };

        // Delete the challenge first, then register (even on failure the challenge becomes unusable). ⚠ **Only the side that
        // managed to delete it registers** (task #586; even if two arrive at once with the same challenge, only one registers).
        if !self.passkey_challenges.delete(challenge_id).await? {
            return Err(PasskeyRegistrationError::ChallengeNotFound);
        }

        // Created as one row in the registry (AP11b). The public key and state go on the same row, so one write
        // suffices —— the two-step "insert into the original table, then add to the registry" during the migration
        // could leave a half-done state where only one side succeeded.
        self.webauthn_credentials.create(&cred).await.map_err(|e| {
            if matches!(e, DomainError::Conflict(_)) {
                PasskeyRegistrationError::DuplicateCredential
            } else {
                PasskeyRegistrationError::Internal(e.to_string())
            }
        })?;

        Ok(cred_id)
    }

    /// Deletes a credential.
    ///
    /// Deletion's result is "it is gone", so the DB says nothing when deleting a missing row. That's why **existence and
    /// owner are checked first**; without it, the screen would answer "deleted" for someone else's id, an already
    /// deleted id, or a typo alike.
    pub async fn delete(
        &self,
        sso_session_id: &str,
        credential_id: Uuid,
    ) -> Result<(), PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        match self.webauthn_credentials.find_by_id(credential_id).await? {
            Some(cred) if cred.user_id == user_id => {}
            _ => return Err(PasskeyRegistrationError::NotFound),
        }
        self.webauthn_credentials
            .delete(credential_id, user_id)
            .await?;
        self.authenticators
            .revoke_webauthn(user_id, credential_id)
            .await
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Returns the list of registered credentials.
    ///
    /// Suspension (AP9) only exists in the registry's `status`, and the key-fetching path (`WebAuthnCredentialRepository`)
    /// only drops revoked rows. **Suspended passkeys also appear in this list**, so the registry is matched against it
    /// to attach the state (1 row = 1 passkey, so matched by id. AP11b). Without it, the screen would list unusable
    /// passkeys as usable.
    pub async fn list(
        &self,
        sso_session_id: &str,
    ) -> Result<Vec<CredentialInfo>, PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        let creds = self.webauthn_credentials.list_by_user_id(user_id).await?;
        let suspended = self
            .authenticators
            .suspended_passkey_ids(user_id)
            .await
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;
        Ok(creds
            .into_iter()
            .map(|c| CredentialInfo {
                suspended: suspended.contains(&c.id),
                id: c.id,
                name: c.name,
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect())
    }

    /// Resolves the user ID and session hash from the SSO cookie value.
    async fn resolve_user(
        &self,
        sso_session_id: &str,
    ) -> Result<(Uuid, String), PasskeyRegistrationError> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = self
            .sso_sessions
            .find_by_hash(&hash)
            .await?
            .ok_or(PasskeyRegistrationError::SessionExpired)?;
        let now = self.clock.now();
        if session.idle_expires_at <= now || session.absolute_expires_at <= now {
            return Err(PasskeyRegistrationError::SessionExpired);
        }
        Ok((session.user_id, hash))
    }
}
