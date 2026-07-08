//! Passkey（WebAuthn）登録ユースケース。
//!
//! SSO 認証済みユーザーが自分でパスキーを登録・削除する。登録フロー:
//! 1. `begin()` — チャレンジ生成・保存・options JSON を返す。
//! 2. `complete()` — ブラウザからのクレデンシャルを検証してDBに保存する。
//! 3. `delete()` — クレデンシャルを削除する。
//! 4. `list()` — 登録済みクレデンシャル一覧を返す（管理画面用）。

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    PasskeyChallengeRepository, SsoSessionRepository, WebAuthnCredentialRepository,
};
use crate::domain::webauthn_credential::WebAuthnCredential;
use crate::infrastructure::crypto;
use crate::infrastructure::webauthn::WebAuthnService;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PasskeyRegistration, RegisterPublicKeyCredential};

/// チャレンジの有効期限（5 分）。
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

/// 登録済みクレデンシャルの一覧表示用。
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct PasskeyRegistrationService {
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    webauthn: Arc<WebAuthnService>,
    clock: Arc<dyn Clock>,
}

impl PasskeyRegistrationService {
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        webauthn: Arc<WebAuthnService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            webauthn_credentials,
            passkey_challenges,
            sso_sessions,
            webauthn,
            clock,
        }
    }

    /// 登録開始。
    ///
    /// 返り値: `(challenge_id, options_json)` — `challenge_id` は complete で使う一時 ID。
    /// `options_json` はブラウザの `navigator.credentials.create()` に渡す JSON。
    pub async fn begin(
        &self,
        sso_session_id: &str,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;

        // 既存クレデンシャルを exclude_credentials に渡して二重登録を防ぐ。
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
            auth_session_id: None,
            expires_at: now + chrono::Duration::from_std(CHALLENGE_TTL).unwrap(),
            created_at: now,
        };
        self.passkey_challenges.create(&challenge).await?;

        let options_json = serde_json::to_value(&ccr)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        Ok((challenge_id, options_json))
    }

    /// 登録完了。
    pub async fn complete(
        &self,
        sso_session_id: &str,
        challenge_id: Uuid,
        name: &str,
        credential_value: serde_json::Value,
    ) -> Result<Uuid, PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        let now = self.clock.now();

        // チャレンジを取得して消費する。
        let challenge = self
            .passkey_challenges
            .find_by_id(challenge_id)
            .await?
            .ok_or(PasskeyRegistrationError::ChallengeNotFound)?;

        if challenge.expires_at <= now || challenge.user_id != Some(user_id) {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return Err(PasskeyRegistrationError::ChallengeNotFound);
        }

        // チャレンジ状態を復元する。
        let reg_state: PasskeyRegistration =
            serde_json::from_str(&challenge.state_json)
                .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        // ブラウザからのクレデンシャルをデシリアライズして検証する。
        let reg_credential: RegisterPublicKeyCredential =
            serde_json::from_value(credential_value)
                .map_err(|e| PasskeyRegistrationError::InvalidCredential(e.to_string()))?;

        let passkey = self
            .webauthn
            .finish_registration(&reg_credential, &reg_state)
            .map_err(PasskeyRegistrationError::InvalidCredential)?;

        // credential_id は base64url エンコードして保存する。
        let credential_id =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, passkey.cred_id());
        let passkey_json = serde_json::to_string(&passkey)
            .map_err(|e| PasskeyRegistrationError::Internal(e.to_string()))?;

        let cred_id = Uuid::new_v4();
        let cred = WebAuthnCredential {
            id: cred_id,
            user_id,
            credential_id,
            passkey_json,
            name: name.trim().to_string(),
            created_at: now,
            last_used_at: None,
        };

        // チャレンジを先に削除してから登録（失敗してもチャレンジは使えなくなる）。
        let _ = self.passkey_challenges.delete(challenge_id).await;

        self.webauthn_credentials
            .create(&cred)
            .await
            .map_err(|e| {
                if matches!(e, DomainError::Conflict(_)) {
                    PasskeyRegistrationError::DuplicateCredential
                } else {
                    PasskeyRegistrationError::Internal(e.to_string())
                }
            })?;

        Ok(cred_id)
    }

    /// クレデンシャルを削除する。
    pub async fn delete(
        &self,
        sso_session_id: &str,
        credential_id: Uuid,
    ) -> Result<(), PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        self.webauthn_credentials
            .delete(credential_id, user_id)
            .await?;
        Ok(())
    }

    /// 登録済みクレデンシャル一覧を返す。
    pub async fn list(
        &self,
        sso_session_id: &str,
    ) -> Result<Vec<CredentialInfo>, PasskeyRegistrationError> {
        let (user_id, _) = self.resolve_user(sso_session_id).await?;
        let creds = self.webauthn_credentials.list_by_user_id(user_id).await?;
        Ok(creds
            .into_iter()
            .map(|c| CredentialInfo {
                id: c.id,
                name: c.name,
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect())
    }

    /// SSO Cookie 値からユーザー ID とセッションハッシュを解決する。
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
