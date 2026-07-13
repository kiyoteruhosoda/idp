//! Passkey（WebAuthn discoverable credentials）認証ユースケース。
//!
//! パスワード入力なしで Passkey だけでログインする。認証フロー:
//! 1. `begin()` — discoverable チャレンジを生成して options JSON を返す。
//! 2. `complete()` — ブラウザからのクレデンシャルを検証し、SSO セッション発行 → code 発行。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, PasskeyChallengeRepository,
    SsoSessionRepository, UserRepository, WebAuthnCredentialRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use crate::infrastructure::webauthn::WebAuthnService;
use chrono::Duration;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PublicKeyCredential,
};

/// チャレンジの有効期限（5 分）。
const CHALLENGE_TTL: StdDuration = StdDuration::from_secs(300);

#[derive(Debug)]
pub enum PasskeyAuthOutcome {
    /// 認証成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        sso_session_id: String,
    },
    /// 認証成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// チャレンジが見つからない・期限切れ。
    ChallengeNotFound,
    /// AuthSession が無い・期限切れ（OIDC フローをやり直し）。
    SessionExpired,
    /// クレデンシャルが無効。
    InvalidCredential,
    /// 内部エラー。
    Internal(String),
}

pub struct PasskeyAuthenticationService {
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    webauthn: Arc<WebAuthnService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
}

impl PasskeyAuthenticationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        webauthn: Arc<WebAuthnService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: StdDuration,
        sso_absolute_ttl: StdDuration,
    ) -> Self {
        Self {
            webauthn_credentials,
            passkey_challenges,
            auth_sessions,
            users,
            sso_sessions,
            client_consents,
            code_issuance,
            webauthn,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
        }
    }

    /// 認証開始。`auth_session_id` は OIDC フローを継続するために必要。
    ///
    /// 返り値: `(challenge_id, options_json)`
    pub async fn begin(
        &self,
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
            challenge_type: PasskeyChallengeType::Authenticate,
            state_json,
            auth_session_id: auth_session_id.map(|s| s.to_string()),
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

    /// 認証完了。
    pub async fn complete(
        &self,
        tenant: TenantContext,
        challenge_id: Uuid,
        credential_value: serde_json::Value,
        ctx: &RequestContext,
    ) -> PasskeyAuthOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. チャレンジを取得して消費する。
        let challenge = match self.passkey_challenges.find_by_id(challenge_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return PasskeyAuthOutcome::ChallengeNotFound,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if challenge.expires_at <= now {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return PasskeyAuthOutcome::ChallengeNotFound;
        }
        // チャレンジを先に削除（リプレイ防止）。
        if let Err(e) = self.passkey_challenges.delete(challenge_id).await {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }

        // 2. DiscoverableAuthentication 状態を復元する。
        let auth_state: DiscoverableAuthentication =
            match serde_json::from_str(&challenge.state_json) {
                Ok(s) => s,
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            };

        // 3. ブラウザからのクレデンシャルをデシリアライズする。
        let public_key_credential: PublicKeyCredential =
            match serde_json::from_value(credential_value) {
                Ok(c) => c,
                Err(_) => return PasskeyAuthOutcome::InvalidCredential,
            };

        // 4. credential_id から登録済みクレデンシャルを引く。
        let stored_cred = match self
            .webauthn_credentials
            .find_by_credential_id(public_key_credential.id.as_str())
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return PasskeyAuthOutcome::InvalidCredential,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        let passkey: Passkey = match serde_json::from_str(&stored_cred.passkey_json) {
            Ok(p) => p,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        let user_id = stored_cred.user_id;
        let cred_row_id = stored_cred.id;

        // 5. WebAuthn 検証。
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
                    return PasskeyAuthOutcome::InvalidCredential;
                }
            };

        // 6. sign_count を更新して passkey_json を保存する（更新があれば DB に反映する）。
        let mut updated_passkey = passkey;
        if updated_passkey
            .update_credential(&auth_result)
            .unwrap_or(false)
        {
            let new_json = match serde_json::to_string(&updated_passkey) {
                Ok(j) => j,
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            };
            if let Err(e) = self
                .webauthn_credentials
                .update_passkey(cred_row_id, &new_json, now)
                .await
            {
                return PasskeyAuthOutcome::Internal(e.to_string());
            }
        }

        // 7. ユーザーを取得して有効確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return PasskeyAuthOutcome::InvalidCredential,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if !user.is_active() {
            return PasskeyAuthOutcome::Internal("user not active".to_string());
        }

        // 8. AuthSession を取得して OIDC フローを継続する。
        let Some(auth_session_id) = &challenge.auth_session_id else {
            return PasskeyAuthOutcome::Internal("no auth_session_id in challenge".to_string());
        };
        let session = match self
            .auth_sessions
            .find_by_id(tenant_id, auth_session_id)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return PasskeyAuthOutcome::SessionExpired,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return PasskeyAuthOutcome::SessionExpired;
        }

        let client_id = session.client_id.clone();

        // 9. auth_time を設定する。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user_id, now)
            .await
        {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }

        // 10. SSO セッション発行。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession {
            session_hash: crypto::sha256_hex(&sso_session_id),
            user_id,
            auth_time: now,
            idle_expires_at: now + self.sso_idle_ttl,
            absolute_expires_at: now + self.sso_absolute_ttl,
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::LoginSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 11. 同意チェック（`openid` は暗黙同意）。
        let scopes_needing_consent: Vec<String> = session
            .scope
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect();
        let consented = if scopes_needing_consent.is_empty() {
            true
        } else {
            match self
                .client_consents
                .find(tenant_id, user_id, &client_id)
                .await
            {
                Ok(Some(consent)) => consent.covers(&scopes_needing_consent),
                Ok(None) => false,
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return PasskeyAuthOutcome::ConsentRequired {
                auth_session_id: session.id,
                sso_session_id,
            };
        }

        // 12. code 発行。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id,
                    client_id: client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    scope: session.scope.clone(),
                    nonce: session.nonce.clone(),
                    auth_time: now,
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method,
                },
                ctx,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        // 13. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after passkey auth");
        }

        PasskeyAuthOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
        }
    }
}
