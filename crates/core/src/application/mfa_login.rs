//! MFA ログイン検証ユースケース。
//!
//! パスワード認証は `LoginService` で完了済み（`auth_sessions.password_verified_at` が設定されている）。
//! 本サービスは TOTP コードを検証し、成功時に SSO セッション発行 → 同意チェック → code 発行を行う。
//! フロー後半は `LoginService` と共通（`CodeIssuanceService` を再利用）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository, TotpSecretRepository,
    UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use chrono::Duration;
use std::sync::Arc;
use uuid::Uuid;

pub enum MfaLoginOutcome {
    /// TOTP 検証成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        sso_session_id: String,
        /// ユーザーの表示言語設定（MT20）。web は `lang` Cookie をこの値で上書きする。
        user_language: Option<String>,
    },
    /// TOTP 検証成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// AuthSession が無い・期限切れ・MFA pending 状態でない（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// TOTP コードが不正。
    InvalidCode,
    /// 内部エラー。
    Internal(String),
}

pub struct MfaLoginCommand {
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
}

pub struct MfaLoginService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    csrf_secret: [u8; 32],
}

impl MfaLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            auth_sessions,
            totp_secrets,
            users,
            sso_sessions,
            client_consents,
            code_issuance,
            audit,
            clock,
            key_encryption_key,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            csrf_secret,
        }
    }

    pub async fn verify(
        &self,
        tenant: TenantContext,
        cmd: MfaLoginCommand,
        ctx: &RequestContext,
    ) -> MfaLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. auth_session_id から AuthSession を取得する（フローのテナントに限る）。
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return MfaLoginOutcome::SessionExpired;
        };
        let session = match self.auth_sessions.find_by_id(tenant_id, session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return MfaLoginOutcome::SessionExpired;
        }

        // 2. MFA pending 状態か確認する（password_verified_at が設定されている必要がある）。
        let Some(user_id) = session.authenticated_user_id else {
            return MfaLoginOutcome::SessionExpired;
        };
        if session.password_verified_at.is_none() {
            return MfaLoginOutcome::SessionExpired;
        }

        // 3. CSRF トークン検証（login_csrf_token と同じ導出を使う）。
        if idp_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret) != cmd.csrf_token {
            return MfaLoginOutcome::CsrfMismatch;
        }

        let client_id = session.client_id.clone();

        // 4. ユーザーを取得して有効確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if !user.is_active() {
            return MfaLoginOutcome::Internal("user not active".to_string());
        }

        // 5. TOTP シークレットを取得して検証する。
        let totp_record = match self.totp_secrets.find_by_user_id(user_id).await {
            Ok(Some(r)) if r.is_confirmed() => r,
            Ok(_) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        let secret_bytes =
            match crypto::decrypt(&totp_record.secret_encrypted, &self.key_encryption_key) {
                Ok(b) => b,
                Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
            };
        let valid = match verify_totp_code(&secret_bytes, &cmd.totp_code) {
            Ok(v) => v,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if !valid {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&client_id),
                    Some("invalid_totp"),
                    ctx,
                )
                .await;
            return MfaLoginOutcome::InvalidCode;
        }

        // 6. auth_time を設定する（MFA 完了時刻を認証時刻とする）。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user_id, now)
            .await
        {
            return MfaLoginOutcome::Internal(e.to_string());
        }

        // 7. SSO セッション発行。
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
            return MfaLoginOutcome::Internal(e.to_string());
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

        // 8. 同意チェック（`openid` は暗黙同意）。
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
                Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return MfaLoginOutcome::ConsentRequired {
                auth_session_id: session.id,
                sso_session_id,
            };
        }

        // 9. code 発行。
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
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };

        // 10. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after MFA code issuance");
        }

        MfaLoginOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// 認証不要なユーザー（TOTP 未設定）が MFA エンドポイントへ来た場合の user_id 取得補助。
    /// `auth_session_id` が MFA pending 状態かを確認するだけ。
    pub async fn has_mfa_pending(&self, tenant: TenantContext, auth_session_id: &str) -> bool {
        let Ok(Some(session)) = self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await
        else {
            return false;
        };
        session.password_verified_at.is_some() && session.authenticated_user_id.is_some()
    }
}

/// `user_id` のユーザーが確認済み TOTP を持つか（他サービスからの問い合わせ用）。
pub async fn user_has_confirmed_totp(
    totp_secrets: &dyn TotpSecretRepository,
    user_id: Uuid,
) -> Result<bool, crate::domain::error::DomainError> {
    Ok(totp_secrets
        .find_by_user_id(user_id)
        .await?
        .map(|s| s.is_confirmed())
        .unwrap_or(false))
}
