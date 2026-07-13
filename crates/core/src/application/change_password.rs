//! パスワード変更ユースケース（ADR-0009 §5）。
//!
//! `LoginService` が検出した `must_change_password`（`LoginOutcome::PasswordChangeRequired`）を受けて、
//! ログイン中の `auth_session_id`（パスワード検証済み状態）を用いて新パスワードを設定する。
//! 「ログイン済みユーザーが現行パスワードで認証したうえで新パスワードを設定する」フローに限定する
//! （ADR-0009 §5）ため、現行パスワードの再入力を要求する。
//!
//! 成功後の SSO 発行 → 同意チェック → code 発行は `LoginService`／`MfaLoginService` と共通のフロー
//! （`CodeIssuanceService` を再利用）。`must_change_password` は自動生成パスワードでの作成時のみ
//! 付与され、その時点のユーザーは一度もログインしていない（自己登録 MFA は SSO が必要なため未設定）
//! ため、変更後に改めて MFA 判定へ進む必要はない。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use chrono::Duration;
use std::sync::Arc;

pub struct ChangePasswordCommand {
    pub auth_session_id: Option<String>,
    pub current_password: String,
    pub new_password: String,
    pub csrf_token: String,
}

pub enum ChangePasswordOutcome {
    /// 変更成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        sso_session_id: String,
    },
    /// 変更成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// AuthSession が無い・期限切れ・パスワード変更待ち状態でない（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal(String),
}

pub struct ChangePasswordService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    csrf_secret: [u8; 32],
}

impl ChangePasswordService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            auth_sessions,
            users,
            sso_sessions,
            client_consents,
            code_issuance,
            hasher,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            csrf_secret,
        }
    }

    pub async fn change(
        &self,
        tenant: TenantContext,
        cmd: ChangePasswordCommand,
        ctx: &RequestContext,
    ) -> ChangePasswordOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. auth_session_id から AuthSession を取得する（フローのテナントに限る）。
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return ChangePasswordOutcome::SessionExpired;
        };
        let session = match self.auth_sessions.find_by_id(tenant_id, session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return ChangePasswordOutcome::SessionExpired;
        }

        // 2. パスワード変更待ち状態か確認する（password_verified_at が設定されている必要がある）。
        let Some(user_id) = session.authenticated_user_id else {
            return ChangePasswordOutcome::SessionExpired;
        };
        if session.password_verified_at.is_none() {
            return ChangePasswordOutcome::SessionExpired;
        }

        // 3. CSRF トークン検証（login_csrf_token と同じ導出を使う）。
        if idp_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret) != cmd.csrf_token {
            return ChangePasswordOutcome::CsrfMismatch;
        }

        let client_id = session.client_id.clone();

        // 4. ユーザーを取得して有効・変更待ちであることを確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !user.is_active() || !user.must_change_password {
            // 変更不要な状態でこのエンドポイントに来るのは想定外（多重送信等）。fail-closed。
            return ChangePasswordOutcome::SessionExpired;
        }

        // 5. 現行パスワードを検証する。
        let verified = match self.hasher.verify(&cmd.current_password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            return ChangePasswordOutcome::InvalidCurrentPassword;
        }

        // 6. 新パスワードの強度を検証し、ハッシュ化して保存する。
        if validate_password_strength(&cmd.new_password).is_err() {
            return ChangePasswordOutcome::WeakPassword;
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return ChangePasswordOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 7. auth_time を設定する（パスワード変更完了時刻を認証時刻とする）。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user.id, now)
            .await
        {
            return ChangePasswordOutcome::Internal(e.to_string());
        }

        // 8. SSO セッション発行。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession {
            session_hash: crypto::sha256_hex(&sso_session_id),
            user_id: user.id,
            auth_time: now,
            idle_expires_at: now + self.sso_idle_ttl,
            absolute_expires_at: now + self.sso_absolute_ttl,
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return ChangePasswordOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
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
                Some(user.id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 9. 同意チェック（`openid` は暗黙同意）。
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
                .find(tenant_id, user.id, &client_id)
                .await
            {
                Ok(Some(consent)) => consent.covers(&scopes_needing_consent),
                Ok(None) => false,
                Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return ChangePasswordOutcome::ConsentRequired {
                auth_session_id: session.id,
                sso_session_id,
            };
        }

        // 10. code 発行。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id: user.id,
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
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };

        // 11. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after password change");
        }

        ChangePasswordOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
        }
    }
}
