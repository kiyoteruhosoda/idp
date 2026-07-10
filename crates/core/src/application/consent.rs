//! 同意（Consent）ユースケース（F3: 設計仕様 §9.2）。
//!
//! ユーザーがクライアントに対して scope の同意を付与または拒否する。
//! 同意付与後は authorization code を発行して RP へリダイレクトする。
//! 同意拒否時は `access_denied` エラーを RP へリダイレクトする。
//!
//! `AuthSession`（`authenticated_user_id` 設定済み）を同意セッションとして再利用する。
//! code 発行後は AuthSession を削除する（ログインフローと同じ）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::{code_redirect, error_redirect_with_state};
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::consent::ClientConsent;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, ClientRepository,
};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

/// 同意画面への遷移前に必要な表示情報。
#[derive(Debug)]
pub struct ConsentInfo {
    pub auth_session_id: String,
    pub client_name: String,
    pub client_id: String,
    /// 同意を求めるスコープ（`openid` は除く）。
    pub requested_scopes: Vec<String>,
}

pub enum ConsentOutcome {
    /// 同意付与・code 発行成功。`redirect_uri?code=...&state=...` へ 302。
    Approved { location: String },
    /// 同意拒否。`redirect_uri?error=access_denied&state=...` へ 302。
    Denied { location: String },
    /// AuthSession が無い・期限切れ・認証済みユーザーが未設定（`/authorize` からやり直し）。
    SessionExpired,
    /// api 内部エラー。
    Internal(String),
}

pub struct ConsentService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    clients: Arc<dyn ClientRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl ConsentService {
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        clients: Arc<dyn ClientRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            auth_sessions,
            client_consents,
            clients,
            code_issuance,
            audit,
            clock,
        }
    }

    /// 同意画面への表示情報を返す。
    ///
    /// `auth_session_id` の AuthSession が存在し、認証済みユーザーが設定されていることを確認する。
    pub async fn info(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Result<Option<ConsentInfo>, crate::domain::error::DomainError> {
        let now = self.clock.now();
        let Some(session) = self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await?
        else {
            return Ok(None);
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return Ok(None);
        }
        if session.authenticated_user_id.is_none() {
            return Ok(None);
        }

        // クライアント情報を取得する（表示名が必要）。
        let client_name = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), &session.client_id)
            .await?
        {
            Some(c) => c.app_name.clone(),
            None => session.client_id.clone(),
        };

        // 同意を求めるスコープから `openid` を除く（暗黙同意）。
        let requested_scopes: Vec<String> = session
            .scope
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect();

        Ok(Some(ConsentInfo {
            auth_session_id: session.id,
            client_name,
            client_id: session.client_id,
            requested_scopes,
        }))
    }

    /// 同意を付与して authorization code を発行する。
    pub async fn approve(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let now = self.clock.now();

        let session = match self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return ConsentOutcome::SessionExpired;
        }
        let Some(user_id) = session.authenticated_user_id else {
            return ConsentOutcome::SessionExpired;
        };
        let Some(auth_time) = session.auth_time else {
            return ConsentOutcome::SessionExpired;
        };

        // 同意レコードを UPSERT する。
        let consent = ClientConsent {
            user_id,
            tenant_id: tenant.tenant_id(),
            client_id: session.client_id.clone(),
            scopes: session.scope.clone(),
            granted_at: now,
            updated_at: now,
        };
        if let Err(e) = self.client_consents.upsert(&consent).await {
            return ConsentOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::ConsentGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                Some(&session.client_id),
                None,
                ctx,
            )
            .await;

        // authorization code を発行する。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id,
                    client_id: session.client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    scope: session.scope.clone(),
                    nonce: session.nonce.clone(),
                    auth_time,
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method,
                },
                ctx,
            )
            .await
        {
            Ok(code) => code,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };

        // AuthSession を削除する（code 発行完了）。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent");
        }

        ConsentOutcome::Approved {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
        }
    }

    /// 同意を拒否して RP にエラーリダイレクトする。
    pub async fn deny(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let now = self.clock.now();

        let session = match self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return ConsentOutcome::SessionExpired;
        }
        let user_id = session.authenticated_user_id;

        self.audit
            .record(
                AuditEventType::ConsentDenied,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                user_id,
                Some(&session.client_id),
                Some("user_denied"),
                ctx,
            )
            .await;

        // AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent denial");
        }

        ConsentOutcome::Denied {
            location: error_redirect_with_state(
                &session.redirect_uri,
                OAuthErrorCode::AccessDenied,
                "user denied consent",
                Some(&session.state),
            ),
        }
    }
}
