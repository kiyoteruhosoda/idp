//! 同意（Consent）ユースケース（F3: 設計仕様 §9.2）。
//!
//! ユーザーがクライアントに対して scope の同意を付与または拒否する。
//! 同意付与後は authorization code を発行して RP へリダイレクトする。
//! 同意拒否時は `access_denied` エラーを RP へリダイレクトする。
//!
//! 認証を終えた `AuthSession` を同意セッションとして再利用する。
//! code 発行後は AuthSession を削除する（ログインフローと同じ）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::AuthorizationDispatch;
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::{AuthSession, AuthSessionId};
use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::clock::Clock;
use crate::domain::consent::ClientConsent;
use crate::domain::error::{DomainError, OAuthErrorCode};
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, ClientRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// 同意画面への遷移前に必要な表示情報。
#[derive(Debug)]
pub struct ConsentInfo {
    pub auth_session_id: String,
    pub client_name: String,
    pub client_id: String,
    /// 同意を求めるスコープ（`openid` は除く）。
    pub requested_scopes: Vec<String>,
    /// この認可要求の `redirect_uri`（登録済みの値と完全一致したもの）。
    ///
    /// web が同意画面の CSP `form-action` に許可するオリジンの出所。同意フォームの送信は
    /// RP へのリダイレクトで終わり、Chrome は `form-action` をフォーム送信後のリダイレクト先にも
    /// 適用するため、ここを渡さないとブラウザが RP へ戻れない。
    pub redirect_uri: String,
}

pub enum ConsentOutcome {
    /// 同意付与・code 発行成功。`redirect_uri?code=...&state=...` へ 302。
    Approved {
        location: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        form_post: Option<Vec<(String, String)>>,
    },
    /// 同意拒否。`query` なら `location` へ 302、`form_post` なら `location` へ hidden フィールドを
    /// POST する（エラーも成功と同じ `response_mode` で返す。G12）。
    Denied {
        location: String,
        form_post: Option<Vec<(String, String)>>,
    },
    /// 同意は付与できたが、このアプリの利用が許可されていない（ADR-0054）。⚠ **RP へ戻さない。**
    /// SSO Cookie はこの経路へ来る前に発行済みなので、ここでは画面を出すだけでよい。
    ApplicationNotPermitted {
        /// 画面に出すアプリ名。
        application_name: String,
    },
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
    /// `auth_session_id` の AuthSession が存在し、利用者を特定できていることを確認する。
    pub async fn info(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Result<Option<ConsentInfo>, DomainError> {
        let Some(session) = self.live_session(tenant, auth_session_id).await? else {
            return Ok(None);
        };
        if session.identified_user().is_none() {
            return Ok(None);
        }
        let request = session.request();

        // クライアント情報を取得する（表示名が必要）。
        let client_name = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), request.client_id())
            .await?
        {
            Some(c) => c.app_name,
            None => request.client_id().to_string(),
        };

        Ok(Some(ConsentInfo {
            auth_session_id: auth_session_id.to_string(),
            client_name,
            client_id: request.client_id().to_string(),
            requested_scopes: request.scopes_needing_consent(),
            redirect_uri: request.redirect_uri().to_string(),
        }))
    }

    /// 同意を付与して authorization code を発行する。
    pub async fn approve(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let session = match self.live_session(tenant, auth_session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };
        // 同意が code を発行する根拠は「このフローで完了した認証」だけ。
        let Some(authentication) = session.completed_authentication().cloned() else {
            return ConsentOutcome::SessionExpired;
        };
        let request = session.request();
        let now = self.clock.now();

        // 同意レコードを UPSERT する。
        let consent = ClientConsent {
            user_id: authentication.user_id(),
            tenant_id: tenant.tenant_id(),
            client_id: request.client_id().to_string(),
            scopes: request.scope().to_vec(),
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
                Some(authentication.user_id()),
                Some(request.client_id()),
                None,
                ctx,
            )
            .await;

        // authorization code を発行する。ログイン時に記録した `sid`（G5）と認証方式（ADR-0043）は、
        // 同意画面を挟むとここが唯一の入手経路になる（どちらも `authentication` に入っている）。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    request: request.clone(),
                    authentication,
                },
                ctx,
            )
            .await
        {
            Ok(CodeIssuance::Issued(code)) => code,
            // 同意は通っているが、このアプリの利用が許可されていない（ADR-0054）。RP へは戻さない。
            Ok(CodeIssuance::ApplicationDenied { application_name }) => {
                return ConsentOutcome::ApplicationNotPermitted { application_name }
            }
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };

        // AuthSession を削除する（code 発行完了）。
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent");
        }

        let dispatch = AuthorizationDispatch::from(request.success_response(&code));
        ConsentOutcome::Approved {
            location: dispatch.location,
            form_post: dispatch.form_post,
        }
    }

    /// 同意を拒否して RP にエラーリダイレクトする。
    pub async fn deny(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let session = match self.live_session(tenant, auth_session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::ConsentDenied,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                session.identified_user(),
                Some(session.client_id()),
                Some("user_denied"),
                ctx,
            )
            .await;

        // AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent denial");
        }

        let dispatch = AuthorizationDispatch::from(
            session
                .request()
                .error_response(OAuthErrorCode::AccessDenied, "user denied consent"),
        );
        ConsentOutcome::Denied {
            location: dispatch.location,
            form_post: dispatch.form_post,
        }
    }

    /// 期限内の AuthSession を引く（期限切れはその場で消して `None`）。
    async fn live_session(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Result<Option<AuthSession>, DomainError> {
        let Some(id) = AuthSessionId::from_presented(auth_session_id) else {
            return Ok(None);
        };
        let Some(session) = self
            .auth_sessions
            .find(tenant.tenant_id(), &id.hash())
            .await?
        else {
            return Ok(None);
        };
        if session.is_expired_at(self.clock.now()) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return Ok(None);
        }
        Ok(Some(session))
    }
}

/// 利用者がこの認可要求の scope すべてに同意済みか。
///
/// `openid` は暗黙同意なので、それしか要求していなければ同意の記録を見ずに `true`
/// （記録を引かないので、その場合は保存先の失敗も起きない）。
pub async fn consent_is_granted(
    consents: &dyn ClientConsentRepository,
    tenant_id: TenantId,
    user_id: Uuid,
    request: &AuthorizationRequest,
) -> Result<bool, DomainError> {
    let needed = request.scopes_needing_consent();
    if needed.is_empty() {
        return Ok(true);
    }
    Ok(consents
        .find(tenant_id, user_id, request.client_id())
        .await?
        .is_some_and(|consent| consent.covers(&needed)))
}
