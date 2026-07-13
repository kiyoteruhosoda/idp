//! RP-initiated Logout のユースケース（F4、設計仕様 §9 拡張）。
//!
//! OIDC RP-initiated Logout 1.0 spec に基づき、SSO セッションを終了し
//! `sso_session.terminated` 監査イベントを記録する。
//! back-channel / front-channel の通知に必要な情報を返すが、
//! 実際の HTTP 送信は Presentation 層（ハンドラ）が行う。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::issuer::tenant_issuer;
use crate::domain::repositories::{
    AuthorizationCodeRepository, ClientRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use std::sync::Arc;
use uuid::Uuid;

/// back-channel logout 通知先の 1 クライアント。
#[derive(Debug, Clone)]
pub struct BackchannelTarget {
    pub client_id: String,
    pub backchannel_logout_uri: String,
}

/// RP-initiated logout の結果。Presentation がこれを元に通知とリダイレクトを実施する。
pub struct LogoutResult {
    /// ログアウトしたユーザーの `sub`（back-channel logout token に使用）。
    pub user_sub: Option<String>,
    /// ログアウトしたユーザーの内部 ID（監査用）。
    pub user_id: Option<Uuid>,
    /// back-channel logout 通知先（`backchannel_logout_uri` を持つ全クライアント）。
    pub backchannel_targets: Vec<BackchannelTarget>,
    /// front-channel logout URI 群（`frontchannel_logout_uri` を持つ全クライアント）。
    pub frontchannel_uris: Vec<String>,
    /// 検証済みの post-logout redirect URI（未指定または検証失敗の場合は `None`）。
    pub post_logout_redirect_uri: Option<String>,
}

pub struct LogoutService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clients: Arc<dyn ClientRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer。front-channel logout の `iss` はテナント毎に合成する（ADR-0009 §6）。
    base_issuer: String,
}

impl LogoutService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn ClientRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clients,
            codes,
            audit,
            clock,
            base_issuer,
        }
    }

    /// RP-initiated logout を処理する。
    ///
    /// - `sso_session_id`: SSO Cookie の値（平文）。`None` なら既にログアウト済み扱い。
    /// - `client_id_hint`: `client_id` パラメータ（post_logout_redirect_uri の検証に使う）。
    /// - `post_logout_redirect_uri`: RP が指定したリダイレクト先。登録済みのもののみ許可。
    #[allow(clippy::too_many_arguments)]
    pub async fn logout(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
        client_id_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        ctx: &RequestContext,
    ) -> LogoutResult {
        let now = self.clock.now();

        // 1. SSO セッションの特定と終了。
        let (user_id, user_sub) = if let Some(sid) = sso_session_id.filter(|s| !s.is_empty()) {
            let hash = crypto::sha256_hex(sid);
            let session = match self.sso_sessions.find_by_hash(&hash).await {
                Ok(Some(s)) => s,
                _ => {
                    // セッション不明または DB エラー → ログアウト済み扱いで続行。
                    return LogoutResult {
                        user_sub: None,
                        user_id: None,
                        backchannel_targets: vec![],
                        frontchannel_uris: vec![],
                        post_logout_redirect_uri: None,
                    };
                }
            };
            let uid = session.user_id;

            // SSO セッション削除。
            if let Err(e) = self.sso_sessions.delete(&hash).await {
                tracing::warn!(error = %e, "failed to delete sso session on logout");
            }

            // 未消費の authorization code を失効。
            if let Err(e) = self.codes.revoke_all_active_for_user(uid, now).await {
                tracing::warn!(error = %e, "failed to revoke active auth codes on logout");
            }

            // ユーザーの sub を取得（logout token に使う）。
            let sub = match self.users.find_by_id(uid).await {
                Ok(Some(u)) => Some(u.sub.to_string()),
                _ => None,
            };

            self.audit
                .record(
                    AuditEventType::SsoSessionTerminated,
                    AuditResult::Success,
                    Some(tenant.tenant_id()),
                    Some(uid),
                    None,
                    Some("rp_initiated_logout"),
                    ctx,
                )
                .await;

            (Some(uid), sub)
        } else {
            (None, None)
        };

        // 2. テナントの全クライアントを取得して logout endpoint を持つものを収集
        //    （logout 通知・redirect 検証はフローのテナント内に限る）。
        let clients = match self.clients.list(tenant.tenant_id()).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list clients for logout notification");
                vec![]
            }
        };

        let backchannel_targets: Vec<BackchannelTarget> = clients
            .iter()
            .filter_map(|c| {
                c.backchannel_logout_uri
                    .as_ref()
                    .map(|uri| BackchannelTarget {
                        client_id: c.client_id.clone(),
                        backchannel_logout_uri: uri.clone(),
                    })
            })
            .collect();

        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        let frontchannel_uris: Vec<String> = clients
            .iter()
            .filter_map(|c| {
                c.frontchannel_logout_uri.as_ref().map(|uri| {
                    // OpenID Connect Front-Channel Logout spec: iss を query param に付与。
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    let encoded_iss = percent_encoding::utf8_percent_encode(
                        &issuer,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string();
                    format!("{uri}{sep}iss={encoded_iss}")
                })
            })
            .collect();

        // 3. post_logout_redirect_uri の検証。
        let post_logout_redirect_uri = post_logout_redirect_uri.and_then(|uri| {
            if uri.is_empty() {
                return None;
            }
            // client_id_hint が指定されていれば、そのクライアントの登録 URI を確認。
            if let Some(cid) = client_id_hint {
                let ok = clients
                    .iter()
                    .find(|c| c.client_id == cid)
                    .map(|c| c.allows_post_logout_redirect_uri(uri))
                    .unwrap_or(false);
                if ok {
                    return Some(uri.to_string());
                }
                // client_id_hint があるが一致しない → 無視。
                None
            } else {
                // client_id_hint 無し → いずれかのクライアントに登録されていれば許可。
                let ok = clients
                    .iter()
                    .any(|c| c.allows_post_logout_redirect_uri(uri));
                if ok {
                    Some(uri.to_string())
                } else {
                    None
                }
            }
        });

        let _ = user_id; // suppress unused warning
        LogoutResult {
            user_sub,
            user_id,
            backchannel_targets,
            frontchannel_uris,
            post_logout_redirect_uri,
        }
    }
}
