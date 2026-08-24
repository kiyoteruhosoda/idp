//! Token 失効エンドポイントのユースケース（F5: RFC 7009 Token Revocation）。
//!
//! - `refresh_token`: DB の `revoked_at` を設定して失効させる。
//! - `access_token`: JWT の jti を `revoked_access_tokens` テーブルに追加して即時失効を実現する。
//! - RFC 7009 §2.2: 失効済み・不存在でも 200 を返す（呼び出し側は常に成功扱い）。
//! - confidential client は認証が必要（方式はクライアントの登録値。`client_secret_basic` /
//!   `client_secret_post`）。public client は認証なし。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::client_authentication::{
    ClientAuthError, ClientAuthFailure, ClientAuthOutcome, ClientAuthenticator,
    PresentedClientCredentials,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    ClientRepository, RefreshTokenRepository, RevokedAccessTokenRepository,
};
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

/// `/revoke` のエラー（RFC 7009 §2.2.1 に準じる）。
#[derive(Debug)]
pub struct RevocationError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl RevocationError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct RevocationService {
    clients: Arc<dyn ClientRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    client_auth: Arc<ClientAuthenticator>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl RevocationService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        client_auth: Arc<ClientAuthenticator>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            refresh_tokens,
            revoked_access_tokens,
            client_auth,
            audit,
            clock,
        }
    }

    /// トークンを失効させる。RFC 7009 §2.2: 常に 200 を返す想定（エラーは client 認証失敗のみ）。
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        token: &str,
        token_type_hint: Option<&str>,
        credentials: &PresentedClientCredentials,
        ctx: &RequestContext,
    ) -> Result<(), RevocationError> {
        if token.is_empty() {
            return Ok(());
        }

        // Client 認証（フローのテナントに属する client のみ解決する）。
        let client = match self.load_client(tenant, credentials, ctx).await {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let now = self.clock.now();

        // token_type_hint に従って試みるが、どちらでも試す（RFC 7009 §2.1）。
        match token_type_hint {
            Some("access_token") => {
                if !self.try_revoke_access_token(token, now).await {
                    let _ = self.try_revoke_refresh_token(token, now, &client).await;
                }
            }
            _ => {
                // hint なし or "refresh_token": refresh_token から試みる。
                if !self.try_revoke_refresh_token(token, now, &client).await {
                    let _ = self.try_revoke_access_token(token, now).await;
                }
            }
        }

        self.audit
            .record(
                AuditEventType::RefreshTokenUsed,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                None,
                Some(&client.client_id),
                Some("revocation"),
                ctx,
            )
            .await;

        Ok(())
    }

    /// refresh_token の失効を試みる。失効させたら `true`。
    ///
    /// **該当行が無かった場合は `false`**。ここで `true` を返すと、`token_type_hint` を伴わない
    /// access_token の失効要求が「refresh_token として失効済み」と誤判定され、access_token 側の
    /// 失効が一度も試されないまま 200 が返る（RFC 7009 §2.1 は hint が外れたら他の種別も試すことを
    /// 求めている）。
    async fn try_revoke_refresh_token(
        &self,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
        _client: &Client,
    ) -> bool {
        let hash = crypto::sha256_hex(token);
        match self.refresh_tokens.revoke(&hash, now).await {
            Ok(revoked) => revoked > 0,
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke refresh token");
                false
            }
        }
    }

    /// access_token（JWT）の失効を試みる。jti を抽出して blocklist に追加。成功したら `true`。
    async fn try_revoke_access_token(
        &self,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        // JWT ヘッダ・ペイロードをデコードして jti と exp を取得（署名検証は省略）。
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() < 2 {
            return false;
        }
        let payload = match base64_decode_no_pad(parts[1]) {
            Some(p) => p,
            None => return false,
        };
        let claims: serde_json::Value = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let jti = match claims["jti"].as_str() {
            Some(j) if !j.is_empty() => j.to_string(),
            _ => return false,
        };
        let exp = claims["exp"].as_i64().unwrap_or(0);
        let expires_at = chrono::DateTime::from_timestamp(exp, 0).unwrap_or(now);

        let revoked = RevokedAccessToken {
            jti,
            revoked_at: now,
            expires_at,
        };
        match self.revoked_access_tokens.revoke(&revoked).await {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke access token jti");
                false
            }
        }
    }

    /// Client を検索し、confidential client の場合は secret を検証する。
    ///
    /// 照合する secret の選択（Basic か body か）は登録された `token_endpoint_auth_method` に
    /// 従う（`client_authentication` に集約。G3）。
    async fn load_client(
        &self,
        tenant: TenantContext,
        credentials: &PresentedClientCredentials,
        ctx: &RequestContext,
    ) -> Result<Client, RevocationError> {
        credentials.ensure_single_method().map_err(|_| {
            RevocationError::new(
                OAuthErrorCode::InvalidRequest,
                "client credentials must be presented with a single authentication method",
            )
        })?;
        let client_id = credentials.resolve_client_id().map_err(|failure| {
            RevocationError::new(
                match failure {
                    ClientAuthFailure::ClientIdMismatch => OAuthErrorCode::InvalidRequest,
                    _ => OAuthErrorCode::InvalidClient,
                },
                "client_id is required",
            )
        })?;

        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), &client_id)
            .await
            .map_err(|e| RevocationError::new(OAuthErrorCode::ServerError, &e.to_string()))?
            .ok_or_else(|| RevocationError::new(OAuthErrorCode::InvalidClient, "unknown client"))?;

        if !client.is_active() {
            return Err(RevocationError::new(
                OAuthErrorCode::InvalidClient,
                "client is disabled",
            ));
        }

        // 資格情報の照合は `client_authentication` へ集約してある（G3・ADR-0030）。
        match self
            .client_auth
            .authenticate(tenant, &client, credentials)
            .await
        {
            // public client は認証なしで通す（RFC 7009 §2.1）。
            Ok(ClientAuthOutcome::NotRequired | ClientAuthOutcome::Authenticated) => {}
            Err(ClientAuthError::Failed(_)) => {
                self.record_auth_failure(tenant, &client.client_id, ctx)
                    .await;
                return Err(RevocationError::new(
                    OAuthErrorCode::InvalidClient,
                    "client authentication failed",
                ));
            }
            Err(ClientAuthError::Internal(message)) => {
                // 内部エラーの詳細はクライアントへ出さない（`CLAUDE.md`「国際化」の翻訳対象外）。
                tracing::error!(error = %message, "client authentication internal error");
                return Err(RevocationError::new(
                    OAuthErrorCode::ServerError,
                    "internal server error",
                ));
            }
        }

        Ok(client)
    }

    async fn record_auth_failure(
        &self,
        tenant: TenantContext,
        client_id: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                Some(client_id),
                Some("revocation"),
                ctx,
            )
            .await;
    }
}

/// base64url（パディングなし）デコード。
fn base64_decode_no_pad(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(s).ok()
}
