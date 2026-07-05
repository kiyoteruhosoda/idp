//! 認可エンドポイントのユースケース（設計仕様 §4.2）。
//!
//! 認可リクエストを検証し、SSO セッションがあれば再ログインなしで code を発行、
//! なければ AuthSession を作成して `/login` へ誘導する。
//!
//! エラー方針: `client_id` / `redirect_uri` が無効な場合はリダイレクトせず、
//! それ以外のエラーは `redirect_uri` にエラーコードを付与して返す。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSession;
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    AuthSessionRepository, ClientRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::values::{CodeChallengeMethod, Scope};
use crate::infrastructure::crypto;
use chrono::Duration;
use std::sync::Arc;

/// `/authorize` のクエリパラメータ（未指定を検出できるようすべて Option で受ける）。
#[derive(Debug, Default)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// SSO Cookie（`sso_session_id`）の値。
    pub sso_session_id: Option<String>,
}

pub enum AuthorizeOutcome {
    /// SSO 復元により code 発行済み。`redirect_uri?code=...&state=...` へ 302。
    Redirect { location: String },
    /// 認証が必要。AuthSession 作成済み。`auth_session_id` Cookie を発行して `/login` へ。
    LoginRequired { auth_session_id: String },
    /// `redirect_uri` にエラーを付与して 302。
    ErrorRedirect { location: String },
    /// リダイレクト不可のエラー（client_id / redirect_uri が無効）。
    FatalError {
        error: OAuthErrorCode,
        description: String,
    },
}

pub struct AuthorizeService {
    clients: Arc<dyn ClientRepository>,
    users: Arc<dyn UserRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    auth_session_ttl: Duration,
    sso_idle_ttl: Duration,
}

impl AuthorizeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        users: Arc<dyn UserRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        auth_session_ttl: std::time::Duration,
        sso_idle_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            users,
            auth_sessions,
            sso_sessions,
            code_issuance,
            audit,
            clock,
            auth_session_ttl: Duration::from_std(auth_session_ttl)
                .expect("auth session TTL out of range"),
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
        }
    }

    pub async fn authorize(&self, req: AuthorizeRequest, ctx: &RequestContext) -> AuthorizeOutcome {
        // 1. client_id / redirect_uri の検証（無効ならリダイレクトしない）。
        let Some(client_id) = non_empty(req.client_id.as_deref()) else {
            return fatal(OAuthErrorCode::InvalidRequest, "client_id is required");
        };
        let client = match self.clients.find_by_client_id(client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return fatal(OAuthErrorCode::InvalidClient, "unknown client_id"),
            Err(e) => {
                tracing::error!(error = %e, "failed to load client");
                return fatal(OAuthErrorCode::ServerError, "internal error");
            }
        };
        if !client.is_active() {
            return fatal(OAuthErrorCode::InvalidClient, "client is not active");
        }
        let Some(redirect_uri) = non_empty(req.redirect_uri.as_deref()) else {
            return fatal(OAuthErrorCode::InvalidRequest, "redirect_uri is required");
        };
        if !client.allows_redirect_uri(redirect_uri) {
            return fatal(
                OAuthErrorCode::InvalidRequest,
                "redirect_uri is not registered",
            );
        }

        let state = non_empty(req.state.as_deref());

        // 2. それ以外の検証（エラーは redirect_uri に付与して返す）。
        if let Err((error, description)) = validate_request(&req, &client) {
            return AuthorizeOutcome::ErrorRedirect {
                location: error_redirect(redirect_uri, error, description, state),
            };
        }

        let scope: Vec<String> = req
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let state = state.expect("state validated above").to_string();
        let nonce = req.nonce.clone().expect("nonce validated above");
        let code_challenge = req.code_challenge.clone().expect("validated above");

        // 3. SSO Cookie 確認。有効なら再ログインなしで code を発行する。
        if let Some(session_id) = non_empty(req.sso_session_id.as_deref()) {
            match self.try_resume_sso(session_id, ctx).await {
                Ok(Some((user_id, auth_time))) => {
                    let cmd = IssueCodeCommand {
                        user_id,
                        client_id: client.client_id.clone(),
                        redirect_uri: redirect_uri.to_string(),
                        scope,
                        nonce,
                        auth_time,
                        code_challenge,
                        code_challenge_method: CodeChallengeMethod::S256,
                    };
                    return match self.code_issuance.issue(cmd, ctx).await {
                        Ok(code) => AuthorizeOutcome::Redirect {
                            location: code_redirect(redirect_uri, &code, &state),
                        },
                        Err(e) => {
                            tracing::error!(error = %e, "failed to issue authorization code");
                            AuthorizeOutcome::ErrorRedirect {
                                location: error_redirect(
                                    redirect_uri,
                                    OAuthErrorCode::ServerError,
                                    "failed to issue authorization code",
                                    Some(&state),
                                ),
                            }
                        }
                    };
                }
                Ok(None) => {} // SSO なし・無効 → ログインへ。
                Err(e) => {
                    tracing::error!(error = %e, "failed to check SSO session");
                    // SSO 確認失敗は致命ではない。ログインへフォールバックする。
                }
            }
        }

        // 4. AuthSession を作成して /login へ。
        let now = self.clock.now();
        let session = AuthSession {
            id: crypto::random_hex(32),
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope,
            state,
            nonce,
            code_challenge,
            code_challenge_method: CodeChallengeMethod::S256,
            authenticated_user_id: None,
            auth_time: None,
            expires_at: now + self.auth_session_ttl,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.auth_sessions.create(&session).await {
            tracing::error!(error = %e, "failed to create auth session");
            return AuthorizeOutcome::ErrorRedirect {
                location: error_redirect(
                    redirect_uri,
                    OAuthErrorCode::ServerError,
                    "failed to start authorization",
                    Some(&session.state),
                ),
            };
        }

        AuthorizeOutcome::LoginRequired {
            auth_session_id: session.id,
        }
    }

    /// SSO セッションの復元を試みる。有効なら `(user_id, auth_time)` を返し idle 期限を延長する。
    /// 期限切れは削除して `sso_session.expired` を監査ログへ記録する。
    async fn try_resume_sso(
        &self,
        session_id: &str,
        ctx: &RequestContext,
    ) -> Result<
        Option<(uuid::Uuid, chrono::DateTime<chrono::Utc>)>,
        crate::domain::error::DomainError,
    > {
        let session_hash = crypto::sha256_hex(session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(None);
        };

        let now = self.clock.now();
        if !session.is_valid_at(now) {
            self.sso_sessions.delete(&session_hash).await?;
            self.audit
                .record(
                    AuditEventType::SsoSessionExpired,
                    AuditResult::Failure,
                    Some(session.user_id),
                    None,
                    Some("idle or absolute timeout"),
                    ctx,
                )
                .await;
            return Ok(None);
        }

        // ユーザーが無効化されていれば SSO 復元しない（再ログインで検出させる）。
        match self.users.find_by_id(session.user_id).await? {
            Some(user) if user.is_active() && !user.is_locked_at(now) => {}
            _ => return Ok(None),
        }

        // idle 期限を +8h 更新（absolute は変更しない）。auth_time は初回ログイン時刻を維持する。
        self.sso_sessions
            .extend_idle(&session_hash, now + self.sso_idle_ttl)
            .await?;
        self.audit
            .record(
                AuditEventType::SsoSessionResumed,
                AuditResult::Success,
                Some(session.user_id),
                None,
                None,
                ctx,
            )
            .await;

        Ok(Some((session.user_id, session.auth_time)))
    }
}

/// client_id / redirect_uri 以外の検証（設計仕様 §4.2「検証項目」）。
fn validate_request(
    req: &AuthorizeRequest,
    client: &Client,
) -> Result<(), (OAuthErrorCode, &'static str)> {
    if req.response_type.as_deref() != Some("code") {
        return Err((
            OAuthErrorCode::UnsupportedResponseType,
            "response_type must be `code`",
        ));
    }
    if !client.response_types.iter().any(|t| t == "code")
        || !client.grant_types.iter().any(|t| t == "authorization_code")
    {
        return Err((
            OAuthErrorCode::UnauthorizedClient,
            "client is not allowed to use the authorization code flow",
        ));
    }

    let scope: Vec<String> = req
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if !scope.iter().any(|s| s == Scope::OpenId.as_str()) {
        return Err((OAuthErrorCode::InvalidScope, "scope must include `openid`"));
    }
    if !client.allows_scopes(&scope) {
        return Err((
            OAuthErrorCode::InvalidScope,
            "requested scope exceeds the client's registered scopes",
        ));
    }

    if non_empty(req.state.as_deref()).is_none() {
        return Err((OAuthErrorCode::InvalidRequest, "state is required"));
    }
    if non_empty(req.nonce.as_deref()).is_none() {
        return Err((OAuthErrorCode::InvalidRequest, "nonce is required"));
    }
    if req.code_challenge_method.as_deref() != Some(CodeChallengeMethod::S256.as_str()) {
        return Err((
            OAuthErrorCode::InvalidRequest,
            "code_challenge_method must be `S256`",
        ));
    }
    if non_empty(req.code_challenge.as_deref()).is_none() {
        return Err((OAuthErrorCode::InvalidRequest, "code_challenge is required"));
    }
    Ok(())
}

fn non_empty(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}

fn fatal(error: OAuthErrorCode, description: &str) -> AuthorizeOutcome {
    AuthorizeOutcome::FatalError {
        error,
        description: description.to_string(),
    }
}

/// `redirect_uri?code=...&state=...` を構築する（state は透過返却、設計仕様 §2.2）。
pub fn code_redirect(redirect_uri: &str, code: &str, state: &str) -> String {
    let mut url = url::Url::parse(redirect_uri).expect("redirect_uri validated as registered URL");
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    url.to_string()
}

/// `redirect_uri?error=...&error_description=...&state=...` を構築する。
fn error_redirect(
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    state: Option<&str>,
) -> String {
    let mut url = url::Url::parse(redirect_uri).expect("redirect_uri validated as registered URL");
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("error", error.as_str());
        pairs.append_pair("error_description", description);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};
    use chrono::Utc;

    fn test_client() -> Client {
        Client {
            id: uuid::Uuid::new_v4(),
            client_id: "app".to_string(),
            client_secret_hash: None,
            client_type: ClientType::Public,
            client_status: ClientStatus::Active,
            app_name: "App".to_string(),
            redirect_uris: vec!["https://client.example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string(), "email".to_string()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            require_pkce: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn valid_request() -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: Some("code".to_string()),
            client_id: Some("app".to_string()),
            redirect_uri: Some("https://client.example.com/cb".to_string()),
            scope: Some("openid email".to_string()),
            state: Some("xyz".to_string()),
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            sso_session_id: None,
        }
    }

    #[test]
    fn accepts_a_valid_request() {
        assert!(validate_request(&valid_request(), &test_client()).is_ok());
    }

    #[test]
    fn rejects_missing_or_invalid_parameters() {
        let client = test_client();

        let mut req = valid_request();
        req.response_type = Some("token".to_string());
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::UnsupportedResponseType
        );

        let mut req = valid_request();
        req.scope = Some("email".to_string()); // openid 無し
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidScope
        );

        let mut req = valid_request();
        req.scope = Some("openid profile".to_string()); // 登録外 scope
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidScope
        );

        let mut req = valid_request();
        req.state = None;
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidRequest
        );

        let mut req = valid_request();
        req.nonce = Some(String::new());
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidRequest
        );

        let mut req = valid_request();
        req.code_challenge_method = Some("plain".to_string());
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidRequest
        );

        let mut req = valid_request();
        req.code_challenge = None;
        assert_eq!(
            validate_request(&req, &client).unwrap_err().0,
            OAuthErrorCode::InvalidRequest
        );
    }

    #[test]
    fn builds_redirect_urls_with_encoded_query() {
        let location = code_redirect("https://client.example.com/cb?keep=1", "c o+de", "st&ate");
        assert!(location.starts_with("https://client.example.com/cb?keep=1&"));
        assert!(location.contains("code=c+o%2Bde"));
        assert!(location.contains("state=st%26ate"));

        let location = error_redirect(
            "https://client.example.com/cb",
            OAuthErrorCode::InvalidScope,
            "scope must include `openid`",
            Some("xyz"),
        );
        assert!(location.contains("error=invalid_scope"));
        assert!(location.contains("state=xyz"));
    }
}
