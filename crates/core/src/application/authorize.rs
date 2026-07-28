//! 認可エンドポイントのユースケース（設計仕様 §4.2、ADR-0018 決定 2・3）。
//!
//! `/authorize` はブラウザ Cookie を読み書きしない。認可リクエストを検証して AuthSession を作成し、
//! **単回・短命のハンドル**を発行して web へのハンドオフ（`{web}/{tenant}/login?auth_session=...`）
//! に載せる（[`AuthorizeService::authorize`]）。SSO 復元・同意チェック・code 発行は、web が
//! ハンドルと自ドメインの `sso_session_id` を `/internal/authorize/resume` で渡してきた時点で行う
//! （[`AuthorizeService::resume`]）。`prompt` / `max_age` の評価も resume まで持ち越す。
//!
//! エラー方針: `client_id` / `redirect_uri` が無効な場合はリダイレクトせず、
//! それ以外のエラーは `redirect_uri` にエラーコードを付与して返す。

use crate::application::audit::RequestContext;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::sso_restore::SsoRestorer;
use crate::domain::auth_session::AuthSession;
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, ClientRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{CodeChallengeMethod, Prompt, Scope};
use chrono::Duration;
use std::sync::Arc;

/// web ハンドオフ用ハンドルの有効期限（秒）。`/authorize` の 302 を web が受けて
/// `/internal/authorize/resume` へ渡すまでの片道だけを覆えばよいため、auth_session 本体の
/// TTL より大幅に短くする（単回・短命・固定束縛。ADR-0018 決定 3）。
const HANDLE_TTL_SECS: i64 = 60;

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
    /// `prompt` パラメータ（`none` / `login` / `consent`）。
    pub prompt: Option<String>,
    /// `max_age` パラメータ（秒）。
    pub max_age: Option<u64>,
}

pub enum AuthorizeOutcome {
    /// 検証成功。AuthSession 作成済み。単回ハンドルを URL に載せて web の `/login` へ 302 する
    /// （SSO の有無は web が resume で確かめる。ADR-0018 決定 2）。
    HandoffToWeb { handle: String },
    /// `redirect_uri` にエラーを付与して 302。
    ErrorRedirect { location: String },
    /// リダイレクト不可のエラー（client_id / redirect_uri が無効）。
    FatalError {
        error: OAuthErrorCode,
        description: String,
    },
}

/// `/internal/authorize/resume` のコマンド（web がハンドルと SSO Cookie 値を転送する）。
#[derive(Debug)]
pub struct ResumeCommand {
    /// `/authorize` が URL に載せた単回ハンドル。
    pub handle: String,
    /// web の host-only `sso_session_id` Cookie の値（無ければ未ログイン）。
    pub sso_session_id: Option<String>,
}

pub enum ResumeOutcome {
    /// SSO 復元・同意済みにより code 発行済み。`redirect_uri?code=...&state=...` へ 302。
    Redirect { location: String },
    /// リクエスト続行不可（`prompt=none` で未ログイン・未同意など）。エラー付き RP URL へ 302。
    ErrorRedirect { location: String },
    /// SSO 有効だが同意が必要。web は `auth_session_id` を Cookie 化して `/consent` へ。
    ConsentRequired { auth_session_id: String },
    /// 認証が必要。web は `auth_session_id` を Cookie 化してログインフォームを表示する。
    LoginRequired { auth_session_id: String },
    /// ハンドルが無効・期限切れ・使用済み（`/authorize` からやり直し）。
    ExpiredHandle,
    /// 内部エラー（RP へのリダイレクトも組み立てられない段階での失敗）。
    Internal(String),
}

pub struct AuthorizeService {
    clients: Arc<dyn ClientRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    /// SSO 復元の共通判定（SAML SSO と共有。[`crate::application::sso_restore`]）。
    sso_restorer: Arc<SsoRestorer>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    clock: Arc<dyn Clock>,
    auth_session_ttl: Duration,
}

impl AuthorizeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_restorer: Arc<SsoRestorer>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        clock: Arc<dyn Clock>,
        auth_session_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            auth_sessions,
            sso_restorer,
            client_consents,
            code_issuance,
            clock,
            auth_session_ttl: Duration::from_std(auth_session_ttl)
                .expect("auth session TTL out of range"),
        }
    }

    pub async fn authorize(
        &self,
        tenant: TenantContext,
        req: AuthorizeRequest,
    ) -> AuthorizeOutcome {
        // 1. client_id / redirect_uri の検証（無効ならリダイレクトしない）。client はフローの
        // テナントに属するものだけを解決する（テナント分離。ADR-0009 §8）。
        let Some(client_id) = non_empty(req.client_id.as_deref()) else {
            return fatal(OAuthErrorCode::InvalidRequest, "client_id is required");
        };
        let client = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
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
                location: error_redirect_with_state(redirect_uri, error, description, state),
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

        // 3. AuthSession を作成し、単回ハンドルを発行して web へハンドオフする（ADR-0018 決定 2）。
        //    SSO Cookie は api からは見えないため、SSO 復元・`prompt`/`max_age` の評価は resume で行う。
        //    未知の `prompt` 値は従来どおり無視する（`parse(...).ok()`）。
        let now = self.clock.now();
        let handle = crypto::random_hex(32);
        let session = AuthSession {
            id: crypto::random_hex(32),
            tenant_id: tenant.tenant_id(),
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope,
            state,
            nonce,
            code_challenge,
            code_challenge_method: CodeChallengeMethod::S256,
            prompt: req.prompt.as_deref().and_then(|p| Prompt::parse(p).ok()),
            max_age: req.max_age,
            handle_hash: Some(crypto::sha256_hex(&handle)),
            handle_expires_at: Some(now + Duration::seconds(HANDLE_TTL_SECS)),
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            expires_at: now + self.auth_session_ttl,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.auth_sessions.create(&session).await {
            tracing::error!(error = %e, "failed to create auth session");
            return AuthorizeOutcome::ErrorRedirect {
                location: error_redirect_with_state(
                    redirect_uri,
                    OAuthErrorCode::ServerError,
                    "failed to start authorization",
                    Some(&session.state),
                ),
            };
        }

        AuthorizeOutcome::HandoffToWeb { handle }
    }

    /// web ハンドオフの再開（`/internal/authorize/resume`。ADR-0018 決定 2）。
    ///
    /// ハンドルを単回消費して AuthSession を特定し、web から渡された `sso_session_id` で
    /// SSO 復元 → `max_age` → 同意チェック → code 発行（従来 `/authorize` が Cookie で行っていた
    /// 判定）を行う。`prompt=none` の失敗は RP へのエラーリダイレクトとして返す。
    pub async fn resume(
        &self,
        tenant: TenantContext,
        cmd: ResumeCommand,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let now = self.clock.now();

        // 1. ハンドルから AuthSession を特定し、単回使用として消費する。
        if cmd.handle.is_empty() {
            return ResumeOutcome::ExpiredHandle;
        }
        let handle_hash = crypto::sha256_hex(&cmd.handle);
        let session = match self
            .auth_sessions
            .find_by_handle(tenant.tenant_id(), &handle_hash)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ResumeOutcome::ExpiredHandle,
            Err(e) => return ResumeOutcome::Internal(e.to_string()),
        };
        if !session.handle_is_valid_at(now) || session.is_expired_at(now) {
            return ResumeOutcome::ExpiredHandle;
        }
        match self
            .auth_sessions
            .consume_handle(&session.id, &handle_hash)
            .await
        {
            Ok(true) => {}
            // 並行する交換に負けた・再利用 → 単回使用として拒否する。
            Ok(false) => return ResumeOutcome::ExpiredHandle,
            Err(e) => return ResumeOutcome::Internal(e.to_string()),
        }

        let prompt_none = session.prompt == Some(Prompt::None);
        let force_login = session.prompt == Some(Prompt::Login);
        let force_consent = session.prompt == Some(Prompt::Consent);

        // 2. SSO 復元を試みる（`prompt=login` は常に再認証）。
        if !force_login {
            if let Some(session_id) = non_empty(cmd.sso_session_id.as_deref()) {
                match self.sso_restorer.try_resume(tenant, session_id, ctx).await {
                    Ok(Some(restored)) => {
                        let (user_id, auth_time) = (restored.user_id, restored.auth_time);
                        // `max_age` チェック: auth_time から max_age 秒超過していれば再認証。
                        let max_age_exceeded = session.max_age.is_some_and(|max_age| {
                            (now - auth_time).num_seconds() > max_age as i64
                        });

                        if !max_age_exceeded {
                            // 同意チェック（force_consent の場合は既存同意を無視）。
                            if !force_consent
                                && self
                                    .check_consent(
                                        tenant,
                                        user_id,
                                        &session.client_id,
                                        &session.scope,
                                    )
                                    .await
                            {
                                // 同意済み → code を発行し AuthSession を削除する。
                                let cmd = IssueCodeCommand {
                                    tenant,
                                    user_id,
                                    client_id: session.client_id.clone(),
                                    redirect_uri: session.redirect_uri.clone(),
                                    scope: session.scope.clone(),
                                    nonce: session.nonce.clone(),
                                    auth_time,
                                    code_challenge: session.code_challenge.clone(),
                                    code_challenge_method: session.code_challenge_method,
                                };
                                return match self.code_issuance.issue(cmd, ctx).await {
                                    Ok(code) => {
                                        if let Err(e) = self.auth_sessions.delete(&session.id).await
                                        {
                                            tracing::warn!(
                                                error = %e,
                                                "failed to delete auth session after SSO code issuance"
                                            );
                                        }
                                        ResumeOutcome::Redirect {
                                            location: code_redirect(
                                                &session.redirect_uri,
                                                &code,
                                                &session.state,
                                            ),
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            error = %e,
                                            "failed to issue authorization code"
                                        );
                                        ResumeOutcome::ErrorRedirect {
                                            location: error_redirect_with_state(
                                                &session.redirect_uri,
                                                OAuthErrorCode::ServerError,
                                                "failed to issue authorization code",
                                                Some(&session.state),
                                            ),
                                        }
                                    }
                                };
                            }

                            // 未同意（または force_consent）。
                            if prompt_none {
                                // prompt=none では同意画面を出せないのでエラー（フロー終了）。
                                let _ = self.auth_sessions.delete(&session.id).await;
                                return ResumeOutcome::ErrorRedirect {
                                    location: error_redirect_with_state(
                                        &session.redirect_uri,
                                        OAuthErrorCode::ConsentRequired,
                                        "consent required",
                                        Some(&session.state),
                                    ),
                                };
                            }

                            // 同意画面へ: AuthSession を認証済み状態にして web に返す。
                            if let Err(e) = self
                                .auth_sessions
                                .set_authenticated_user(&session.id, user_id, auth_time)
                                .await
                            {
                                tracing::error!(error = %e, "failed to mark session for consent");
                                return ResumeOutcome::ErrorRedirect {
                                    location: error_redirect_with_state(
                                        &session.redirect_uri,
                                        OAuthErrorCode::ServerError,
                                        "failed to start consent",
                                        Some(&session.state),
                                    ),
                                };
                            }
                            return ResumeOutcome::ConsentRequired {
                                auth_session_id: session.id,
                            };
                        }
                        // max_age 超過 → ログインへ（SSO は復元しない）。prompt=none なら下でエラー。
                    }
                    Ok(None) => {} // SSO なし・無効 → ログインへ。
                    Err(e) => {
                        tracing::error!(error = %e, "failed to check SSO session");
                        // SSO 確認失敗は致命ではない。ログインへフォールバックする。
                    }
                }
            }
        }

        // 3. SSO で完了できない: prompt=none はログイン画面を出せないのでエラー（フロー終了）。
        if prompt_none {
            let _ = self.auth_sessions.delete(&session.id).await;
            return ResumeOutcome::ErrorRedirect {
                location: error_redirect_with_state(
                    &session.redirect_uri,
                    OAuthErrorCode::LoginRequired,
                    "login required",
                    Some(&session.state),
                ),
            };
        }

        ResumeOutcome::LoginRequired {
            auth_session_id: session.id,
        }
    }

    /// 同意チェック: ユーザーがクライアントに対してすべての scope に同意済みか確認する。
    async fn check_consent(
        &self,
        tenant: TenantContext,
        user_id: uuid::Uuid,
        client_id: &str,
        scope: &[String],
    ) -> bool {
        let scopes_without_openid: Vec<String> = scope
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect();
        // openid のみの場合は常に同意済みとみなす。
        if scopes_without_openid.is_empty() {
            return true;
        }
        match self
            .client_consents
            .find(tenant.tenant_id(), user_id, client_id)
            .await
        {
            Ok(Some(consent)) => consent.covers(&scopes_without_openid),
            Ok(None) => false,
            Err(e) => {
                tracing::error!(error = %e, "failed to check consent");
                false
            }
        }
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

/// `redirect_uri?error=...&error_description=...&state=...` を構築する（state は省略可）。
pub fn error_redirect_with_state(
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
            tenant_id: uuid::Uuid::now_v7().into(),
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
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
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
            prompt: None,
            max_age: None,
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

        let location = error_redirect_with_state(
            "https://client.example.com/cb",
            OAuthErrorCode::InvalidScope,
            "scope must include `openid`",
            Some("xyz"),
        );
        assert!(location.contains("error=invalid_scope"));
        assert!(location.contains("state=xyz"));
    }

    #[test]
    fn handle_validity_requires_both_hash_and_deadline() {
        let now = Utc::now();
        let mut session = AuthSession {
            id: "s".to_string(),
            tenant_id: uuid::Uuid::now_v7().into(),
            client_id: "app".to_string(),
            redirect_uri: "https://client.example.com/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: "xyz".to_string(),
            nonce: "n".to_string(),
            code_challenge: "c".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            prompt: None,
            max_age: None,
            handle_hash: Some("h".to_string()),
            handle_expires_at: Some(now + Duration::seconds(HANDLE_TTL_SECS)),
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            expires_at: now + Duration::minutes(10),
            created_at: now,
            updated_at: now,
        };
        assert!(session.handle_is_valid_at(now));
        // 期限切れは無効。
        assert!(!session.handle_is_valid_at(now + Duration::seconds(HANDLE_TTL_SECS + 1)));
        // 消費済み（NULL）は無効（単回使用）。
        session.handle_hash = None;
        assert!(!session.handle_is_valid_at(now));
    }
}
