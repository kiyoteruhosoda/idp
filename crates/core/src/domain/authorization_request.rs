//! 認可要求（`/authorize` が受理した OIDC の認可リクエスト。設計仕様 §4.2）。
//!
//! [`AuthorizationRequest`] は**検証を通った後の**認可要求を表す値オブジェクトである。生成は
//! [`AuthorizationRequest::accept`] に限られ、そこを通らない限り作れない（永続化からの復元
//! [`AuthorizationRequest::reconstitute`] を除く）。したがってこの型を受け取った側は、`redirect_uri` が
//! 登録済みであること・`openid` を含むこと・PKCE が S256 であることを改めて確かめなくてよい。
//!
//! 認可要求は AuthSession（`/authorize` 〜 code 発行までの一時状態）に丸ごと持ち越され、ログイン・
//! MFA・パスキー・外部 IdP・パスワード変更・同意・SSO 復元のどの経路でも、最後はこの値から
//! authorization code と認可応答を組み立てる。

use crate::domain::client::Client;
use crate::domain::error::OAuthErrorCode;
use crate::domain::response_mode::{AuthorizationResponse, ResponseMode};
use crate::domain::values::{CodeChallengeMethod, Prompt, PromptSet, Scope};
use chrono::{DateTime, Utc};

/// `/authorize` のクエリパラメータ（検証前の生値）。
///
/// 未指定を検出できるよう、すべて `Option` で受ける。
#[derive(Debug, Default)]
pub struct AuthorizationParameters {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// `prompt` パラメータ（`none` / `login` / `consent` / `select_account`）。
    pub prompt: Option<String>,
    /// `max_age` パラメータ（秒）。
    pub max_age: Option<u64>,
    /// `acr_values` パラメータ（空白区切り。G12）。認証ポリシーの `requested_acr` 条件（AP3）が
    /// 参照する。IdP は要求された acr を**保証しない**（満たせない要求は単に一致しないだけ）。
    pub acr_values: Option<String>,
    /// `login_hint` パラメータ（ログイン画面のユーザー名プリフィル。G12）。
    pub login_hint: Option<String>,
    /// `ui_locales` パラメータ（RP が要求する表示言語。空白区切りの BCP47 タグ。G12）。
    pub ui_locales: Option<String>,
    /// `response_mode` パラメータ（`query`（既定）/ `form_post`。G12）。
    /// 未知の値は既定へ丸めず `invalid_request` にする（理由は [`ResponseMode::parse`]）。
    pub response_mode: Option<String>,
}

/// 認可要求を受理できなかった理由。
///
/// 2 種類を分けるのは、**`redirect_uri` を信用してよいかどうか**で返し方が変わるためである。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRequestRejection {
    /// `client_id` / `redirect_uri` が信用できない。**リダイレクトしない**（オープンリダイレクタに
    /// しない）。エラーは IdP 自身の画面（400）で返す。
    NotRedirectable {
        error: OAuthErrorCode,
        description: &'static str,
    },
    /// `redirect_uri` は登録済みと確認できた。エラーを付けてそこへ戻す。
    Redirectable {
        redirect_uri: String,
        /// 要求に `state` があれば透過返却する（空なら返さない）。
        state: Option<String>,
        error: OAuthErrorCode,
        description: &'static str,
    },
}

/// PKCE の code challenge（RFC 7636）。受理できる方式は S256 だけ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    challenge: String,
    method: CodeChallengeMethod,
}

impl PkceChallenge {
    /// 永続化された値から復元する（受理の時点で検証済み）。
    pub fn reconstitute(challenge: String, method: CodeChallengeMethod) -> Self {
        Self { challenge, method }
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub fn method(&self) -> CodeChallengeMethod {
        self.method
    }
}

/// 受理済みの認可要求（値オブジェクト）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    client_id: String,
    redirect_uri: String,
    scope: Vec<String>,
    state: String,
    /// ⚠ **`nonce` は任意**（ADR-0049）。無いときは空文字で持ち回り、id_token では**クレームごと
    /// 出さない**（`token.rs` の `skip_serializing_if`）。
    nonce: String,
    pkce: PkceChallenge,
    /// 空白区切りの**集合**。未指定・未知値のみは空集合。SSO 判定は resume（ADR-0018 決定 2）で
    /// 行うため、評価時点まで持ち越す。
    prompt: PromptSet,
    /// 認可応答の返し方（G12）。要求は `/authorize` で来るが応答を組み立てるのは別のリクエスト。
    response_mode: ResponseMode,
    /// 秒。未指定は `None`。`prompt` と同じく resume で評価する。
    max_age: Option<u64>,
    /// 空白区切りの生値（G12）。認証ポリシーの `requested_acr` 条件（AP3）が参照する。
    acr_values: Option<String>,
    login_hint: Option<String>,
    ui_locales: Option<String>,
}

/// 永続化から [`AuthorizationRequest`] を組み立て直すための部品。
///
/// ⚠ **Infrastructure 層（リポジトリ実装）と試験のためだけ**にある。保存されている値は受理の時点で
/// 検証を通っているので、ここでは検証し直さない。新しい要求を作るときは必ず
/// [`AuthorizationRequest::accept`] を通す。
#[derive(Debug, Clone)]
pub struct AuthorizationRequestParts {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub prompt: PromptSet,
    pub response_mode: ResponseMode,
    pub max_age: Option<u64>,
    pub acr_values: Option<String>,
    pub login_hint: Option<String>,
    pub ui_locales: Option<String>,
}

impl AuthorizationRequest {
    /// 認可要求を、それを出したクライアントに照らして受理する（設計仕様 §4.2「検証項目」）。
    ///
    /// `client` はフローのテナントで `client_id` から解決済みのもの（解決できなかった場合の
    /// 扱いは呼び出し側）。検証の順序は次のとおりで、前の段で落ちたら後ろは見ない:
    ///
    /// 1. クライアントが有効か・`redirect_uri` が登録済みか（落ちたら**リダイレクトしない**）
    /// 2. それ以外（落ちたら `redirect_uri` へエラーを付けて戻す）
    pub fn accept(
        params: &AuthorizationParameters,
        client: &Client,
    ) -> Result<Self, AuthorizationRequestRejection> {
        use AuthorizationRequestRejection::NotRedirectable;

        if !client.is_active() {
            return Err(NotRedirectable {
                error: OAuthErrorCode::InvalidClient,
                description: "client is not active",
            });
        }
        let Some(redirect_uri) = non_empty(params.redirect_uri.as_deref()) else {
            return Err(NotRedirectable {
                error: OAuthErrorCode::InvalidRequest,
                description: "redirect_uri is required",
            });
        };
        if !client.allows_redirect_uri(redirect_uri) {
            return Err(NotRedirectable {
                error: OAuthErrorCode::InvalidRequest,
                description: "redirect_uri is not registered",
            });
        }

        let state = non_empty(params.state.as_deref());
        validate_redirectable(params, client).map_err(|(error, description)| {
            AuthorizationRequestRejection::Redirectable {
                redirect_uri: redirect_uri.to_string(),
                state: state.map(str::to_string),
                error,
                description,
            }
        })?;

        Ok(Self {
            // 要求の生値ではなく**登録されている表記**を使う（照合は DB の照合順序に従う）。
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope: split_scope(params.scope.as_deref()),
            state: state.expect("state validated above").to_string(),
            nonce: params.nonce.clone().unwrap_or_default(),
            pkce: PkceChallenge {
                challenge: params.code_challenge.clone().expect("validated above"),
                method: CodeChallengeMethod::S256,
            },
            // 未知の `prompt` 値は無視する（`PromptSet::parse` が読み飛ばす）。
            prompt: PromptSet::parse(params.prompt.as_deref().unwrap_or_default()),
            // 検証済み（未知の値は上で弾いている）。未指定は既定の `query`。
            response_mode: non_empty(params.response_mode.as_deref())
                .and_then(|raw| ResponseMode::parse(raw).ok())
                .unwrap_or_default(),
            max_age: params.max_age,
            acr_values: non_empty(params.acr_values.as_deref()).map(str::to_string),
            login_hint: non_empty(params.login_hint.as_deref()).map(str::to_string),
            ui_locales: non_empty(params.ui_locales.as_deref()).map(str::to_string),
        })
    }

    /// 永続化された値から復元する（[`AuthorizationRequestParts`] の注意を参照）。
    pub fn reconstitute(parts: AuthorizationRequestParts) -> Self {
        Self {
            client_id: parts.client_id,
            redirect_uri: parts.redirect_uri,
            scope: parts.scope,
            state: parts.state,
            nonce: parts.nonce,
            pkce: PkceChallenge::reconstitute(parts.code_challenge, parts.code_challenge_method),
            prompt: parts.prompt,
            response_mode: parts.response_mode,
            max_age: parts.max_age,
            acr_values: parts.acr_values,
            login_hint: parts.login_hint,
            ui_locales: parts.ui_locales,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn pkce(&self) -> &PkceChallenge {
        &self.pkce
    }

    pub fn prompt(&self) -> &PromptSet {
        &self.prompt
    }

    pub fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    pub fn max_age(&self) -> Option<u64> {
        self.max_age
    }

    /// `acr_values` の生値（未指定は `None`）。
    pub fn acr_values(&self) -> Option<&str> {
        self.acr_values.as_deref()
    }

    pub fn login_hint(&self) -> Option<&str> {
        self.login_hint.as_deref()
    }

    pub fn ui_locales(&self) -> Option<&str> {
        self.ui_locales.as_deref()
    }

    /// `acr_values` を空白区切りで分割した一覧（未指定は空）。
    pub fn requested_acr(&self) -> Vec<String> {
        self.acr_values
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// `prompt=none`: 利用者に画面を見せてはならない（ログインも同意も求められない）。
    pub fn forbids_interaction(&self) -> bool {
        self.prompt.contains(Prompt::None)
    }

    /// 既存の SSO を使わず、ログイン画面を通させるか。
    ///
    /// `select_account` も `login` と同じく SSO 復元を止める（G12）。assay はブラウザごとに SSO
    /// セッションを 1 つしか持たないため「選ばせる別アカウント」の一覧は出せないが、**黙って現在の
    /// アカウントで続けない**ことが要求の本質である。ログイン画面へ戻せば、利用者は同じアカウントで
    /// 入り直すことも別のアカウントへ切り替えることもできる。
    pub fn forces_reauthentication(&self) -> bool {
        self.prompt.contains(Prompt::Login) || self.prompt.contains(Prompt::SelectAccount)
    }

    /// 既存の同意があっても同意画面を出すか（`prompt=consent`）。
    pub fn forces_consent(&self) -> bool {
        self.prompt.contains(Prompt::Consent)
    }

    /// `auth_time` の認証が `max_age` を超えて古いか（`max_age` 未指定なら常に `false`）。
    pub fn authentication_is_too_old(&self, auth_time: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        self.max_age
            .is_some_and(|max_age| (now - auth_time).num_seconds() > max_age as i64)
    }

    /// 利用者の同意が要る scope（`openid` は暗黙同意なので除く）。空なら同意は要らない。
    pub fn scopes_needing_consent(&self) -> Vec<String> {
        self.scope
            .iter()
            .filter(|s| s.as_str() != Scope::OpenId.as_str())
            .cloned()
            .collect()
    }

    /// 認可成功の応答（送信先＋パラメータ）。`response_mode` に従う（G12）。
    pub fn success_response(&self, code: &str) -> AuthorizationResponse {
        AuthorizationResponse::success(&self.redirect_uri, code, &self.state, self.response_mode)
    }

    /// 認可エラーの応答。エラーも**成功と同じ `response_mode`** で返す（RP は同じ受け口で待っている。
    /// OAuth 2.0 Form Post Response Mode）。
    pub fn error_response(
        &self,
        error: OAuthErrorCode,
        description: &str,
    ) -> AuthorizationResponse {
        AuthorizationResponse::error(
            &self.redirect_uri,
            error.as_str(),
            description,
            &self.state,
            self.response_mode,
        )
    }
}

/// `redirect_uri` の確認より後ろの検証（エラーは `redirect_uri` へ戻す）。
fn validate_redirectable(
    params: &AuthorizationParameters,
    client: &Client,
) -> Result<(), (OAuthErrorCode, &'static str)> {
    if params.response_type.as_deref() != Some("code") {
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

    let scope = split_scope(params.scope.as_deref());
    if !scope.iter().any(|s| s == Scope::OpenId.as_str()) {
        return Err((OAuthErrorCode::InvalidScope, "scope must include `openid`"));
    }
    if !client.allows_scopes(&scope) {
        return Err((
            OAuthErrorCode::InvalidScope,
            "requested scope exceeds the client's registered scopes",
        ));
    }

    if non_empty(params.state.as_deref()).is_none() {
        return Err((OAuthErrorCode::InvalidRequest, "state is required"));
    }
    // `nonce` は**任意**（OIDC Core 3.1.2.1。必須なのは implicit / hybrid で、
    // このサーバは `response_type=code` しか受けない）。
    //
    // ⚠ **2026-09-10 に必須化をやめた**（ADR-0049）。方針として必須にしていたが、
    // **仕様どおりに送ってくる相手を弾いていた** ——Forgejo は `nonce` を送らない
    // （未実装。forgejo/forgejo#186）ので、ログイン画面にすら着けなかった。
    //
    // ⚠ **`state` と PKCE(S256) は必須のまま**である。コード奪取と CSRF の防御は
    // そちらが持っており、`nonce` が主に効くのは id_token のリプレイ
    // （implicit）である。
    //
    // ⚠ **送ってきた相手には、これまでどおり id_token へ載せて返す**
    // （`token.rs`。無いときは**クレームごと出さない** ——空文字を載せない）。
    // `response_mode` は未指定なら `query`。指定があって解釈できない値は弾く（丸めない）。
    if let Some(raw) = non_empty(params.response_mode.as_deref()) {
        if ResponseMode::parse(raw).is_err() {
            return Err((
                OAuthErrorCode::InvalidRequest,
                "response_mode must be `query` or `form_post`",
            ));
        }
    }
    if params.code_challenge_method.as_deref() != Some(CodeChallengeMethod::S256.as_str()) {
        return Err((
            OAuthErrorCode::InvalidRequest,
            "code_challenge_method must be `S256`",
        ));
    }
    if non_empty(params.code_challenge.as_deref()).is_none() {
        return Err((OAuthErrorCode::InvalidRequest, "code_challenge is required"));
    }
    Ok(())
}

fn split_scope(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn non_empty(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}

/// 試験で認可要求を手早く組み立てるための部品（検証済みの値として扱う）。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// `openid` だけを要求する、S256 の最小の認可要求。
    pub fn request(client_id: &str, redirect_uri: &str) -> AuthorizationRequest {
        AuthorizationRequest::reconstitute(AuthorizationRequestParts {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: vec!["openid".to_string()],
            state: "state-1".to_string(),
            nonce: "nonce-1".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: CodeChallengeMethod::S256,
            prompt: PromptSet::default(),
            response_mode: ResponseMode::Query,
            max_age: None,
            acr_values: None,
            login_hint: None,
            ui_locales: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};
    use chrono::Duration;

    fn client() -> Client {
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
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn valid() -> AuthorizationParameters {
        AuthorizationParameters {
            response_type: Some("code".to_string()),
            client_id: Some("app".to_string()),
            redirect_uri: Some("https://client.example.com/cb".to_string()),
            scope: Some("openid email".to_string()),
            state: Some("xyz".to_string()),
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            ..Default::default()
        }
    }

    /// 戻し先へ返すエラー（`Redirectable`）のコードだけを取り出す。
    fn redirect_error(params: &AuthorizationParameters) -> OAuthErrorCode {
        match AuthorizationRequest::accept(params, &client()) {
            Err(AuthorizationRequestRejection::Redirectable { error, .. }) => error,
            other => panic!("expected a redirectable rejection, got {other:?}"),
        }
    }

    #[test]
    fn accepts_a_valid_request_and_keeps_its_parameters() {
        let request = AuthorizationRequest::accept(&valid(), &client()).expect("accepted");
        assert_eq!(request.client_id(), "app");
        assert_eq!(request.redirect_uri(), "https://client.example.com/cb");
        assert_eq!(request.scope(), ["openid", "email"]);
        assert_eq!(request.state(), "xyz");
        assert_eq!(request.nonce(), "n-0S6_WzA2Mj");
        assert_eq!(request.pkce().method(), CodeChallengeMethod::S256);
        assert_eq!(request.response_mode(), ResponseMode::Query);
        assert_eq!(request.acr_values(), None);
    }

    #[test]
    fn the_registered_client_id_wins_over_the_requested_spelling() {
        let mut params = valid();
        params.client_id = Some("APP".to_string());
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
        assert_eq!(request.client_id(), "app");
    }

    /// `redirect_uri` を信用できない段階の失敗は、リダイレクトしない。
    #[test]
    fn untrusted_redirect_uri_is_not_redirected_to() {
        let mut inactive = client();
        inactive.client_status = ClientStatus::Disabled;
        assert_eq!(
            AuthorizationRequest::accept(&valid(), &inactive),
            Err(AuthorizationRequestRejection::NotRedirectable {
                error: OAuthErrorCode::InvalidClient,
                description: "client is not active",
            })
        );

        let mut params = valid();
        params.redirect_uri = Some(String::new());
        assert_eq!(
            AuthorizationRequest::accept(&params, &client()),
            Err(AuthorizationRequestRejection::NotRedirectable {
                error: OAuthErrorCode::InvalidRequest,
                description: "redirect_uri is required",
            })
        );

        let mut params = valid();
        params.redirect_uri = Some("https://evil.example.com/cb".to_string());
        assert_eq!(
            AuthorizationRequest::accept(&params, &client()),
            Err(AuthorizationRequestRejection::NotRedirectable {
                error: OAuthErrorCode::InvalidRequest,
                description: "redirect_uri is not registered",
            })
        );
    }

    #[test]
    fn redirectable_rejection_carries_the_state_back() {
        let mut params = valid();
        params.response_type = Some("token".to_string());
        assert_eq!(
            AuthorizationRequest::accept(&params, &client()),
            Err(AuthorizationRequestRejection::Redirectable {
                redirect_uri: "https://client.example.com/cb".to_string(),
                state: Some("xyz".to_string()),
                error: OAuthErrorCode::UnsupportedResponseType,
                description: "response_type must be `code`",
            })
        );

        // `state` が無い要求は、戻すときも `state` を付けない。
        let mut params = valid();
        params.state = None;
        match AuthorizationRequest::accept(&params, &client()) {
            Err(AuthorizationRequestRejection::Redirectable { state, error, .. }) => {
                assert_eq!(state, None);
                assert_eq!(error, OAuthErrorCode::InvalidRequest);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_or_invalid_parameters() {
        let mut params = valid();
        params.scope = Some("email".to_string()); // openid 無し
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidScope);

        let mut params = valid();
        params.scope = Some("openid profile".to_string()); // 登録外 scope
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidScope);

        let mut params = valid();
        params.code_challenge_method = Some("plain".to_string());
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidRequest);

        let mut params = valid();
        params.code_challenge = None;
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidRequest);

        let mut params = valid();
        params.response_mode = Some("fragment".to_string());
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidRequest);

        let mut unauthorized = client();
        unauthorized.grant_types = vec!["client_credentials".to_string()];
        assert!(matches!(
            AuthorizationRequest::accept(&valid(), &unauthorized),
            Err(AuthorizationRequestRejection::Redirectable {
                error: OAuthErrorCode::UnauthorizedClient,
                ..
            })
        ));
    }

    /// ⚠ **`nonce` は任意である**（ADR-0049）。無くても空でも通り、空文字で持ち回る。
    #[test]
    fn nonce_is_optional() {
        for nonce in [None, Some(String::new())] {
            let mut params = valid();
            params.nonce = nonce;
            let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
            assert_eq!(request.nonce(), "");
        }
    }

    #[test]
    fn empty_optional_parameters_are_treated_as_absent() {
        let mut params = valid();
        params.acr_values = Some(String::new());
        params.login_hint = Some(String::new());
        params.ui_locales = Some(String::new());
        params.response_mode = Some(String::new());
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
        assert_eq!(request.acr_values(), None);
        assert_eq!(request.login_hint(), None);
        assert_eq!(request.ui_locales(), None);
        assert_eq!(request.response_mode(), ResponseMode::Query);
        assert!(request.requested_acr().is_empty());
    }

    #[test]
    fn prompt_decides_how_much_interaction_is_allowed() {
        let with_prompt = |raw: &str| {
            let mut params = valid();
            params.prompt = Some(raw.to_string());
            AuthorizationRequest::accept(&params, &client()).expect("accepted")
        };
        assert!(with_prompt("none").forbids_interaction());
        assert!(with_prompt("login").forces_reauthentication());
        assert!(with_prompt("select_account").forces_reauthentication());
        assert!(with_prompt("consent").forces_consent());

        let plain = AuthorizationRequest::accept(&valid(), &client()).expect("accepted");
        assert!(!plain.forbids_interaction());
        assert!(!plain.forces_reauthentication());
        assert!(!plain.forces_consent());
    }

    #[test]
    fn max_age_is_exceeded_only_past_the_limit() {
        let mut params = valid();
        params.max_age = Some(60);
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
        let now = Utc::now();
        assert!(!request.authentication_is_too_old(now - Duration::seconds(60), now));
        assert!(request.authentication_is_too_old(now - Duration::seconds(61), now));

        let unlimited = AuthorizationRequest::accept(&valid(), &client()).expect("accepted");
        assert!(!unlimited.authentication_is_too_old(now - Duration::days(365), now));
    }

    #[test]
    fn openid_never_needs_consent() {
        let request = AuthorizationRequest::accept(&valid(), &client()).expect("accepted");
        assert_eq!(request.scopes_needing_consent(), ["email"]);

        let mut params = valid();
        params.scope = Some("openid".to_string());
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
        assert!(request.scopes_needing_consent().is_empty());
    }

    #[test]
    fn requested_acr_splits_on_whitespace() {
        let mut params = valid();
        params.acr_values = Some("  urn:a   urn:b ".to_string());
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");
        assert_eq!(request.requested_acr(), ["urn:a", "urn:b"]);
    }

    /// 成功もエラーも、要求された `response_mode` で返す（G12）。
    #[test]
    fn responses_follow_the_requested_response_mode() {
        let mut params = valid();
        params.response_mode = Some("form_post".to_string());
        let request = AuthorizationRequest::accept(&params, &client()).expect("accepted");

        let success = request.success_response("the-code");
        assert!(success.is_form_post());
        assert_eq!(success.location(), "https://client.example.com/cb");

        let error = request.error_response(OAuthErrorCode::AccessDenied, "no");
        assert!(error.is_form_post());
        assert!(error
            .parameters
            .contains(&("state".to_string(), "xyz".to_string())));
    }
}
