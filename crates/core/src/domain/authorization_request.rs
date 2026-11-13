//! Authorization request (an OIDC authorization request accepted by `/authorize`. Design spec §4.2).
//!
//! [`AuthorizationRequest`] is a value object representing an authorization request **after it passed validation**. It can be
//! created only through [`AuthorizationRequest::accept`] and cannot be made without going through it (except restoration from
//! persistence, [`AuthorizationRequest::reconstitute`]). So whoever receives this type need not re-check that `redirect_uri` is
//! registered, that it includes `openid`, or that PKCE is S256.
//!
//! The authorization request is carried whole into the AuthSession (temporary state from `/authorize` to code issuance), and
//! whichever path is taken (sign-in, MFA, passkey, external IdP, password change, consent, SSO restore), the
//! authorization code and authorization response are finally built from this value.

use crate::domain::client::Client;
use crate::domain::error::OAuthErrorCode;
use crate::domain::response_mode::{AuthorizationResponse, ResponseMode};
use crate::domain::values::{CodeChallengeMethod, Prompt, PromptSet, Scope};
use chrono::{DateTime, Utc};

/// Query parameters of `/authorize` (raw values before validation).
///
/// All are received as `Option` so that omission can be detected.
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
    /// The `prompt` parameter (`none` / `login` / `consent` / `select_account`).
    pub prompt: Option<String>,
    /// The `max_age` parameter (seconds).
    pub max_age: Option<u64>,
    /// The `acr_values` parameter (space-separated. G12). Referenced by the authentication policy's `requested_acr` condition (AP3).
    /// The IdP **does not guarantee** the requested acr (an unsatisfiable request simply does not match).
    pub acr_values: Option<String>,
    /// The `login_hint` parameter (prefills the user name on the sign-in screen. G12).
    pub login_hint: Option<String>,
    /// The `ui_locales` parameter (display languages requested by the RP. Space-separated BCP47 tags. G12).
    pub ui_locales: Option<String>,
    /// The `response_mode` parameter (`query` (default) / `form_post`. G12).
    /// Unknown values are not rounded to the default but become `invalid_request` (see [`ResponseMode::parse`] for why).
    pub response_mode: Option<String>,
}

/// Why the authorization request could not be accepted.
///
/// The two kinds are separated because how to respond depends on **whether `redirect_uri` can be trusted**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRequestRejection {
    /// `client_id` / `redirect_uri` cannot be trusted. **Do not redirect** (do not become an open
    /// redirector). The error is returned on the IdP's own screen (400).
    NotRedirectable {
        error: OAuthErrorCode,
        description: &'static str,
    },
    /// `redirect_uri` was confirmed as registered. Return there with the error attached.
    Redirectable {
        redirect_uri: String,
        /// If the request had a `state`, it is passed back (not returned if empty).
        state: Option<String>,
        error: OAuthErrorCode,
        description: &'static str,
    },
}

/// PKCE code challenge (RFC 7636). The only acceptable method is S256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceChallenge {
    challenge: String,
    method: CodeChallengeMethod,
}

impl PkceChallenge {
    /// Restores from a persisted value (validated at acceptance time).
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

/// An accepted authorization request (value object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    client_id: String,
    redirect_uri: String,
    scope: Vec<String>,
    state: String,
    /// ⚠ **`nonce` is optional** (ADR-0049). When absent it is carried as an empty string, and the id_token **omits the claim
    /// entirely** (`skip_serializing_if` in `token.rs`).
    nonce: String,
    pkce: PkceChallenge,
    /// A space-separated **set**. Empty set when omitted or only unknown values. The SSO decision happens in resume (ADR-0018 decision 2),
    /// so it is carried until evaluation.
    prompt: PromptSet,
    /// How to return the authorization response (G12). The request comes at `/authorize`, but the response is built by a different request.
    response_mode: ResponseMode,
    /// Seconds. `None` when omitted. Evaluated in resume, like `prompt`.
    max_age: Option<u64>,
    /// Raw space-separated value (G12). Referenced by the authentication policy's `requested_acr` condition (AP3).
    acr_values: Option<String>,
    login_hint: Option<String>,
    ui_locales: Option<String>,
}

/// Parts for rebuilding an [`AuthorizationRequest`] from persistence.
///
/// ⚠ Exists **only for the Infrastructure layer (repository implementations) and tests**. Stored values passed validation
/// at acceptance time, so they are not re-validated here. New requests must always go through
/// [`AuthorizationRequest::accept`].
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
    /// Accepts an authorization request against the client that issued it (design spec §4.2 "validation items").
    ///
    /// `client` is the one resolved from `client_id` in the flow's tenant (what to do if it could not be resolved
    /// is up to the caller). Validation runs in this order, and later stages are not looked at if an earlier one fails:
    ///
    /// 1. Whether the client is active and `redirect_uri` is registered (on failure, **do not redirect**)
    /// 2. Everything else (on failure, return to `redirect_uri` with the error attached)
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
            // Use **the registered notation**, not the raw request value (matching follows the DB collation).
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.to_string(),
            scope: split_scope(params.scope.as_deref()),
            state: state.expect("state validated above").to_string(),
            nonce: params.nonce.clone().unwrap_or_default(),
            pkce: PkceChallenge {
                challenge: params.code_challenge.clone().expect("validated above"),
                method: CodeChallengeMethod::S256,
            },
            // Unknown `prompt` values are ignored (`PromptSet::parse` skips them).
            prompt: PromptSet::parse(params.prompt.as_deref().unwrap_or_default()),
            // Validated (unknown values were rejected above). Default is `query` when omitted.
            response_mode: non_empty(params.response_mode.as_deref())
                .and_then(|raw| ResponseMode::parse(raw).ok())
                .unwrap_or_default(),
            max_age: params.max_age,
            acr_values: non_empty(params.acr_values.as_deref()).map(str::to_string),
            login_hint: non_empty(params.login_hint.as_deref()).map(str::to_string),
            ui_locales: non_empty(params.ui_locales.as_deref()).map(str::to_string),
        })
    }

    /// Restores from a persisted value (see the note on [`AuthorizationRequestParts`]).
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

    /// Raw value of `acr_values` (`None` when omitted).
    pub fn acr_values(&self) -> Option<&str> {
        self.acr_values.as_deref()
    }

    pub fn login_hint(&self) -> Option<&str> {
        self.login_hint.as_deref()
    }

    pub fn ui_locales(&self) -> Option<&str> {
        self.ui_locales.as_deref()
    }

    /// `acr_values` split on whitespace (empty when omitted).
    pub fn requested_acr(&self) -> Vec<String> {
        self.acr_values
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// `prompt=none`: no screen may be shown to the user (neither sign-in nor consent can be requested).
    pub fn forbids_interaction(&self) -> bool {
        self.prompt.contains(Prompt::None)
    }

    /// Whether to bypass existing SSO and make the user go through the sign-in screen.
    ///
    /// `select_account`, like `login`, stops SSO restore (G12). assay has only one SSO session per browser,
    /// so it cannot show a list of "other accounts to choose", but the essence of the request is **not to silently continue with
    /// the current account**. Returning to the sign-in screen lets the user either sign in again with the same account
    /// or switch to another account.
    pub fn forces_reauthentication(&self) -> bool {
        self.prompt.contains(Prompt::Login) || self.prompt.contains(Prompt::SelectAccount)
    }

    /// Whether to show the consent screen even if consent already exists (`prompt=consent`).
    pub fn forces_consent(&self) -> bool {
        self.prompt.contains(Prompt::Consent)
    }

    /// Whether the authentication at `auth_time` is older than `max_age` (always `false` when `max_age` is omitted).
    pub fn authentication_is_too_old(&self, auth_time: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        self.max_age
            .is_some_and(|max_age| (now - auth_time).num_seconds() > max_age as i64)
    }

    /// Scopes that need the user's consent (`openid` is excluded as implicitly consented). Consent is unnecessary if empty.
    pub fn scopes_needing_consent(&self) -> Vec<String> {
        self.scope
            .iter()
            .filter(|s| s.as_str() != Scope::OpenId.as_str())
            .cloned()
            .collect()
    }

    /// The authorization success response (destination + parameters). Follows `response_mode` (G12).
    pub fn success_response(&self, code: &str) -> AuthorizationResponse {
        AuthorizationResponse::success(&self.redirect_uri, code, &self.state, self.response_mode)
    }

    /// The authorization error response. Errors are also returned **with the same `response_mode` as success** (the RP waits at the same endpoint.
    /// OAuth 2.0 Form Post Response Mode).
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

/// Validation after the `redirect_uri` check (errors return to `redirect_uri`).
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
    // `nonce` is **optional** (OIDC Core 3.1.2.1. It is required only for implicit / hybrid, and
    // this server only accepts `response_type=code`).
    //
    // ⚠ **Stopped requiring it on 2026-09-10** (ADR-0049). It had been required as a policy, but
    // **that rejected parties sending requests per the spec**: Forgejo does not send `nonce`
    // (not implemented. forgejo/forgejo#186), so it could not even reach the sign-in screen.
    //
    // ⚠ **`state` and PKCE (S256) remain required**. Those carry the defense against code theft and CSRF,
    // and `nonce` mainly matters for id_token replay
    // (implicit).
    //
    // ⚠ **For parties that send it, it is returned in the id_token as before**
    // (`token.rs`. When absent, **the claim is omitted entirely**: no empty string).
    // `response_mode` defaults to `query`. A specified value that cannot be interpreted is rejected (not rounded).
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

/// Parts for quickly building authorization requests in tests (treated as validated values).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// The minimal S256 authorization request, requesting only `openid`.
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

    /// Extracts only the code of an error returned to the redirect target (`Redirectable`).
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

    /// Failures at the stage where `redirect_uri` cannot be trusted do not redirect.
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

        // A request without `state` does not get a `state` when returned either.
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
        params.scope = Some("email".to_string()); // no openid
        assert_eq!(redirect_error(&params), OAuthErrorCode::InvalidScope);

        let mut params = valid();
        params.scope = Some("openid profile".to_string()); // scope not registered
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

    /// ⚠ **`nonce` is optional** (ADR-0049). Passes when absent or empty, carried as an empty string.
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

    /// Both success and errors are returned with the requested `response_mode` (G12).
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
