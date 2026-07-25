//! 認可エンドポイント（`GET /authorize`、設計仕様 §4.2）。

use crate::application::authorize::{AuthorizeOutcome, AuthorizeRequest};
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{AuthorizeParams, OAuthErrorResponse};
use crate::presentation::handlers::{found, request_context};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::Json;

/// OIDC 認可エンドポイント。検証成功時は `redirect_uri` または `/login` または `/consent` へ 302 する。
/// `prompt` / `max_age` に正式対応（F3）。`login_hint` / `acr_values` は引き続き無視する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/authorize",
    tag = "oidc",
    params(AuthorizeParams),
    responses(
        (status = 302, description = "redirect_uri（code/error 付与）または /login または /consent へリダイレクト"),
        (status = 400, description = "client_id / redirect_uri が無効（リダイレクトしない）", body = OAuthErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let request = AuthorizeRequest {
        response_type: params.response_type,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope,
        state: params.state,
        nonce: params.nonce,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        sso_session_id: cookies::get(&headers, cookies::SSO_SESSION_COOKIE),
        prompt: params.prompt,
        max_age: params.max_age,
    };

    match state
        .authorize
        .authorize(tenant.context(), request, &ctx)
        .await
    {
        AuthorizeOutcome::Redirect { location } | AuthorizeOutcome::ErrorRedirect { location } => {
            found(&location)
        }
        // ログイン・同意画面は web が描画する。別ドメイン構成（ADR-0012 §4)に対応するため
        // `PUBLIC_WEB_BASE_URL` 基点の絶対 URL へ 302 する（単一オリジン構成では issuer と同値）。
        AuthorizeOutcome::LoginRequired { auth_session_id } => {
            let set_cookies = auth_session_cookies(&state, &auth_session_id);
            (
                AppendHeaders(set_cookies),
                found(&format!(
                    "{}/{}/login",
                    state.config.public_web_base_url(),
                    tenant.id()
                )),
            )
                .into_response()
        }
        AuthorizeOutcome::ConsentRequired { auth_session_id } => {
            let set_cookies = auth_session_cookies(&state, &auth_session_id);
            (
                AppendHeaders(set_cookies),
                found(&format!(
                    "{}/{}/consent",
                    state.config.public_web_base_url(),
                    tenant.id()
                )),
            )
                .into_response()
        }
        AuthorizeOutcome::FatalError { error, description } => (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorResponse {
                error: error.as_str().to_string(),
                error_description: Some(description),
            }),
        )
            .into_response(),
    }
}

/// `auth_session_id` Cookie の `Set-Cookie` ヘッダ組（サービス横断 Cookie。ADR-0012 §3）。
fn auth_session_cookies(state: &AppState, auth_session_id: &str) -> Vec<(HeaderName, String)> {
    cookies::headers(state.config.cookie_policy().set_shared(
        cookies::AUTH_SESSION_COOKIE,
        auth_session_id,
        state.config.auth_session_ttl().as_secs(),
    ))
}
