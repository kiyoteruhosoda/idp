//! 認可エンドポイント（`GET /authorize`、設計仕様 §4.2）。

use crate::application::authorize::{AuthorizeOutcome, AuthorizeRequest};
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{AuthorizeParams, OAuthErrorResponse};
use crate::presentation::handlers::{found, request_context};
use crate::presentation::state::AppState;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// OIDC 認可エンドポイント。検証成功時は `redirect_uri` または `/login` へ 302 する。
/// `prompt` / `max_age` / `login_hint` / `acr_values` は MVP では無視する。
#[utoipa::path(
    get,
    path = "/authorize",
    tag = "oidc",
    params(AuthorizeParams),
    responses(
        (status = 302, description = "redirect_uri（code/error 付与）または /login へリダイレクト"),
        (status = 400, description = "client_id / redirect_uri が無効（リダイレクトしない）", body = OAuthErrorResponse),
    )
)]
pub async fn authorize(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let ctx = request_context(&headers, &correlation);
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
    };

    match state.authorize.authorize(request, &ctx).await {
        AuthorizeOutcome::Redirect { location } | AuthorizeOutcome::ErrorRedirect { location } => {
            found(&location)
        }
        AuthorizeOutcome::LoginRequired { auth_session_id } => {
            let cookie = cookies::build(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl().as_secs(),
                state.config.cookie_secure(),
            );
            ([(header::SET_COOKIE, cookie)], found("/login")).into_response()
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
