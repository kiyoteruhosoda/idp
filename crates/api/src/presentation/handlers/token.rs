//! トークンエンドポイント（`POST /token`、設計仕様 §4.4）。

use crate::application::token::{TokenCommand, TokenError};
use crate::domain::error::OAuthErrorCode;
use crate::presentation::client_auth::{
    presented_credentials, unauthorized, BodyClientCredentials,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{OAuthErrorResponse, TokenRequest, TokenResponse};
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};

/// トークン発行。confidential client は登録した方式（`client_secret_basic` / `client_secret_post`）、
/// public client は認証なし。
#[utoipa::path(
    post,
    path = "/{tenant_id}/token",
    tag = "oidc",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "ID Token / Access Token を発行", body = TokenResponse),
        (status = 400, description = "リクエスト・grant の不正", body = OAuthErrorResponse),
        (status = 401, description = "クライアント認証失敗", body = OAuthErrorResponse),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Form(body): Form<TokenRequest>,
) -> Response {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );

    let credentials = match presented_credentials(
        &headers,
        BodyClientCredentials {
            client_id: body.client_id,
            client_secret: body.client_secret,
            client_assertion: body.client_assertion,
            client_assertion_type: body.client_assertion_type,
        },
    ) {
        Ok(v) => v,
        Err(_) => return unauthorized("token", "malformed Basic authorization header"),
    };

    let command = TokenCommand {
        grant_type: body.grant_type,
        code: body.code,
        redirect_uri: body.redirect_uri,
        code_verifier: body.code_verifier,
        credentials,
        refresh_token: body.refresh_token,
        scope: body.scope,
    };

    match state.token.exchange(tenant.context(), command, &ctx).await {
        Ok(tokens) => (
            // トークンレスポンスはキャッシュ禁止（設計仕様 §4.4）。
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(TokenResponse {
                access_token: tokens.access_token,
                token_type: "Bearer".to_string(),
                expires_in: tokens.expires_in,
                id_token: tokens.id_token,
                scope: tokens.scope,
                refresh_token: tokens.refresh_token,
            }),
        )
            .into_response(),
        Err(e) => error_response(e),
    }
}

fn error_response(e: TokenError) -> Response {
    let body = Json(OAuthErrorResponse {
        error: e.code.as_str().to_string(),
        error_description: Some(e.description),
    });
    match e.code {
        // RFC 6749 §5.2: invalid_client は 401 + WWW-Authenticate。
        OAuthErrorCode::InvalidClient => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"token\"")],
            body,
        )
            .into_response(),
        OAuthErrorCode::ServerError => (StatusCode::INTERNAL_SERVER_ERROR, body).into_response(),
        _ => (StatusCode::BAD_REQUEST, body).into_response(),
    }
}
