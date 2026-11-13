//! Token introspection endpoint (`POST /introspect`, RFC 7662).
//!
//! - Only confidential clients allowed (public clients get 401). The auth method follows the client's registered value
//!   (`client_secret_basic` / `client_secret_post` / `private_key_jwt`).
//! - `token`: the target token (required).
//! - `token_type_hint`: `access_token` or `refresh_token` (optional).
//! - Invalid or revoked tokens return `{"active": false}`.

use crate::application::introspection::IntrospectionError;
use crate::domain::error::OAuthErrorCode;
use crate::presentation::client_auth::{
    presented_credentials, unauthorized, BodyClientCredentials,
};
use crate::presentation::dto::OAuthErrorResponse;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectionRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    /// Client secret for `client_secret_post` (G3).
    pub client_secret: Option<String>,
    /// Signed `private_key_jwt` assertion (RFC 7523 §2.2, ADR-0030).
    pub client_assertion: Option<String>,
    /// Type of `client_assertion`. Only `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    pub client_assertion_type: Option<String>,
}

/// Token introspection endpoint (RFC 7662).
#[utoipa::path(
    post,
    path = "/{tenant_id}/introspect",
    tag = "oidc",
    request_body(content = IntrospectionRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "イントロスペクション結果（active: true/false）"),
        (status = 401, description = "クライアント認証失敗"),
    )
)]
pub async fn introspect(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Form(body): Form<IntrospectionRequest>,
) -> Response {
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
        Err(_) => return unauthorized("introspect", "malformed Basic authorization header"),
    };

    let token = body.token.as_deref().unwrap_or_default().to_string();

    match state
        .introspection
        .introspect(
            tenant.context(),
            &token,
            body.token_type_hint.as_deref(),
            &credentials,
        )
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(IntrospectionError { code, description }) => {
            let body = Json(OAuthErrorResponse {
                error: code.as_str().to_string(),
                error_description: Some(description),
            });
            match code {
                // RFC 6749 §5.2: invalid_client is 401 + WWW-Authenticate.
                OAuthErrorCode::InvalidClient => (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"introspect\"")],
                    body,
                )
                    .into_response(),
                OAuthErrorCode::ServerError => {
                    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
                }
                // Presenting multiple methods at once (§2.3.1) etc. is a malformed request itself.
                _ => (StatusCode::BAD_REQUEST, body).into_response(),
            }
        }
    }
}
