//! Token 失効エンドポイント（`POST /revoke`、RFC 7009）。
//!
//! - `token`: 失効させるトークン（必須）。
//! - `token_type_hint`: `access_token` または `refresh_token`（任意）。
//! - confidential client は登録した方式（`client_secret_basic` / `client_secret_post` / `private_key_jwt`）での認証が
//!   必要。public client は `client_id` のみ。
//! - RFC 7009 §2.2: トークン不存在・失効済みでも 200 を返す（エラーは client 認証失敗のみ）。

use crate::application::revocation::RevocationError;
use crate::domain::error::OAuthErrorCode;
use crate::presentation::client_auth::{
    presented_credentials, unauthorized, BodyClientCredentials,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::OAuthErrorResponse;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevocationRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    /// `client_secret_post` のクライアント secret（G3）。
    pub client_secret: Option<String>,
    /// `private_key_jwt` の署名済み assertion（RFC 7523 §2.2。ADR-0030）。
    pub client_assertion: Option<String>,
    /// `client_assertion` の種別。`urn:ietf:params:oauth:client-assertion-type:jwt-bearer` のみ。
    pub client_assertion_type: Option<String>,
}

/// Token 失効エンドポイント（RFC 7009）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/revoke",
    tag = "oidc",
    request_body(content = RevocationRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "失効成功（または不存在・失効済みも 200）"),
        (status = 400, description = "リクエスト不正"),
        (status = 401, description = "クライアント認証失敗"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Form(body): Form<RevocationRequest>,
) -> Response {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );

    let token = match body.token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => return StatusCode::OK.into_response(), // token なしは 200（RFC 7009 §2.1）
    };

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
        Err(_) => return unauthorized("revoke", "malformed Basic authorization header"),
    };

    match state
        .revocation
        .revoke(
            tenant.context(),
            &token,
            body.token_type_hint.as_deref(),
            &credentials,
            &ctx,
        )
        .await
    {
        Ok(()) => StatusCode::OK.into_response(),
        Err(RevocationError { code, description }) => {
            let body = Json(OAuthErrorResponse {
                error: code.as_str().to_string(),
                error_description: Some(description),
            });
            match code {
                OAuthErrorCode::InvalidClient => (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"revoke\"")],
                    body,
                )
                    .into_response(),
                OAuthErrorCode::ServerError => {
                    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
                }
                _ => (StatusCode::BAD_REQUEST, body).into_response(),
            }
        }
    }
}
