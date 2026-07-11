//! Token 失効エンドポイント（`POST /revoke`、RFC 7009）。
//!
//! - `token`: 失効させるトークン（必須）。
//! - `token_type_hint`: `access_token` または `refresh_token`（任意）。
//! - confidential client は `client_secret_basic` 認証が必要。public client は `client_id` のみ。
//! - RFC 7009 §2.2: トークン不存在・失効済みでも 200 を返す（エラーは client 認証失敗のみ）。

use crate::application::revocation::RevocationError;
use crate::domain::error::OAuthErrorCode;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::OAuthErrorResponse;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevocationRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
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
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());

    let token = match body.token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => return StatusCode::OK.into_response(), // token なしは 200（RFC 7009 §2.1）
    };

    // Basic 認証ヘッダを解析（confidential client 用）。
    let basic_credentials = match parse_basic_credentials(&headers) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"revoke\"")],
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidClient.as_str().to_string(),
                    error_description: Some("malformed Basic authorization header".to_string()),
                }),
            )
                .into_response()
        }
    };

    // client_id を特定（Basic ヘッダ優先、次いで body）。
    let client_id = match basic_credentials
        .as_ref()
        .map(|(id, _)| id.as_str())
        .or(body.client_id.as_deref())
    {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"revoke\"")],
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidClient.as_str().to_string(),
                    error_description: Some("client_id is required".to_string()),
                }),
            )
                .into_response()
        }
    };

    let creds = basic_credentials.as_ref().map(|(id, s)| (id.as_str(), s.as_str()));

    match state
        .revocation
        .revoke(
            tenant.context(),
            &token,
            body.token_type_hint.as_deref(),
            &client_id,
            creds,
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

/// `Authorization: Basic` から `(client_id, client_secret)` を取り出す。
fn parse_basic_credentials(
    headers: &HeaderMap,
) -> Result<Option<(String, String)>, ()> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    let encoded = value.strip_prefix("Basic ").ok_or(())?;
    let decoded = STANDARD.decode(encoded.trim()).map_err(|_| ())?;
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    let (id, secret) = decoded.split_once(':').ok_or(())?;
    let id = percent_decode_str(id).decode_utf8().map_err(|_| ())?;
    let secret = percent_decode_str(secret).decode_utf8().map_err(|_| ())?;
    Ok(Some((id.into_owned(), secret.into_owned())))
}
