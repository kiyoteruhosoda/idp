//! Token イントロスペクションエンドポイント（`POST /introspect`、RFC 7662）。
//!
//! - confidential client のみ許可（public client は 401）。
//! - `token`: 対象トークン（必須）。
//! - `token_type_hint`: `access_token` または `refresh_token`（任意）。
//! - 無効・失効済みのトークンは `{"active": false}` を返す。

use crate::application::introspection::{IntrospectionError, IntrospectionResponse};
use crate::domain::error::OAuthErrorCode;
use crate::presentation::dto::OAuthErrorResponse;
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
pub struct IntrospectionRequest {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
}

/// Token イントロスペクションエンドポイント（RFC 7662）。
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
    // Basic 認証を必須とする（confidential client）。
    let basic_credentials = match parse_basic_credentials(&headers) {
        Ok(Some(creds)) => creds,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"introspect\"")],
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidClient.as_str().to_string(),
                    error_description: Some(
                        "client authentication is required for introspection".to_string(),
                    ),
                }),
            )
                .into_response()
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"introspect\"")],
                Json(OAuthErrorResponse {
                    error: OAuthErrorCode::InvalidClient.as_str().to_string(),
                    error_description: Some("malformed Basic authorization header".to_string()),
                }),
            )
                .into_response()
        }
    };

    let (client_id, client_secret) = basic_credentials;

    let token = match body.token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t.to_string(),
        None => {
            // token なしは inactive を返す（RFC 7662 §2.2 準拠）。
            return Json(IntrospectionResponse::inactive()).into_response();
        }
    };

    match state
        .introspection
        .introspect(
            tenant.context(),
            &token,
            body.token_type_hint.as_deref(),
            &client_id,
            Some((&client_id, &client_secret)),
        )
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(IntrospectionError { code, description }) => {
            let body = Json(OAuthErrorResponse {
                error: code.as_str().to_string(),
                error_description: Some(description),
            });
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"introspect\"")],
                body,
            )
                .into_response()
        }
    }
}

fn parse_basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, ()> {
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
