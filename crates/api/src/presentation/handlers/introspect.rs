//! Token イントロスペクションエンドポイント（`POST /introspect`、RFC 7662）。
//!
//! - confidential client のみ許可（public client は 401）。認証方式はクライアントの登録値
//!   （`client_secret_basic` / `client_secret_post`）に従う。
//! - `token`: 対象トークン（必須）。
//! - `token_type_hint`: `access_token` または `refresh_token`（任意）。
//! - 無効・失効済みのトークンは `{"active": false}` を返す。

use crate::application::introspection::IntrospectionError;
use crate::domain::error::OAuthErrorCode;
use crate::presentation::client_auth::{presented_credentials, unauthorized};
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
    /// `client_secret_post` のクライアント secret（G3）。
    pub client_secret: Option<String>,
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
    let credentials = match presented_credentials(&headers, body.client_id, body.client_secret) {
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
                // RFC 6749 §5.2: invalid_client は 401 + WWW-Authenticate。
                OAuthErrorCode::InvalidClient => (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"introspect\"")],
                    body,
                )
                    .into_response(),
                OAuthErrorCode::ServerError => {
                    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
                }
                // 複数方式の同時提示（§2.3.1）等は要求そのものの不正。
                _ => (StatusCode::BAD_REQUEST, body).into_response(),
            }
        }
    }
}
