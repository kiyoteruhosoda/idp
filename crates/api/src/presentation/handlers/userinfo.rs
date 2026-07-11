//! UserInfo エンドポイント（`GET /userinfo`、設計仕様 §4.7）。

use crate::application::userinfo::UserInfoError;
use crate::presentation::dto::{OAuthErrorResponse, UserInfoResponse};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Bearer の Access Token（`typ=at+jwt`）を検証し、scope に応じたクレームを返す。
#[utoipa::path(
    get,
    path = "/{tenant_id}/userinfo",
    tag = "oidc",
    security(("bearer_token" = [])),
    responses(
        (status = 200, description = "scope に応じたユーザークレーム", body = UserInfoResponse),
        (status = 401, description = "トークン不正", body = OAuthErrorResponse),
        (status = 403, description = "openid scope なし", body = OAuthErrorResponse),
    )
)]
pub async fn userinfo(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
) -> Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return unauthorized("missing bearer token");
    };

    // 要求テナントはパス由来（`resolve_tenant`）。トークンの `iss`/`aud` を当該テナントの合成 issuer と
    // 厳密照合し、他テナント発行トークンの流用を弾く（ADR-0009 §6）。
    match state.userinfo.userinfo(tenant.context(), token).await {
        Ok(claims) => Json(UserInfoResponse {
            sub: claims.sub,
            email: claims.email,
            email_verified: claims.email_verified,
            preferred_username: claims.preferred_username,
            name: claims.name,
        })
        .into_response(),
        Err(UserInfoError::InvalidToken(reason)) => unauthorized(reason),
        Err(UserInfoError::InsufficientScope) => (
            StatusCode::FORBIDDEN,
            [(
                header::WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\"",
            )],
            Json(OAuthErrorResponse {
                error: "insufficient_scope".to_string(),
                error_description: Some("openid scope is required".to_string()),
            }),
        )
            .into_response(),
        Err(UserInfoError::Internal(e)) => {
            tracing::error!(error = %e, "userinfo failed with internal error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn unauthorized(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
        Json(OAuthErrorResponse {
            error: "invalid_token".to_string(),
            error_description: Some(reason.to_string()),
        }),
    )
        .into_response()
}
