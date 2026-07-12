//! ユーザー登録エンドポイント（`POST /auth/register`、設計仕様 §4.1）。

use crate::application::register::{RegisterCommand, RegisterError};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{RegisterRequest, RegisterResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

#[utoipa::path(
    post,
    path = "/{tenant_id}/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "登録成功", body = RegisterResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 403, description = "当該テナントで自己登録が無効（SEC6。既定）"),
        (status = 409, description = "email / preferred_username の重複"),
        (status = 429, description = "レート制限超過（SEC6）"),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let command = RegisterCommand {
        email: body.email,
        preferred_username: body.preferred_username,
        password: body.password,
        name: body.name,
    };

    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let registered = state
        .register
        .register(tenant.context(), command, ctx.ip_address.as_deref())
        .await
        .map_err(map_error)?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            sub: registered.sub.to_string(),
            status: registered.status.as_str().to_string(),
        }),
    ))
}

fn map_error(e: RegisterError) -> ApiError {
    match e {
        RegisterError::Validation(m) => ApiError::BadRequest(m),
        RegisterError::Forbidden(m) => ApiError::Forbidden(m),
        RegisterError::RateLimited => {
            ApiError::TooManyRequests("too many registration attempts".to_string())
        }
        RegisterError::Conflict(m) => ApiError::Conflict(m),
        RegisterError::Internal(m) => ApiError::Internal(m),
    }
}
