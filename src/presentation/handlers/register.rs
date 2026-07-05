//! ユーザー登録エンドポイント（`POST /auth/register`、設計仕様 §4.1）。

use crate::application::register::{RegisterCommand, RegisterError, RegisterService};
use crate::presentation::dto::{RegisterRequest, RegisterResponse};
use crate::presentation::error::ApiError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "登録成功", body = RegisterResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 409, description = "email / preferred_username の重複"),
    )
)]
pub async fn register(
    State(service): State<Arc<RegisterService>>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let command = RegisterCommand {
        email: body.email,
        preferred_username: body.preferred_username,
        password: body.password,
        name: body.name,
    };

    let registered = service.register(command).await.map_err(map_error)?;

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
        RegisterError::Conflict(m) => ApiError::Conflict(m),
        RegisterError::Internal(m) => ApiError::Internal(m),
    }
}
