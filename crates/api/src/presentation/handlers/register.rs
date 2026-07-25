//! ユーザー登録エンドポイント（`POST /auth/register`、設計仕様 §4.1）。

use crate::application::email_verification::VerifyEmailOutcome;
use crate::application::register::{RegisterCommand, RegisterError};
use crate::domain::message::keys;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{RegisterRequest, RegisterResponse, VerifyEmailRequest};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
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
    locale: ApiLocale,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let command = RegisterCommand {
        email: body.email,
        preferred_username: body.preferred_username,
        password: body.password,
        name: body.name,
    };

    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let registered = state
        .register
        .register(tenant.context(), command, ctx.ip_address.as_deref())
        .await
        .map_err(|e| map_error(e, locale))?;

    // 検証メールを送る（best-effort。SMTP 未設定・送信失敗でも登録自体は成立する。SEC6b）。
    // 自己登録アカウントは `email_verified = false` で作られ、確認リンクを踏むまでログインできない。
    let email_verification_required = state
        .email_verification
        .send_verification(
            tenant.context().tenant_id(),
            registered.user_id,
            &registered.email,
            &ctx,
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            sub: registered.sub.to_string(),
            status: registered.status.as_str().to_string(),
            email_verification_required,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/{tenant_id}/auth/verify-email",
    tag = "auth",
    request_body = VerifyEmailRequest,
    responses(
        (status = 204, description = "検証成功（email_verified を立てた）"),
        (status = 400, description = "トークンが無効・期限切れ・使用済み・別テナント"),
    )
)]
pub async fn verify_email(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    locale: ApiLocale,
    Json(body): Json<VerifyEmailRequest>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    match state
        .email_verification
        .verify(tenant.context(), &body.token, &ctx)
        .await
    {
        VerifyEmailOutcome::Ok => Ok(StatusCode::NO_CONTENT),
        VerifyEmailOutcome::InvalidOrExpired => Err(ApiError::BadRequest(
            ApiMessages::new(locale).get(keys::REGISTER_VERIFICATION_INVALID),
        )),
        VerifyEmailOutcome::Internal(m) => Err(ApiError::Internal(m)),
    }
}

fn map_error(e: RegisterError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        RegisterError::Validation(m) => ApiError::BadRequest(msgs.message(&m)),
        RegisterError::Forbidden(m) => ApiError::Forbidden(msgs.message(&m)),
        RegisterError::RateLimited => {
            ApiError::TooManyRequests(msgs.get(keys::REGISTER_RATE_LIMITED))
        }
        RegisterError::Conflict(m) => ApiError::Conflict(msgs.message(&m)),
        RegisterError::Internal(m) => ApiError::Internal(m),
    }
}
