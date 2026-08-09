//! ログイン識別子の管理 API（`/{tenant_id}/admin/users/{user_id}/login-identifiers`。AP8）。
//!
//! テナント管理者が、利用者に**複数のログイン識別子**（電話番号・社員番号・別名のユーザー名・
//! メールアドレス）を割り当てる。すべて `idp.tenant.admin` 権限が必要。
//!
//! 応答には登録どおりの `display_value` と照合キーの `normalized_value` を両方返す。管理者が
//! 「登録した値」と「実際に一致する値」を突き合わせられないと、電話番号のように書き方が
//! 揺れる識別子の設定ミスに気づけない。

use crate::application::login_identifier_management::{
    AddLoginIdentifierCommand, LoginIdentifierManagementError,
};
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginIdentifierResponse {
    pub id: String,
    /// `username` / `email` / `phone_number` / `employee_number`。
    pub identifier_type: String,
    /// 登録されたままの値（表示用）。
    pub display_value: String,
    /// 照合キー（種別ごとの正規化を適用した値）。
    pub normalized_value: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<UserLoginIdentifier> for LoginIdentifierResponse {
    fn from(v: UserLoginIdentifier) -> Self {
        Self {
            id: v.id.to_string(),
            identifier_type: v.identifier_type.as_str().to_string(),
            display_value: v.display_value,
            normalized_value: v.normalized_value,
            is_active: v.is_active,
            created_at: v.created_at.to_rfc3339(),
            updated_at: v.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginIdentifierCreateRequest {
    /// `username` / `email` / `phone_number` / `employee_number`。
    pub identifier_type: String,
    pub value: String,
    /// 省略時は有効。
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginIdentifierUpdateRequest {
    pub is_active: bool,
}

/// 利用者のログイン識別子を一覧する。無効な行も返す（無効化した識別子は管理対象として残るため）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers",
    tag = "admin",
    responses(
        (status = 200, description = "識別子の一覧", body = [LoginIdentifierResponse]),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "利用者が見つからない"),
    )
)]
pub async fn list_login_identifiers(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, Uuid)>,
) -> Result<Json<Vec<LoginIdentifierResponse>>, ApiError> {
    let identifiers = state
        .login_identifiers_admin
        .list(tenant.context(), user_id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(
        identifiers.into_iter().map(Into::into).collect::<Vec<_>>(),
    ))
}

/// ログイン識別子を追加する。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers",
    tag = "admin",
    request_body = LoginIdentifierCreateRequest,
    responses(
        (status = 201, description = "追加した識別子", body = LoginIdentifierResponse),
        (status = 400, description = "種別・値が不正"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "利用者が見つからない"),
        (status = 409, description = "同じ値が他の利用者に解決される"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn add_login_identifier(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<LoginIdentifierCreateRequest>,
) -> Result<(StatusCode, Json<LoginIdentifierResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let identifier_type =
        LoginIdentifierType::parse(body.identifier_type.trim()).map_err(|_| {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-login-identifier-type-invalid"))
        })?;
    let added = state
        .login_identifiers_admin
        .add(
            tenant.context(),
            user_id,
            AddLoginIdentifierCommand {
                identifier_type,
                value: body.value,
                is_active: body.is_active,
            },
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(added.into())))
}

/// 識別子単位で有効/無効を切り替える（仕様 §4）。行は残るため、値が他の利用者へ移ることはない。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}",
    tag = "admin",
    request_body = LoginIdentifierUpdateRequest,
    responses(
        (status = 200, description = "更新後の識別子", body = LoginIdentifierResponse),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "利用者・識別子が見つからない"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_login_identifier(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<LoginIdentifierUpdateRequest>,
) -> Result<Json<LoginIdentifierResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let updated = state
        .login_identifiers_admin
        .set_active(
            tenant.context(),
            user_id,
            identifier_id,
            body.is_active,
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(updated.into()))
}

/// 識別子を削除する。`users.preferred_username` の写しは削除できない（プロフィール編集で変える）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}",
    tag = "admin",
    responses(
        (status = 204, description = "削除した"),
        (status = 400, description = "主たるログイン識別子の写しは削除できない"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "利用者・識別子が見つからない"),
    )
)]
pub async fn delete_login_identifier(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .login_identifiers_admin
        .remove(
            tenant.context(),
            user_id,
            identifier_id,
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_error(e: LoginIdentifierManagementError, locale: ApiLocale) -> ApiError {
    let messages = ApiMessages::new(locale);
    match e {
        LoginIdentifierManagementError::NotFound => {
            ApiError::NotFound(messages.get("api-user-not-found"))
        }
        LoginIdentifierManagementError::Validation(key) => {
            ApiError::BadRequest(messages.get_message(&key))
        }
        LoginIdentifierManagementError::Conflict(key) => {
            ApiError::Conflict(messages.get_message(&key))
        }
        LoginIdentifierManagementError::Internal(m) => ApiError::Internal(m),
    }
}
