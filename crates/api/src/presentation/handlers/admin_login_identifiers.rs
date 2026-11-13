//! Login identifier management API (`/{tenant_id}/admin/users/{user_id}/login-identifiers`, AP8).
//!
//! Tenant admins assign **multiple login identifiers** to a user (phone number, employee number, alias username,
//! email address). Listing needs `idp.users:read`; add/update/delete/promote to primary email need
//! `idp.users:write` (`RequirePerms<UsersRead>` / `<UsersWrite>`; `idp.tenant.admin` implies both).
//!
//! Responses return both the `display_value` as registered and the match key `normalized_value`. Unless admins
//! can compare "the value registered" with "the value that actually matches", they cannot notice misconfigured
//! identifiers whose notation varies, like phone numbers.

use crate::application::login_identifier_management::{
    AddLoginIdentifierCommand, LoginIdentifierEntry, LoginIdentifierManagementError,
};
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::presentation::admin::{RequirePerms, UsersRead, UsersWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_admin_account_guard_error, request_context};
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
    /// Registry row id. `null` is a row for the **primary login identifier** (`users.preferred_username`)
    /// synthesized on read, not stored. `is_primary` is `true` for it.
    pub id: Option<String>,
    /// `username` / `email` / `phone_number` / `employee_number`.
    pub identifier_type: String,
    /// The value as registered (for display).
    pub display_value: String,
    /// Match key (the value with per-kind normalization applied).
    pub normalized_value: String,
    pub is_active: bool,
    /// Whether this is the primary login identifier. Rows with `true` cannot be changed or deleted per identifier
    /// (to change it edit the profile; to stop it disable the account).
    pub is_primary: bool,
    /// Whether this is the primary email row (ADR-0050). Like the primary identifier, not subject to individual operations.
    pub is_primary_email: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<LoginIdentifierEntry> for LoginIdentifierResponse {
    fn from(v: LoginIdentifierEntry) -> Self {
        Self {
            id: v.id.map(|id| id.to_string()),
            identifier_type: v.identifier_type.as_str().to_string(),
            display_value: v.display_value,
            normalized_value: v.normalized_value,
            is_active: v.is_active,
            is_primary: v.is_primary,
            is_primary_email: v.is_primary_email,
            created_at: v.created_at.to_rfc3339(),
            updated_at: v.updated_at.to_rfc3339(),
        }
    }
}

impl From<UserLoginIdentifier> for LoginIdentifierResponse {
    fn from(v: UserLoginIdentifier) -> Self {
        LoginIdentifierEntry::from(v).into()
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginIdentifierCreateRequest {
    /// `username` / `email` / `phone_number` / `employee_number`.
    pub identifier_type: String,
    pub value: String,
    /// Enabled when omitted.
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

/// Lists the user's login identifiers. Also returns disabled rows (disabled identifiers remain managed).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers",
    tag = "admin",
    responses(
        (status = 200, description = "識別子の一覧", body = [LoginIdentifierResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:read 必須）"),
        (status = 404, description = "利用者が見つからない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_login_identifiers(
    RequirePerms(_admin, _): RequirePerms<UsersRead>,
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

/// Adds a login identifier.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers",
    tag = "admin",
    request_body = LoginIdentifierCreateRequest,
    responses(
        (status = 201, description = "追加した識別子", body = LoginIdentifierResponse),
        (status = 400, description = "種別・値が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "利用者が見つからない"),
        (status = 409, description = "同じ値が他の利用者に解決される"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn add_login_identifier(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<LoginIdentifierCreateRequest>,
) -> Result<(StatusCode, Json<LoginIdentifierResponse>), ApiError> {
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            user_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(added.into())))
}

/// Toggles enabled/disabled per identifier (spec §4). The row remains, so the value never moves to another user.
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}",
    tag = "admin",
    request_body = LoginIdentifierUpdateRequest,
    responses(
        (status = 200, description = "更新後の識別子", body = LoginIdentifierResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "利用者・識別子が見つからない"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_login_identifier(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<LoginIdentifierUpdateRequest>,
) -> Result<Json<LoginIdentifierResponse>, ApiError> {
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            user_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(updated.into()))
}

/// Promotes an alias email address to the primary email (ADR-0052).
///
/// **Not a `PATCH` field.** Promotion is not "set this row's value to `true`" but a **swap** of demoting the current
/// primary email row and promoting the chosen row. As a writable field, `is_primary_email: false`
/// (= no primary email at all) could be written as a request, which cannot be accepted.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}/primary-email",
    tag = "admin",
    responses(
        (status = 200, description = "昇格後の識別子", body = LoginIdentifierResponse),
        (status = 400, description = "メール種別の識別子ではない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "利用者・識別子が見つからない"),
        (status = 409, description = "そのアドレスは既に他の利用者のものになっている"),
    ),
    security(("bearer_token" = []))
)]
pub async fn promote_primary_email(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<LoginIdentifierResponse>, ApiError> {
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            user_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let promoted = state
        .login_identifiers_admin
        .promote_email(tenant.context(), user_id, identifier_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(promoted.into()))
}

/// Deletes an identifier. The primary login identifier (`is_primary`) is not in the registry, so it is not a target.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}/login-identifiers/{identifier_id}",
    tag = "admin",
    responses(
        (status = 204, description = "削除した"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "利用者・識別子が見つからない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_login_identifier(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            user_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .login_identifiers_admin
        .remove(tenant.context(), user_id, identifier_id, &admin.actor, &ctx)
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
