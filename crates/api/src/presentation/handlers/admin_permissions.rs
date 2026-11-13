//! User permission grant / revoke / query endpoints (`/admin/users/{user_id}/permissions`,
//! A2, ADR-0006, design spec §7).
//!
//! Reading needs `idp.permissions:read`; grant/revoke need `idp.permissions:write` (`RequirePerms<PermissionsRead>` /
//! `<PermissionsWrite>`; `idp.tenant.admin` implies both). Grants/revocations are recorded in `audit_log`
//! (`user_permission.granted` / `.revoked`). Decisions are made by the application layer (`PermissionManagementService`);
//! this handler only maps to HTTP.

use crate::domain::permission;
use crate::presentation::admin::{PermissionsRead, PermissionsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AvailablePermissionsResponse, GrantPermissionRequest, UserPermissionsResponse,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{
    map_admin_account_guard_error, map_permission_management_error, request_context,
};
use crate::presentation::i18n::ApiLocale;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use uuid::Uuid;

/// Lists grantable permission codes (the `permissions` master) (`GET /admin/permissions`).
/// A support API used for the choices of the grant form in the admin console (web).
///
/// **Codes that cannot be granted in the requesting tenant are always dropped.** `idp.system.admin` can only exist
/// in root scope (ADR-0009 §4), so returning it in a non-root tenant would make "a choice that always 403s".
/// ADR-0032's "don't show what can't be chosen" applies here too.
///
/// **Codes the caller cannot hand out are dropped too** (`permission::may_assign`, task #579).
///
/// With `?grantable_to=client`, it narrows further to **only codes grantable to clients** (ADR-0037).
/// Filtering in the api keeps the single source of the decision (the `domain::permission` functions) in core.
/// web does not depend on core (enforced by the crate boundary, ADR-0007), so writing the same decision in web would leave
/// **one side stale when the master grows**.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/permissions",
    tag = "admin",
    params(AvailablePermissionsQuery),
    responses(
        (status = 200, description = "要求テナントで付与し得る権限コード", body = AvailablePermissionsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.permissions:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_available_permissions(
    RequirePerms(admin, _): RequirePerms<PermissionsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(query): Query<AvailablePermissionsQuery>,
) -> Result<Json<AvailablePermissionsResponse>, ApiError> {
    let mut codes = state
        .permissions_admin
        .available_codes()
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    let tenant_is_root = tenant.tenant().is_root();
    codes.retain(|code| permission::is_grantable_in_tenant(code, tenant_is_root));
    // Also drop codes the caller cannot hand out (permissions it doesn't hold, task #579). The grant endpoint would 403 them.
    codes.retain(|code| permission::may_assign(&admin.permission_codes, code, tenant_is_root));
    if query.grantable_to.as_deref() == Some(GRANTABLE_TO_CLIENT) {
        codes.retain(|code| permission::is_grantable_to_client(code));
    }
    Ok(Json(AvailablePermissionsResponse { codes }))
}

/// The only allowed value of `grantable_to`. Unknown values don't filter (= all) -- not a 400 here because
/// it is a support API, and a misspelling only results in "too many candidates", which is harmless.
const GRANTABLE_TO_CLIENT: &str = "client";

/// Query of `GET /admin/permissions`.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub struct AvailablePermissionsQuery {
    /// With `client`, returns only codes grantable to clients.
    #[serde(default)]
    pub grantable_to: Option<String>,
}

/// Lists the permission codes held by the target user.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "保有する権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.permissions:read 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_permissions(
    RequirePerms(_admin, _): RequirePerms<PermissionsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // The first path segment is `{tenant_id}` (discarded; already obtained from `ResolvedTenant`).
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let codes = state
        .permissions_admin
        .list(tenant.context(), target)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// Grants a permission code to the target user (idempotent). Returns the held codes after granting.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = GrantPermissionRequest,
    responses(
        (status = 200, description = "付与後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "バリデーションエラー（未知の権限コード等）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.permissions:write 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn grant_permission(
    RequirePerms(admin, _): RequirePerms<PermissionsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<GrantPermissionRequest>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_assign(
            &admin.permission_codes,
            body.permission_code.trim(),
            tenant.tenant().is_root(),
        )
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let codes = state
        .permissions_admin
        .grant(
            tenant.context(),
            target,
            &body.permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// Revokes a permission code from the target user (not an error if not held). Returns the held codes after revoking.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}/permissions/{permission_code}",
    tag = "admin",
    params(
        ("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）"),
        ("permission_code" = String, Path, description = "剥奪する権限コード"),
    ),
    responses(
        (status = 200, description = "剥奪後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない・権限コードが空"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.permissions:write 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn revoke_permission(
    RequirePerms(admin, _): RequirePerms<PermissionsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id, permission_code)): Path<(String, String, String)>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_assign(
            &admin.permission_codes,
            permission_code.trim(),
            tenant.tenant().is_root(),
        )
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let codes = state
        .permissions_admin
        .revoke(
            tenant.context(),
            target,
            &permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

fn parse_user_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    use crate::presentation::i18n::ApiMessages;
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))
}
