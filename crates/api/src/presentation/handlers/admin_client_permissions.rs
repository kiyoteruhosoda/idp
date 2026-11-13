//! Granting, revoking and listing admin permissions for system clients
//! (`/{tenant_id}/admin/clients/{client_id}/permissions`, ADR-0037).
//!
//! Permission codes granted here become the `perms` claim of the admin token obtained via `client_credentials`
//! with `resource={issuer}/admin`. **This API is the entry point for letting machines operate the IdP**.
//!
//! Protected by `idp.clients:write` (reads: `idp.clients:read`). As it decides what a client is allowed to do,
//! it sits on the client-management side rather than permission management (`idp.permissions:write`) -- the
//! decision belongs to whoever owns the target's lifecycle (registration, revocation).
//!
//! Only fine-grained codes can be granted; `idp.tenant.admin` / `idp.system.admin` are
//! rejected by the application layer (`ClientPermissionManagementService`) and a DB CHECK constraint.

use crate::application::client_permission_management::ClientPermissionError;
use crate::presentation::admin::{ClientsRead, ClientsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::GrantClientPermissionRequest;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_admin_account_guard_error, request_context};
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use assay_contracts::admin::ClientPermissionsResponse;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::Json;

/// Lists the admin permission codes held by the target client.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients/{client_id}/permissions",
    tag = "admin",
    params(("client_id" = String, Path, description = "対象クライアントの client_id")),
    responses(
        (status = 200, description = "保有する権限コード一覧"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:read 必須）"),
        (status = 404, description = "対象クライアントが不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_client_permissions(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // The first path segment is `{tenant_id}` (discarded; already obtained from `ResolvedTenant`).
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientPermissionsResponse>, ApiError> {
    let codes = state
        .client_permissions_admin
        .list(tenant.context(), &client_id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientPermissionsResponse {
        client_id,
        permission_codes: codes,
    }))
}

/// Grants an admin permission code to the target client (idempotent). Returns the held codes after granting.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients/{client_id}/permissions",
    tag = "admin",
    params(("client_id" = String, Path, description = "対象クライアントの client_id")),
    request_body = GrantClientPermissionRequest,
    responses(
        (status = 200, description = "付与後の権限コード一覧"),
        (status = 400, description = "未知の権限コード・クライアントへ付与できないコード"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "対象クライアントが不存在"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn grant_client_permission(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<GrantClientPermissionRequest>,
) -> Result<Json<ClientPermissionsResponse>, ApiError> {
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
        .client_permissions_admin
        .grant(
            tenant.context(),
            tenant.tenant().is_root(),
            &client_id,
            &body.permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientPermissionsResponse {
        client_id,
        permission_codes: codes,
    }))
}

/// Revokes an admin permission code from the target client (not an error if not held).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/clients/{client_id}/permissions/{permission_code}",
    tag = "admin",
    params(
        ("client_id" = String, Path, description = "対象クライアントの client_id"),
        ("permission_code" = String, Path, description = "剥奪する権限コード"),
    ),
    responses(
        (status = 200, description = "剥奪後の権限コード一覧"),
        (status = 400, description = "権限コードが空"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "対象クライアントが不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn revoke_client_permission(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id, permission_code)): Path<(String, String, String)>,
) -> Result<Json<ClientPermissionsResponse>, ApiError> {
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
        .client_permissions_admin
        .revoke(
            tenant.context(),
            &client_id,
            &permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientPermissionsResponse {
        client_id,
        permission_codes: codes,
    }))
}

fn map_error(e: ClientPermissionError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        ClientPermissionError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
        ClientPermissionError::NotFound => ApiError::NotFound(msgs.get("api-client-not-found")),
        ClientPermissionError::Internal(m) => ApiError::Internal(m),
    }
}
