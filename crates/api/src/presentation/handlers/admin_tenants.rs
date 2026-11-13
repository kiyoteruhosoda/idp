//! Tenant creation and management endpoints (`/{tenant_id}/admin/tenants`, ADR-0009 §4, §6).
//!
//! Getting/updating the own tenant (`/admin/settings/tenant`) needs `idp.tenant-settings:read` / `:write`
//! (`RequirePerms<TenantSettingsRead>` / `<TenantSettingsWrite>`; implied by `idp.tenant.admin`);
//! everything else (listing/creating/updating/deleting tenants, domains, reissuing child tenant admin passwords)
//! needs `idp.system.admin` (`RequirePerms<IdpSystemAdmin>`). `idp.system.admin` can only exist in root
//! scope, so effectively only system admins of the root tenant can create and delete tenants
//! (§4). On creation, **the creator themselves** is registered as the new tenant's bootstrap admin (ACTIVE GUEST +
//! `idp.tenant.admin`) (no plaintext password is returned). Decisions are made by the application layer
//! (`TenantManagementService`). Note that reissuing a child tenant admin's password
//! (`admin-password-reset`) remains available, targeting users registered after creation by email address.

use crate::application::tenant_management::{
    CreateTenantCommand, TenantManagementError, UpdateTenantCommand,
};
use crate::application::user_lifecycle::UserLifecycleError;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_domain::TenantDomain;
use crate::domain::values::TenantStatus;
use crate::presentation::admin::{
    IdpSystemAdmin, RequirePerms, TenantSettingsRead, TenantSettingsWrite,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AddTenantDomainRequest, CreateTenantRequest, PageQueryParams, TenantAdminPasswordResetRequest,
    TenantDomainResponse, TenantListResponse, TenantResponse, UpdateTenantRequest,
    UpdateTenantSettingsRequest, UserPasswordResetResponse,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

/// Returns one page of direct child tenants plus the total count (G7). Paging happens in the DB.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/tenants",
    tag = "admin",
    params(PageQueryParams),
    responses(
        (status = 200, description = "子テナント一覧（1 ページ分と総件数）", body = TenantListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_tenants(
    RequirePerms(_admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<PageQueryParams>,
) -> Result<Json<TenantListResponse>, ApiError> {
    let result = state
        .tenants_admin
        .list_children_page(tenant.context(), params.limit, params.offset)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(TenantListResponse {
        tenants: result.page.items.iter().map(tenant_response).collect(),
        total: result.page.total,
        limit: result.applied.limit(),
        offset: result.applied.offset(),
    }))
}

/// Creates a child tenant. The creator becomes the new tenant's bootstrap admin (ACTIVE GUEST +
/// `idp.tenant.admin`) (ADR-0009 §4). The creator then registers and grants the real admins, and then removes
/// themselves and leaves.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/tenants",
    tag = "admin",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "作成成功（作成したテナント）", body = TenantResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 409, description = "テナント作成の一意制約違反等"),
    ),
    security(("bearer_token" = []))
)]
pub async fn create_tenant(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let created = state
        .tenants_admin
        .create_tenant(
            tenant.context(),
            CreateTenantCommand { name: body.name },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(tenant_response(&created))))
}

/// Gets one direct child tenant.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/tenants/{child_id}",
    tag = "admin",
    params(("child_id" = String, Path, description = "子テナントの UUID")),
    responses(
        (status = 200, description = "テナント", body = TenantResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "不存在（直下の子でない場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_tenant(
    RequirePerms(_admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, child_id)): Path<(String, String)>,
) -> Result<Json<TenantResponse>, ApiError> {
    let child = parse_tenant_id(&child_id, locale)?;
    let found = state
        .tenants_admin
        .get_child(tenant.context(), child)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(tenant_response(&found)))
}

/// Partially updates a child tenant's display name and status.
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/tenants/{child_id}",
    tag = "admin",
    params(("child_id" = String, Path, description = "子テナントの UUID")),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "更新後のテナント", body = TenantResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_tenant(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, child_id)): Path<(String, String)>,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    let child = parse_tenant_id(&child_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let status = body
        .status
        .as_deref()
        .map(TenantStatus::parse)
        .transpose()
        .map_err(|_| {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-tenant-status-invalid"))
        })?;
    let updated = state
        .tenants_admin
        .update_tenant(
            tenant.context(),
            child,
            UpdateTenantCommand {
                name: body.name,
                status,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    // The resolution cache holds the pre-update name and status. Unless dropped, subsequent requests keep showing the old name
    // in the header and deciding with the old status for the TTL (TENANT_CACHE_TTL_SECS).
    state.tenant_resolution.invalidate(updated.id);
    Ok(Json(tenant_response(&updated)))
}

/// Deletes a child tenant. 409 if child tenants, users or clients exist under it.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/tenants/{child_id}",
    tag = "admin",
    params(("child_id" = String, Path, description = "子テナントの UUID")),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）・root は削除不可"),
        (status = 404, description = "不存在"),
        (status = 409, description = "配下に子テナント・ユーザー・クライアントが存在する"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_tenant(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, child_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let child = parse_tenant_id(&child_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .tenants_admin
        .delete_tenant(tenant.context(), child, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    // Drop the deleted tenant (= must never resolve again) from the resolution cache.
    state.tenant_resolution.invalidate(child);
    Ok(StatusCode::NO_CONTENT)
}

/// Reissues the password of a child tenant's user (e.g. the initial admin registered with the tenant)
/// (`POST /{tenant_id}/admin/tenants/{child_id}/admin-password-reset`).
///
/// The target is a user **belonging to a direct child tenant**, specified by email address. Generates a random
/// password of 32+ characters, sets `must_change_password`, and returns `setup_url` in plaintext
/// **only in this response** (same pattern as tenant creation, ADR-0009 §5).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/tenants/{child_id}/admin-password-reset",
    tag = "admin",
    params(("child_id" = String, Path, description = "子テナントの UUID")),
    request_body = TenantAdminPasswordResetRequest,
    responses(
        (status = 200, description = "再発行成功（setup_url を含む）", body = UserPasswordResetResponse),
        (status = 400, description = "email が未指定"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "テナントまたは利用者が不存在"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn reset_tenant_admin_password(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, child_id)): Path<(String, String)>,
    Json(body): Json<TenantAdminPasswordResetRequest>,
) -> Result<Json<UserPasswordResetResponse>, ApiError> {
    let child = parse_tenant_id(&child_id, locale)?;
    // Verify it is a direct child tenant (don't allow targeting tenants of other lineages).
    let child_tenant = state
        .tenants_admin
        .get_child(tenant.context(), child)
        .await
        .map_err(|e| map_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reset = state
        .users_lifecycle
        .reset_password_by_email(
            TenantContext::new(child_tenant.id),
            &body.email,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_lifecycle_error(e, locale))?;
    Ok(Json(UserPasswordResetResponse {
        user_id: reset.user_id.to_string(),
        setup_url: reset.setup_link.url,
        setup_expires_at: reset.setup_link.expires_at.to_rfc3339(),
    }))
}

/// Tenant section of the settings screen: gets the own tenant (the requesting tenant itself) (requires `idp.tenant-settings:read`, MT14).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/tenant",
    tag = "admin",
    responses(
        (status = 200, description = "自テナント", body = TenantResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_current_tenant(
    RequirePerms(_admin, _): RequirePerms<TenantSettingsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<TenantResponse>, ApiError> {
    let current = state
        .tenants_admin
        .get_current(tenant.context())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(tenant_response(&current)))
}

/// Tenant section of the settings screen: updates the own tenant's display name (requires `idp.tenant-settings:write`, MT14).
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/settings/tenant",
    tag = "admin",
    request_body = UpdateTenantSettingsRequest,
    responses(
        (status = 200, description = "更新後の自テナント", body = TenantResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update_current_tenant(
    RequirePerms(admin, _): RequirePerms<TenantSettingsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<UpdateTenantSettingsRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let updated = state
        .tenants_admin
        .update_current_settings(
            tenant.context(),
            body.name,
            body.self_registration_enabled,
            body.email_login_enabled,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    // Drop the resolution cache. The admin console header gets the display name from whoami (= the resolved tenant),
    // so without dropping it, right after a rename the screen shows "new name in the body, old name in the header".
    state.tenant_resolution.invalidate(updated.id);
    Ok(Json(tenant_response(&updated)))
}

// ── Domain assignment (ADR-0029) ────────────────────────────────────────────────
//
// Targets are **the own tenant or direct children**. Root itself needs domains too (root's users enter the tenants
// they created as guests), so it is not limited to children. Decisions are made by the application layer.

/// Lists the domains assigned to the tenant.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/tenants/{target_id}/domains",
    tag = "admin",
    responses(
        (status = 200, description = "割り当て済みドメイン", body = Vec<TenantDomainResponse>),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "対象テナントが存在しない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_tenant_domains(
    RequirePerms(_admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, target_id)): Path<(String, String)>,
) -> Result<Json<Vec<TenantDomainResponse>>, ApiError> {
    let target = parse_tenant_id(&target_id, locale)?;
    let domains = state
        .tenants_admin
        .list_domains(tenant.context(), target)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(domains.iter().map(domain_response).collect()))
}

/// Assigns a domain. 409 if **any tenant** already holds it (uniqueness is global).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/tenants/{target_id}/domains",
    tag = "admin",
    request_body = AddTenantDomainRequest,
    responses(
        (status = 201, description = "割り当てたドメイン", body = TenantDomainResponse),
        (status = 400, description = "ドメインとして読めない値"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "対象テナントが存在しない"),
        (status = 409, description = "すでに割り当て済み（他テナントの場合も含む）"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn add_tenant_domain(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, target_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<AddTenantDomainRequest>,
) -> Result<(StatusCode, Json<TenantDomainResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let target = parse_tenant_id(&target_id, locale)?;
    let added = state
        .tenants_admin
        .add_domain(tenant.context(), target, &body.domain, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(domain_response(&added))))
}

/// Removes an assignment.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/tenants/{target_id}/domains/{domain_id}",
    tag = "admin",
    responses(
        (status = 204, description = "解除した"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "対象テナント、または割り当てが存在しない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn remove_tenant_domain(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, target_id, domain_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let target = parse_tenant_id(&target_id, locale)?;
    state
        .tenants_admin
        .remove_domain(tenant.context(), target, domain_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn domain_response(d: &TenantDomain) -> TenantDomainResponse {
    TenantDomainResponse {
        id: d.id.to_string(),
        tenant_id: d.tenant_id.to_string(),
        domain: d.domain.clone(),
        created_at: d.created_at.to_rfc3339(),
        updated_at: d.updated_at.to_rfc3339(),
    }
}

fn tenant_response(t: &Tenant) -> TenantResponse {
    TenantResponse {
        id: t.id.to_string(),
        parent_tenant_id: t.parent_tenant_id.map(|p| p.to_string()),
        name: t.name.clone(),
        status: t.status.as_str().to_string(),
        self_registration_enabled: t.self_registration_enabled,
        email_login_enabled: t.email_login_enabled,
        created_at: t.created_at.to_rfc3339(),
        updated_at: t.updated_at.to_rfc3339(),
    }
}

fn parse_tenant_id(raw: &str, locale: ApiLocale) -> Result<TenantId, ApiError> {
    Uuid::parse_str(raw)
        .map(TenantId::from)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-tenant-not-found")))
}

fn map_lifecycle_error(e: UserLifecycleError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        UserLifecycleError::NotFound => ApiError::NotFound(msgs.get("api-user-not-found")),
        UserLifecycleError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        UserLifecycleError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        UserLifecycleError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        UserLifecycleError::Internal(m) => ApiError::Internal(m),
    }
}

fn map_error(e: TenantManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        TenantManagementError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        TenantManagementError::NotFound => ApiError::NotFound(msgs.get("api-tenant-not-found")),
        TenantManagementError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        TenantManagementError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        TenantManagementError::Internal(m) => ApiError::Internal(m),
    }
}
