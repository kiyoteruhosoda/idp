//! Registering protected resources (the audience names put in `aud`) and lending them to clients
//! (`/{tenant_id}/admin/resources`, `/{tenant_id}/admin/clients/{client_id}/resources`, ADR-0042).
//!
//! A name registered here becomes the `aud` of a token obtained via `client_credentials` with `resource=<name>`.
//! **Only the audience is carried, not what may be done there** (ADR-0033; the resource server
//! decides by `client_id`).
//!
//! Protected by `idp.resources:read` / `idp.resources:write`. It is separate from client management (`idp.clients:*`)
//! because audiences are an independent registry that outlives clients -- deleting one RP does not
//! make the name of the API it exposed go away for other callers.

use crate::application::resource_management::ResourceManagementError;
use crate::domain::resource::ProtectedResource;
use crate::domain::values::ResourceStatus;
use crate::presentation::admin::{RequirePerms, ResourcesRead, ResourcesWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    RegisterResourceRequest, ResourceListResponse, ResourceResponse, UpdateResourceStatusRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

/// Lists registered audiences (`GET /{tenant_id}/admin/resources`).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/resources",
    tag = "admin",
    responses(
        (status = 200, description = "宛名の一覧", body = ResourceListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_resources(
    RequirePerms(_admin, _): RequirePerms<ResourcesRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let resources = state
        .resources_admin
        .list(tenant.context())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_list(resources)))
}

/// Registers an audience (`POST /{tenant_id}/admin/resources`).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/resources",
    tag = "admin",
    request_body = RegisterResourceRequest,
    responses(
        (status = 201, description = "登録成功", body = ResourceResponse),
        (status = 400, description = "絶対 URI でない・fragment 付き・予約済みの宛名"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:write 必須）"),
        (status = 409, description = "同じ宛名が登録済み"),
    ),
    security(("bearer_token" = []))
)]
pub async fn register_resource(
    RequirePerms(admin, _): RequirePerms<ResourcesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<RegisterResourceRequest>,
) -> Result<(StatusCode, Json<ResourceResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let resource = state
        .resources_admin
        .register(
            tenant.context(),
            &body.resource_uri,
            &body.display_name,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(to_response(&resource))))
}

/// Changes an audience's status (`PATCH /{tenant_id}/admin/resources/{resource_id}`).
///
/// `DISABLED` means it **can no longer be the audience of new tokens**, but already issued tokens stay
/// valid until they expire (signed claims cannot be revoked).
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/resources/{resource_id}",
    tag = "admin",
    params(("resource_id" = String, Path, description = "対象の宛名の内部 ID（UUID）")),
    request_body = UpdateResourceStatusRequest,
    responses(
        (status = 200, description = "変更後の宛名", body = ResourceResponse),
        (status = 400, description = "未知の状態値"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:write 必須）"),
        (status = 404, description = "不存在（他テナントの宛名を含む）"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_resource_status(
    RequirePerms(admin, _): RequirePerms<ResourcesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, resource_id)): Path<(String, String)>,
    Json(body): Json<UpdateResourceStatusRequest>,
) -> Result<Json<ResourceResponse>, ApiError> {
    let id = parse_resource_id(&resource_id, locale)?;
    let status = ResourceStatus::parse(body.status.trim()).map_err(|_| {
        ApiError::BadRequest(ApiMessages::new(locale).get("api-resource-status-invalid"))
    })?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let resource = state
        .resources_admin
        .set_status(tenant.context(), id, status, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_response(&resource)))
}

/// Deletes an audience (`DELETE /{tenant_id}/admin/resources/{resource_id}`). Its loans are deleted too.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/resources/{resource_id}",
    tag = "admin",
    params(("resource_id" = String, Path, description = "対象の宛名の内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:write 必須）"),
        (status = 404, description = "不存在（他テナントの宛名を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_resource(
    RequirePerms(admin, _): RequirePerms<ResourcesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, resource_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_resource_id(&resource_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .resources_admin
        .delete(tenant.context(), id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_resource_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-resource-not-found")))
}

fn to_response(resource: &ProtectedResource) -> ResourceResponse {
    ResourceResponse {
        id: resource.id.to_string(),
        resource_uri: resource.resource_uri.clone(),
        display_name: resource.display_name.clone(),
        status: resource.status.as_str().to_string(),
        created_at: resource.created_at.to_rfc3339(),
        updated_at: resource.updated_at.to_rfc3339(),
    }
}

fn to_list(resources: Vec<ProtectedResource>) -> ResourceListResponse {
    ResourceListResponse {
        resources: resources.iter().map(to_response).collect(),
    }
}

fn map_error(e: ResourceManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        ResourceManagementError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
        ResourceManagementError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        ResourceManagementError::NotFound => ApiError::NotFound(msgs.get("api-resource-not-found")),
        ResourceManagementError::Internal(m) => ApiError::Internal(m),
    }
}
