//! 保護リソース（`aud` に入る宛名）の登録と、クライアントへの貸し出し
//! （`/{tenant_id}/admin/resources`・`/{tenant_id}/admin/clients/{client_id}/resources`。ADR-0042）。
//!
//! ここで登録した名前が、`client_credentials` に `resource=<名前>` を添えて得たトークンの `aud` に
//! なる。**載るのは宛名だけで、そこで何をしてよいかは載らない**（ADR-0033。リソースサーバが
//! `client_id` で決める）。
//!
//! 保護は `idp.resources:read` / `idp.resources:write`。クライアント管理（`idp.clients:*`）と
//! 分けるのは、宛名がクライアントより長生きする独立した登録簿だからである——RP を 1 つ消しても、
//! その RP が公開していた API の名前は他の呼び出し元にとって在り続ける。

use crate::application::resource_management::ResourceManagementError;
use crate::domain::resource::ProtectedResource;
use crate::domain::values::ResourceStatus;
use crate::presentation::admin::{RequirePerms, ResourcesRead, ResourcesWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    ClientResourceRequest, RegisterResourceRequest, ResourceListResponse, ResourceResponse,
    UpdateResourceStatusRequest,
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

/// 登録済みの宛名を一覧する（`GET /{tenant_id}/admin/resources`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/resources",
    tag = "admin",
    responses(
        (status = 200, description = "宛名の一覧", body = ResourceListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:read 必須）"),
    )
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

/// 宛名を登録する（`POST /{tenant_id}/admin/resources`）。
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
    )
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

/// 宛名の状態を変える（`PATCH /{tenant_id}/admin/resources/{resource_id}`）。
///
/// `DISABLED` にすると**新しいトークンの宛先に使えなくなる**が、発行済みのトークンは寿命が
/// 尽きるまで有効なままである（署名済みのクレームは取り消せない）。
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
    )
)]
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

/// 宛名を削除する（`DELETE /{tenant_id}/admin/resources/{resource_id}`）。貸し出しも一緒に消える。
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
    )
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

/// クライアントへ許した宛名を一覧する（`GET /{tenant_id}/admin/clients/{client_id}/resources`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients/{client_id}/resources",
    tag = "admin",
    params(("client_id" = String, Path, description = "対象クライアントの client_id")),
    responses(
        (status = 200, description = "許可済みの宛名一覧", body = ResourceListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:read 必須）"),
        (status = 404, description = "対象クライアントが不存在"),
    )
)]
pub async fn list_client_resources(
    RequirePerms(_admin, _): RequirePerms<ResourcesRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let resources = state
        .resources_admin
        .list_for_client(tenant.context(), &client_id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_list(resources)))
}

/// クライアントへ宛名を許可する（冪等。`POST /{tenant_id}/admin/clients/{client_id}/resources`）。
///
/// 貸すときは**名前**で指す。運用で書く値は登録した宛名そのもので、内部 ID ではないからである。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients/{client_id}/resources",
    tag = "admin",
    params(("client_id" = String, Path, description = "対象クライアントの client_id")),
    request_body = ClientResourceRequest,
    responses(
        (status = 200, description = "許可後の宛名一覧", body = ResourceListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:write 必須）"),
        (status = 404, description = "クライアントまたは宛名が不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn grant_client_resource(
    RequirePerms(admin, _): RequirePerms<ResourcesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<ClientResourceRequest>,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let resources = state
        .resources_admin
        .grant(
            tenant.context(),
            &client_id,
            &body.resource_uri,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_list(resources)))
}

/// クライアントの許可を取り消す
/// （`DELETE /{tenant_id}/admin/clients/{client_id}/resources/{resource_id}`）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/clients/{client_id}/resources/{resource_id}",
    tag = "admin",
    params(
        ("client_id" = String, Path, description = "対象クライアントの client_id"),
        ("resource_id" = String, Path, description = "取り消す宛名の内部 ID（UUID）"),
    ),
    responses(
        (status = 200, description = "取り消し後の宛名一覧", body = ResourceListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.resources:write 必須）"),
        (status = 404, description = "クライアントまたは宛名が不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn revoke_client_resource(
    RequirePerms(admin, _): RequirePerms<ResourcesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id, resource_id)): Path<(String, String, String)>,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let id = parse_resource_id(&resource_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let resources = state
        .resources_admin
        .revoke(tenant.context(), &client_id, id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_list(resources)))
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
