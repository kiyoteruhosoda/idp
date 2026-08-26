//! システム用クライアントへの管理権限の付与・剥奪・参照
//! （`/{tenant_id}/admin/clients/{client_id}/permissions`。ADR-0037）。
//!
//! ここで付与した権限コードが、`client_credentials` に `resource={issuer}/admin` を添えて得た
//! 管理トークンの `perms` クレームになる。**この API が IdP を機械から操作させるための入口**である。
//!
//! 保護は `idp.clients:write`（読み取りは `idp.clients:read`）。クライアントへ何を許すかを決める
//! 操作なので、権限管理（`idp.permissions:write`）ではなくクライアント管理の側に置く —— 対象の
//! ライフサイクル（登録・失効）と同じ人が握るべき判断だからである。
//!
//! 付与できるのは細粒度コードだけで、`idp.tenant.admin` / `idp.system.admin` は
//! Application 層（`ClientPermissionManagementService`）と DB の CHECK 制約が拒む。

use crate::application::client_permission_management::ClientPermissionError;
use crate::presentation::admin::{ClientsRead, ClientsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::GrantClientPermissionRequest;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use idp_contracts::admin::ClientPermissionsResponse;

/// 対象クライアントが保有する管理権限コードを一覧する。
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
    )
)]
pub async fn list_client_permissions(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // 先頭のパスセグメントは `{tenant_id}`（`ResolvedTenant` から取得済みのため破棄する）。
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

/// 対象クライアントへ管理権限コードを付与する（冪等）。付与後の保有コード一覧を返す。
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
    )
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
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let codes = state
        .client_permissions_admin
        .grant(
            tenant.context(),
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

/// 対象クライアントから管理権限コードを剥奪する（未保有でもエラーにしない）。
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
    )
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
