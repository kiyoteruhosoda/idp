//! テナント作成・管理エンドポイント（`/{tenant_id}/admin/tenants`。ADR-0009 §4・§6）。
//!
//! すべて `idp.system.admin` 権限が必要（`RequirePerms<IdpSystemAdmin>`）。`idp.system.admin` は root
//! scope でしか存在できないため、実質的にテナントを作成・削除できるのは root テナントの system 管理者
//! だけになる（§4）。作成時は**作成者自身**を新テナントのブートストラップ管理者（ACTIVE GUEST +
//! `idp.tenant.admin`）として登録する（平文パスワードは返さない）。判定は Application 層
//! （`TenantManagementService`）が行う。なお、子テナント管理者のパスワード再発行
//! （`admin-password-reset`）は、作成後に登録された利用者をメールアドレスで対象に残置する。

use crate::application::tenant_management::{
    CreateTenantCommand, TenantManagementError, UpdateTenantCommand,
};
use crate::application::user_lifecycle::UserLifecycleError;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::TenantStatus;
use crate::presentation::admin::{IdpAdmin, IdpSystemAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    CreateTenantRequest, PageQueryParams, TenantAdminPasswordResetRequest, TenantListResponse,
    TenantResponse, UpdateTenantRequest, UpdateTenantSettingsRequest, UserPasswordResetResponse,
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

/// 直下の子テナントを 1 ページ分と総件数で返す（G7）。ページングは DB 側で行う。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/tenants",
    tag = "admin",
    params(PageQueryParams),
    responses(
        (status = 200, description = "子テナント一覧（1 ページ分と総件数）", body = TenantListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    )
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

/// 子テナントを作成する。作成者自身が新テナントのブートストラップ管理者（ACTIVE GUEST +
/// `idp.tenant.admin`）になる（ADR-0009 §4）。作成者は以後、正式な管理者を登録・付与してから自身を
/// 解除して離脱する。
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
    )
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(tenant_response(&created))))
}

/// 直下の子テナント 1 件を取得する。
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
    )
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

/// 子テナントの表示名・状態を部分更新する。
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
    )
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    // 解決キャッシュには更新前の名称・状態が載っている。捨てないと、次のリクエストが TTL
    // （TENANT_CACHE_TTL_SECS）の間だけ旧名称のヘッダ表示・旧 status での可否判定を続ける。
    state.tenant_resolution.invalidate(updated.id);
    Ok(Json(tenant_response(&updated)))
}

/// 子テナントを削除する。配下に子テナント・ユーザー・クライアントが存在する場合は 409。
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
    )
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
        .delete_tenant(tenant.context(), child, admin.user_id, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    // 削除した（＝以後解決してはならない）テナントを解決キャッシュから捨てる。
    state.tenant_resolution.invalidate(child);
    Ok(StatusCode::NO_CONTENT)
}

/// 子テナントの利用者（テナント登録時の初期管理者等）のパスワードを再発行する
/// （`POST /{tenant_id}/admin/tenants/{child_id}/admin-password-reset`）。
///
/// 対象は**直下の子テナント所属**の利用者をメールアドレスで指定する。32 文字以上のランダム
/// パスワードを自動生成して `must_change_password` を設定し、`generated_password` を
/// **この応答でのみ**平文で返す（テナント作成時と同じパターン。ADR-0009 §5）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/tenants/{child_id}/admin-password-reset",
    tag = "admin",
    params(("child_id" = String, Path, description = "子テナントの UUID")),
    request_body = TenantAdminPasswordResetRequest,
    responses(
        (status = 200, description = "再発行成功（generated_password を含む）", body = UserPasswordResetResponse),
        (status = 400, description = "email が未指定"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
        (status = 404, description = "テナントまたは利用者が不存在"),
    )
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
    // 直下の子テナントであることを検証する（他系統のテナントを対象にさせない）。
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_lifecycle_error(e, locale))?;
    Ok(Json(UserPasswordResetResponse {
        user_id: reset.user_id.to_string(),
        generated_password: reset.generated_password,
    }))
}

/// 設定画面のテナント設定区画: 自テナント（要求テナント自身）を取得する（`idp.tenant.admin` 必須。MT14）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/tenant",
    tag = "admin",
    responses(
        (status = 200, description = "自テナント", body = TenantResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn get_current_tenant(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

/// 設定画面のテナント設定区画: 自テナントの表示名を更新する（`idp.tenant.admin` 必須。MT14）。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/settings/tenant",
    tag = "admin",
    request_body = UpdateTenantSettingsRequest,
    responses(
        (status = 200, description = "更新後の自テナント", body = TenantResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn update_current_tenant(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    // 解決キャッシュを捨てる。管理コンソールのヘッダは whoami（＝解決済みテナント）から表示名を
    // 得るため、捨てないと改名直後に「本文は新名称・ヘッダは旧名称」の画面になる。
    state.tenant_resolution.invalidate(updated.id);
    Ok(Json(tenant_response(&updated)))
}

fn tenant_response(t: &Tenant) -> TenantResponse {
    TenantResponse {
        id: t.id.to_string(),
        parent_tenant_id: t.parent_tenant_id.map(|p| p.to_string()),
        name: t.name.clone(),
        status: t.status.as_str().to_string(),
        self_registration_enabled: t.self_registration_enabled,
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
