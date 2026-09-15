//! アプリの管理（`/{tenant_id}/admin/applications`。ADR-0054）。
//!
//! アプリは「利用者から見た 1 つのアプリ」であり、OIDC の `clients` や SAML の
//! `saml_service_providers` は**そのアプリがどう繋がるか**（binding）でしかない。認証ポリシー・
//! 利用者の割り当て・停止はこの段に付く。
//!
//! 保護は `idp.applications:read` / `idp.applications:write`。クライアント管理（`idp.clients:*`）と
//! 分けるのは、⚠ **「繋ぎ方を直せる人」と「誰が使ってよいかを決める人」が同じとは限らない**
//! ためである。前者は RP を作る側の作業、後者は組織の判断になる。

use crate::application::application_management::{
    ApplicationDetail, ApplicationManagementError, ApplicationSummary, CurrentUsers, NewApplication,
};
use crate::domain::values::{ApplicationStatus, AssignmentMode};
use crate::presentation::admin::{ApplicationsRead, ApplicationsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    ApplicationAssignmentResponse, ApplicationBindingResponse, ApplicationCurrentUserResponse,
    ApplicationCurrentUsersResponse, ApplicationDetailResponse, ApplicationListResponse,
    ApplicationResponse, CreateApplicationAssignmentRequest, CreateApplicationBindingRequest,
    CreateApplicationRequest, UpdateApplicationRequest,
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

/// アプリを一覧する（`GET /{tenant_id}/admin/applications`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications",
    tag = "admin",
    responses(
        (status = 200, description = "アプリの一覧", body = ApplicationListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
    )
)]
pub async fn list_applications(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<ApplicationListResponse>, ApiError> {
    let applications = state
        .applications_admin
        .list(tenant.context())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ApplicationListResponse {
        applications: applications.iter().map(to_response).collect(),
        enforcement: state
            .config
            .application_assignment_enforcement()
            .as_str()
            .to_string(),
    }))
}

/// アプリ 1 件の詳細（`GET /{tenant_id}/admin/applications/{application_id}`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications/{application_id}",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    responses(
        (status = 200, description = "アプリの詳細", body = ApplicationDetailResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
        (status = 404, description = "不存在（他テナントのアプリを含む）"),
    )
)]
pub async fn get_application(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Result<Json<ApplicationDetailResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_detail(&detail)))
}

/// アプリを登録する（`POST /{tenant_id}/admin/applications`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/applications",
    tag = "admin",
    request_body = CreateApplicationRequest,
    responses(
        (status = 201, description = "登録成功", body = ApplicationResponse),
        (status = 400, description = "表示名が空・長すぎる／割り当てモードが不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
    )
)]
pub async fn create_application(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<CreateApplicationRequest>,
) -> Result<(StatusCode, Json<ApplicationResponse>), ApiError> {
    // ⚠ 省略時は「個別」。既定を「全員」にすると、絞り忘れたアプリが全員に開いたままになる。
    let assignment_mode = match body.assignment_mode.as_deref() {
        Some(raw) => parse_assignment_mode(raw, locale)?,
        None => AssignmentMode::Individual,
    };
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let application = state
        .applications_admin
        .create(
            tenant.context(),
            NewApplication {
                display_name: body.display_name,
                assignment_mode,
                assign_creator: body.assign_creator,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    // 作った直後の詳細を返す（割り当てた本人が名簿に居ることを、呼び出し側が確かめられる）。
    let detail = state
        .applications_admin
        .detail(tenant.context(), application.id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(to_detail(&detail).application)))
}

/// アプリを更新する（`PUT /{tenant_id}/admin/applications/{application_id}`）。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/applications/{application_id}",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    request_body = UpdateApplicationRequest,
    responses(
        (status = 200, description = "更新後のアプリ", body = ApplicationResponse),
        (status = 400, description = "表示名・状態・割り当てモードが不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_application(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Json(body): Json<UpdateApplicationRequest>,
) -> Result<Json<ApplicationResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let status = parse_status(&body.status, locale)?;
    let assignment_mode = parse_assignment_mode(&body.assignment_mode, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .update(
            tenant.context(),
            id,
            &body.display_name,
            status,
            assignment_mode,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_detail(&detail).application))
}

/// アプリを削除する（`DELETE /{tenant_id}/admin/applications/{application_id}`）。
///
/// ⚠ **ぶら下がっている RP の登録は消えない。** 消えるのは括りと名簿だけである。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/applications/{application_id}",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn delete_application(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .delete(tenant.context(), id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 認証方法を繋ぐ（`POST /{tenant_id}/admin/applications/{application_id}/bindings`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/applications/{application_id}/bindings",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    request_body = CreateApplicationBindingRequest,
    responses(
        (status = 200, description = "追加後のアプリ", body = ApplicationResponse),
        (status = 400, description = "client_id と service_provider_id のどちらも無い・両方ある"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリ・相手が不存在"),
        (status = 409, description = "その相手は既に別のアプリへ繋がっている"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn add_binding(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Json(body): Json<CreateApplicationBindingRequest>,
) -> Result<Json<ApplicationResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    // ⚠ `ApiMessages`（FluentBundle）は `Send` ではない。await をまたいで持てないので、
    // **繋ぐ相手を先に決め切ってから**非同期の呼び出しへ入る。
    let target = match (
        body.client_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        body.service_provider_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(client_id), None) => BindingRequest::Oidc(client_id.to_string()),
        (None, Some(raw)) => BindingRequest::Saml(Uuid::parse_str(raw).map_err(|_| {
            ApiError::NotFound(ApiMessages::new(locale).get("api-application-not-found"))
        })?),
        // ⚠ 両方・どちらも無し、は「どのプロトコルで繋ぐのか」が決まらない。既定を置かない。
        _ => {
            return Err(ApiError::BadRequest(
                ApiMessages::new(locale).get("api-application-binding-target-required"),
            ))
        }
    };
    match target {
        BindingRequest::Oidc(client_id) => {
            state
                .applications_admin
                .bind_client(tenant.context(), id, &client_id, &admin.actor, &ctx)
                .await
                .map_err(|e| map_error(e, locale))?;
        }
        BindingRequest::Saml(provider_id) => {
            state
                .applications_admin
                .bind_service_provider(tenant.context(), id, provider_id, &admin.actor, &ctx)
                .await
                .map_err(|e| map_error(e, locale))?;
        }
    }
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_detail(&detail).application))
}

/// 認証方法を外す
/// （`DELETE /{tenant_id}/admin/applications/{application_id}/bindings/{binding_id}`）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/applications/{application_id}/bindings/{binding_id}",
    tag = "admin",
    params(
        ("application_id" = String, Path, description = "アプリの内部 ID"),
        ("binding_id" = String, Path, description = "binding の内部 ID"),
    ),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn remove_binding(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id, binding_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let binding = parse_id(&binding_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .unbind(tenant.context(), id, binding, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 利用者を割り当てる
/// （`POST /{tenant_id}/admin/applications/{application_id}/assignments`。冪等）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/applications/{application_id}/assignments",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    request_body = CreateApplicationAssignmentRequest,
    responses(
        (status = 200, description = "割り当て後の詳細", body = ApplicationDetailResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリ・利用者が不存在（他テナントの利用者を含む）"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn assign_user(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Json(body): Json<CreateApplicationAssignmentRequest>,
) -> Result<Json<ApplicationDetailResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let user_id = parse_user_id(&body.user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .assign(tenant.context(), id, user_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_detail(&detail)))
}

/// 割り当てを外す
/// （`DELETE /{tenant_id}/admin/applications/{application_id}/assignments/{user_id}`）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/applications/{application_id}/assignments/{user_id}",
    tag = "admin",
    params(
        ("application_id" = String, Path, description = "アプリの内部 ID"),
        ("user_id" = String, Path, description = "利用者の内部 ID"),
    ),
    responses(
        (status = 204, description = "削除成功（未割り当てでも成功）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリが不存在"),
    )
)]
pub async fn unassign_user(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id, user_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let user = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .unassign(tenant.context(), id, user, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 「いま入れている人」を引く
/// （`GET /{tenant_id}/admin/applications/{application_id}/current-users`）。
///
/// 「全員」から「個別」へ倒す前に、そのまま名簿へ写すための一覧である。⚠ **これを出さずに
/// 切り替えさせると、空の名簿で保存した瞬間に全員が入れなくなる。**
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications/{application_id}/current-users",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    responses(
        (status = 200, description = "いま入れている利用者", body = ApplicationCurrentUsersResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn current_users(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Result<Json<ApplicationCurrentUsersResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let users = state
        .applications_admin
        .current_users(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_current_users(users)))
}

/// 繋ぐ相手（要求の解釈結果）。
///
/// 応答の翻訳器を await をまたいで持てないため、要求の検証と非同期の呼び出しの間にこの型を挟む。
enum BindingRequest {
    Oidc(String),
    Saml(Uuid),
}

fn parse_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-application-not-found")))
}

fn parse_user_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-user-not-found")))
}

fn parse_status(raw: &str, locale: ApiLocale) -> Result<ApplicationStatus, ApiError> {
    ApplicationStatus::parse(raw.trim()).map_err(|_| {
        ApiError::BadRequest(ApiMessages::new(locale).get("api-application-status-invalid"))
    })
}

fn parse_assignment_mode(raw: &str, locale: ApiLocale) -> Result<AssignmentMode, ApiError> {
    AssignmentMode::parse(raw.trim()).map_err(|_| {
        ApiError::BadRequest(
            ApiMessages::new(locale).get("api-application-assignment-mode-invalid"),
        )
    })
}

fn to_response(summary: &ApplicationSummary) -> ApplicationResponse {
    ApplicationResponse {
        id: summary.application.id.to_string(),
        display_name: summary.application.display_name.clone(),
        status: summary.application.status.as_str().to_string(),
        assignment_mode: summary.application.assignment_mode.as_str().to_string(),
        bindings: summary
            .bindings
            .iter()
            .map(|b| ApplicationBindingResponse {
                id: b.binding.id.to_string(),
                protocol: b.binding.target.protocol().to_string(),
                identifier: b.identifier.clone(),
                display_name: b.display_name.clone(),
            })
            .collect(),
        assigned_count: summary.assigned_count,
        created_at: summary.application.created_at.to_rfc3339(),
        updated_at: summary.application.updated_at.to_rfc3339(),
    }
}

fn to_detail(detail: &ApplicationDetail) -> ApplicationDetailResponse {
    let summary = ApplicationSummary {
        application: detail.application.clone(),
        bindings: detail
            .bindings
            .iter()
            .map(
                |b| crate::application::application_management::BindingSummary {
                    binding: b.binding.clone(),
                    identifier: b.identifier.clone(),
                    display_name: b.display_name.clone(),
                },
            )
            .collect(),
        assigned_count: detail.assigned.len() as i64,
    };
    ApplicationDetailResponse {
        application: to_response(&summary),
        assigned: detail
            .assigned
            .iter()
            .map(|a| ApplicationAssignmentResponse {
                user_id: a.user_id.to_string(),
                sub: a.sub.to_string(),
                email: a.email.clone(),
                name: a.name.clone(),
                status: a.status.as_str().to_string(),
                assigned_at: a.assigned_at.to_rfc3339(),
            })
            .collect(),
    }
}

fn to_current_users(users: CurrentUsers) -> ApplicationCurrentUsersResponse {
    ApplicationCurrentUsersResponse {
        users: users
            .members
            .iter()
            .map(|m| ApplicationCurrentUserResponse {
                user_id: m.user_id.to_string(),
                email: m.email.clone(),
                name: m.name.clone(),
            })
            .collect(),
        total: users.total,
        truncated: users.truncated,
    }
}

fn map_error(e: ApplicationManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        ApplicationManagementError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
        ApplicationManagementError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        ApplicationManagementError::NotFound => {
            ApiError::NotFound(msgs.get("api-application-not-found"))
        }
        ApplicationManagementError::Internal(m) => ApiError::Internal(m),
    }
}
