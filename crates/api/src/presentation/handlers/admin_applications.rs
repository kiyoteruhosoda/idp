//! App management (`/{tenant_id}/admin/applications`, ADR-0054).
//!
//! An app is "one app as users see it"; OIDC `clients` and SAML
//! `saml_service_providers` are merely **how that app connects** (bindings). Authentication policies,
//! user assignments and suspension attach at this level.
//!
//! Protected by `idp.applications:read` / `idp.applications:write`. It is separate from client management (`idp.clients:*`)
//! because ⚠ **"who can fix how it connects" and "who decides who may use it" are not necessarily the same**.
//! The former is work for whoever builds the RP; the latter is an organizational decision.

use crate::application::application_management::{
    ApplicationDetail, ApplicationManagementError, ApplicationSummary, CurrentUsers,
    NewApplication, NewAssignment, NewBinding,
};
use crate::application::application_user_directory::{
    ApplicationUserDirectoryError, RosterQuery, MAX_SUBJECTS,
};
use crate::domain::account::AccountLocator;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::message::MessageKey;
use crate::domain::values::{ApplicationStatus, AssignmentMode};
use crate::presentation::admin::{
    ApplicationsRead, ApplicationsWrite, ManagementPrincipal, RequirePerms,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AccountApplicationListResponse, AccountApplicationResponse, ApplicationAssignmentResponse,
    ApplicationBindingCandidateListResponse, ApplicationBindingCandidateResponse,
    ApplicationBindingResponse, ApplicationCurrentUserResponse, ApplicationCurrentUsersResponse,
    ApplicationDetailResponse, ApplicationListResponse, ApplicationResponse,
    ApplicationServiceAccountAssignmentResponse, ApplicationUserListResponse,
    ApplicationUserQueryParams, ApplicationUserResponse, CreateApplicationAssignmentRequest,
    CreateApplicationBindingRequest, CreateApplicationRequest, UpdateApplicationRequest,
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

/// Lists apps (`GET /{tenant_id}/admin/applications`).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications",
    tag = "admin",
    responses(
        (status = 200, description = "アプリの一覧", body = ApplicationListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
    ),
    security(("bearer_token" = []))
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
        enforcement: assignment_enforcement(&state, &tenant).await?,
    }))
}

/// Apps one member can use (`GET /{tenant_id}/admin/members/{user_id}/applications`, ADR-0063).
///
/// The flip side of an app's detail (who can use it). Lists only apps with sign-in bindings (OIDC / SAML), and
/// answers allow/deny by the same rule as the decision.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members/{user_id}/applications",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "メンバーが使えるアプリ", body = AccountApplicationListResponse),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
        (status = 404, description = "このテナントのメンバーではない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_member_applications(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<AccountApplicationListResponse>, ApiError> {
    let user_id = parse_id(&user_id, locale)?;
    account_applications(
        &state,
        &tenant,
        locale,
        AccountLocator::User { user_id },
        "api-member-not-found",
    )
    .await
}

/// Apps one service account can use
/// (`GET /{tenant_id}/admin/service-accounts/{client_id}/applications`, ADR-0065).
///
/// Same shape as the people endpoint. Lists only apps with an audience (`resource`) binding, and answers allow/deny by the same rule
/// as token issuance (the app is active and an assignment exists). ⚠ Service accounts are not included even for "everyone" apps.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/service-accounts/{client_id}/applications",
    tag = "admin",
    params(("client_id" = String, Path, description = "サービスアカウントの client_id")),
    responses(
        (status = 200, description = "サービスアカウントが使えるアプリ", body = AccountApplicationListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
        (status = 404, description = "このテナントのサービスアカウントではない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_service_account_applications(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<AccountApplicationListResponse>, ApiError> {
    account_applications(
        &state,
        &tenant,
        locale,
        AccountLocator::ServiceAccount {
            client_id: &client_id,
        },
        "api-service-account-not-found",
    )
    .await
}

/// Returns the "usable apps" of people and service accounts in the same shape.
async fn account_applications(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: ApiLocale,
    account: AccountLocator<'_>,
    not_found_key: &str,
) -> Result<Json<AccountApplicationListResponse>, ApiError> {
    let rows = state
        .applications_admin
        .account_applications(tenant.context(), account)
        .await
        .map_err(|e| match e {
            // Don't say "no apps" when the subject itself is not found.
            ApplicationManagementError::NotFound => {
                ApiError::NotFound(ApiMessages::new(locale).get(not_found_key))
            }
            e => map_error(e, locale),
        })?;
    Ok(Json(AccountApplicationListResponse {
        applications: rows
            .into_iter()
            .map(|row| AccountApplicationResponse {
                application_id: row.application.id.to_string(),
                display_name: row.application.display_name,
                status: row.application.status.as_str().to_string(),
                assignment_mode: row.application.assignment_mode.as_str().to_string(),
                access: row.access.reason().to_string(),
                assigned_at: row.assigned_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
        enforcement: assignment_enforcement(state, tenant).await?,
    }))
}

/// Detail of one app (`GET /{tenant_id}/admin/applications/{application_id}`).
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
    ),
    security(("bearer_token" = []))
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
    let enforcement = assignment_enforcement(&state, &tenant).await?;
    Ok(Json(to_detail(&detail, enforcement)))
}

/// Registers an app (`POST /{tenant_id}/admin/applications`).
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
    ),
    security(("bearer_token" = []))
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
    // ⚠ "Individual" when omitted. With "everyone" as the default, an app someone forgot to restrict would stay open to all.
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
    // Return the detail right after creation (so the caller can confirm the assigned person is on the roster).
    let detail = state
        .applications_admin
        .detail(tenant.context(), application.id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(to_application_response(&detail))))
}

/// Updates an app (`PUT /{tenant_id}/admin/applications/{application_id}`).
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
    ),
    security(("bearer_token" = []))
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
    Ok(Json(to_application_response(&detail)))
}

/// Deletes an app (`DELETE /{tenant_id}/admin/applications/{application_id}`).
///
/// ⚠ **The registrations of RPs hanging off it are not deleted.** Only the grouping and the roster go away.
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
    ),
    security(("bearer_token" = []))
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

/// Adds a binding (`POST /{tenant_id}/admin/applications/{application_id}/bindings`, ADR-0059).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/applications/{application_id}/bindings",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    request_body = CreateApplicationBindingRequest,
    responses(
        (status = 200, description = "追加後のアプリ", body = ApplicationResponse),
        (status = 400, description = "種類が不正・相手の欄が無い・相手の性質が種類と合わない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリ・相手・移す元のアプリが不存在"),
        (status = 409, description = "その相手は既に別のアプリの名乗り（応答にそのアプリ名）。`move_from_application_id` が今の持ち主と違うときも"),
    ),
    security(("bearer_token" = []))
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
    // ⚠ `ApiMessages` (FluentBundle) is not `Send`. It can't be held across await, so
    // **fully decide what to add first** before entering the async call.
    let request = parse_binding_request(&body, locale)?;
    let move_from = match body
        .move_from_application_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(parse_id(raw, locale)?),
        None => None,
    };
    state
        .applications_admin
        .bind(tenant.context(), id, request, move_from, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_application_response(&detail)))
}

/// Binding candidates (`GET /{tenant_id}/admin/applications/{application_id}/binding-candidates`, ADR-0067).
///
/// Lists the tenant's registered sign-in clients, SAML SPs, service accounts and audiences that fit the kind's
/// nature, noting **which app each is currently bound to**. The endpoint lets the screen have targets picked
/// from a list instead of typing IDs. Permission is the same `idp.applications:read` as the app detail.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications/{application_id}/binding-candidates",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    responses(
        (status = 200, description = "名乗りの候補", body = ApplicationBindingCandidateListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:read 必須）"),
        (status = 404, description = "不存在（他テナントのアプリを含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn binding_candidates(
    RequirePerms(_admin, _): RequirePerms<ApplicationsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Result<Json<ApplicationBindingCandidateListResponse>, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let candidates = state
        .applications_admin
        .binding_candidates(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ApplicationBindingCandidateListResponse {
        candidates: candidates
            .into_iter()
            .map(|c| ApplicationBindingCandidateResponse {
                kind: c.target.kind().to_string(),
                reference: c.reference,
                identifier: c.identifier,
                display_name: c.display_name,
                application_id: c.owner.as_ref().map(|o| o.id.to_string()),
                application_name: c.owner.map(|o| o.display_name),
            })
            .collect(),
    }))
}

/// Reads the request into a kind and a target. ⚠ **Only the field matching the kind is read** -- values in other fields
/// are silently not used (a request with `kind=oidc` sending only `resource_uri` is not reinterpreted as something else).
fn parse_binding_request(
    body: &CreateApplicationBindingRequest,
    locale: ApiLocale,
) -> Result<NewBinding, ApiError> {
    fn present(value: &Option<String>) -> Option<String> {
        value
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
    let required = || {
        ApiError::BadRequest(
            ApiMessages::new(locale).get("api-application-binding-target-required"),
        )
    };
    match body.kind.trim() {
        "oidc" => Ok(NewBinding::Oidc {
            client_id: present(&body.client_id).ok_or_else(required)?,
        }),
        "service_account" => Ok(NewBinding::ServiceAccount {
            client_id: present(&body.client_id).ok_or_else(required)?,
        }),
        "saml" => {
            let raw = present(&body.service_provider_id).ok_or_else(required)?;
            let service_provider_id = Uuid::parse_str(&raw).map_err(|_| {
                ApiError::NotFound(ApiMessages::new(locale).get("api-application-not-found"))
            })?;
            Ok(NewBinding::Saml {
                service_provider_id,
            })
        }
        "resource" => Ok(NewBinding::Resource {
            resource_uri: present(&body.resource_uri).ok_or_else(required)?,
        }),
        _ => Err(ApiError::BadRequest(
            ApiMessages::new(locale).get("api-application-binding-kind-invalid"),
        )),
    }
}

/// Removes a binding
/// (`DELETE /{tenant_id}/admin/applications/{application_id}/bindings/{binding_id}`).
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
    ),
    security(("bearer_token" = []))
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

/// Assigns a principal
/// (`POST /{tenant_id}/admin/applications/{application_id}/assignments`; idempotent, ADR-0059).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/applications/{application_id}/assignments",
    tag = "admin",
    params(("application_id" = String, Path, description = "アプリの内部 ID")),
    request_body = CreateApplicationAssignmentRequest,
    responses(
        (status = 200, description = "割り当て後の詳細", body = ApplicationDetailResponse),
        (status = 400, description = "種類が不正・相手の欄が無い・サービスアカウントでない client"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリ・利用者・client が不存在（他テナントを含む）"),
    ),
    security(("bearer_token" = []))
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
    let request = parse_assignment_request(&body, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .assign(tenant.context(), id, request, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    let detail = state
        .applications_admin
        .detail(tenant.context(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    let enforcement = assignment_enforcement(&state, &tenant).await?;
    Ok(Json(to_detail(&detail, enforcement)))
}

/// Reads the request into a kind and a target. ⚠ Only the field matching the kind is read (not reinterpreted as another field's value).
fn parse_assignment_request(
    body: &CreateApplicationAssignmentRequest,
    locale: ApiLocale,
) -> Result<NewAssignment, ApiError> {
    let present = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let required = || {
        ApiError::BadRequest(
            ApiMessages::new(locale).get("api-application-assignment-target-required"),
        )
    };
    match body.kind.trim() {
        "user" => {
            let raw = present(&body.user_id).ok_or_else(required)?;
            Ok(NewAssignment::User {
                user_id: parse_user_id(&raw, locale)?,
            })
        }
        "service_account" => Ok(NewAssignment::ServiceAccount {
            client_id: present(&body.client_id).ok_or_else(required)?,
        }),
        _ => Err(ApiError::BadRequest(
            ApiMessages::new(locale).get("api-application-assignment-kind-invalid"),
        )),
    }
}

/// Removes a person's assignment
/// (`DELETE /{tenant_id}/admin/applications/{application_id}/assignments/users/{user_id}`).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/applications/{application_id}/assignments/users/{user_id}",
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
    ),
    security(("bearer_token" = []))
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
        .unassign_user(tenant.context(), id, user, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a service account's assignment
/// (`DELETE /{tenant_id}/admin/applications/{application_id}/assignments/service-accounts/{client_id}`).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/applications/{application_id}/assignments/service-accounts/{client_id}",
    tag = "admin",
    params(
        ("application_id" = String, Path, description = "アプリの内部 ID"),
        ("client_id" = String, Path, description = "サービスアカウントの client_id"),
    ),
    responses(
        (status = 204, description = "削除成功（未割り当てでも成功）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.applications:write 必須）"),
        (status = 404, description = "アプリ・client が不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn unassign_service_account(
    RequirePerms(admin, _): RequirePerms<ApplicationsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, application_id, client_id)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&application_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .applications_admin
        .unassign_service_account(tenant.context(), id, &client_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Looks up "the people who can get in now"
/// (`GET /{tenant_id}/admin/applications/{application_id}/current-users`).
///
/// A list for copying straight into the roster before switching from "everyone" to "individual". ⚠ **Letting them switch
/// without showing this means that the moment an empty roster is saved, nobody can get in.**
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
    ),
    security(("bearer_token" = []))
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
                kind: b.binding.target.kind().to_string(),
                identifier: b.identifier.clone(),
                display_name: b.display_name.clone(),
            })
            .collect(),
        assigned_count: summary.assigned_count,
        created_at: summary.application.created_at.to_rfc3339(),
        updated_at: summary.application.updated_at.to_rfc3339(),
    }
}

/// Whether the tenant rejects on app assignments (`record_only` / `enforce`).
///
/// Put in the response so the screen can show "currently only recording". ⚠ **It carries the tenant's value** (ADR-0058 §4).
/// It is read from the same place as the decision (`ApplicationAccessService`), so display and decision never diverge.
async fn assignment_enforcement(
    state: &AppState,
    tenant: &ResolvedTenant,
) -> Result<String, ApiError> {
    state
        .tenant_settings
        .assignment_enforcement(tenant.context().tenant_id())
        .await
        .map(|enforcement| enforcement.as_str().to_string())
        .map_err(|e| ApiError::Internal(e.to_string()))
}

fn to_application_response(detail: &ApplicationDetail) -> ApplicationResponse {
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
    to_response(&summary)
}

fn to_detail(detail: &ApplicationDetail, enforcement: String) -> ApplicationDetailResponse {
    ApplicationDetailResponse {
        application: to_application_response(detail),
        enforcement,
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
        assigned_service_accounts: detail
            .assigned_service_accounts
            .iter()
            .map(|a| ApplicationServiceAccountAssignmentResponse {
                client_id: a.client_id.clone(),
                app_name: a.app_name.clone(),
                status: a.client_status.as_str().to_string(),
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

/// Looks up the roster of one's own app
/// (`GET /{tenant_id}/admin/applications/self/users`, ADR-0057 / ADR-0059).
///
/// The endpoint read by the RP's periodic reconciliation (ADR-0049's I7). ⚠ **The RP doesn't get to name the target**
/// -- it returns the roster of the app the calling service account is bound to as a binding. No permission code is
/// required (being the binding is the reason it may read that app's roster).
///
/// ⚠ **403 for unbound principals**. Returning an empty roster would make the RP stop everyone.
///
/// ⚠ **`unknown` (gone) is returned only when `subs` is given.** People who are gone, being absent, don't
/// appear in the candidate list.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/applications/self/users",
    tag = "admin",
    params(ApplicationUserQueryParams),
    responses(
        (status = 200, description = "名簿", body = ApplicationUserListResponse),
        (status = 400, description = "sub の指定が不正、または多すぎる"),
        (status = 401, description = "未認証"),
        (status = 403, description = "呼び出し元がサービスアカウントでない、またはどのアプリの名乗りでもない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn own_application_users(
    ManagementPrincipal(caller): ManagementPrincipal,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<ApplicationUserQueryParams>,
) -> Result<Json<ApplicationUserListResponse>, ApiError> {
    let query = match params.subs.as_deref() {
        Some(raw) => RosterQuery::Subjects(parse_subs(raw, locale)?),
        None => RosterQuery::Page,
    };
    let result = state
        .application_users
        .for_caller(
            tenant.context(),
            &caller.actor,
            query,
            params.limit,
            params.offset,
        )
        .await
        .map_err(|e| map_directory_error(e, locale))?;
    Ok(Json(ApplicationUserListResponse {
        users: result
            .page
            .items
            .iter()
            .map(|user| ApplicationUserResponse {
                sub: user.sub.to_string(),
                state: user.state.as_str().to_string(),
            })
            .collect(),
        total: result.page.total,
        // Return the clamped value rather than the requested one (same as other lists; callers can use it for paging).
        limit: result.applied.limit(),
        offset: result.applied.offset(),
    }))
}

/// Reads comma-separated `sub`s.
///
/// ⚠ **Reject if even one can't be read.** Answering with only the readable ones would silently turn a `sub` with a one-character
/// typo into "gone", and the RP would drop that person's link.
fn parse_subs(raw: &str, locale: ApiLocale) -> Result<Vec<Uuid>, ApiError> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            Uuid::parse_str(value).map_err(|_| {
                ApiError::BadRequest(
                    ApiMessages::new(locale).get("api-application-users-sub-invalid"),
                )
            })
        })
        .collect()
}

fn map_directory_error(e: ApplicationUserDirectoryError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        // ⚠ 403, not an empty roster. Returning empty makes the RP stop everyone (ADR-0059).
        ApplicationUserDirectoryError::NotAServiceAccount => {
            ApiError::Forbidden(msgs.get("api-application-self-requires-service-account"))
        }
        ApplicationUserDirectoryError::NotBound => {
            ApiError::Forbidden(msgs.get("api-application-self-not-bound"))
        }
        ApplicationUserDirectoryError::TooManySubjects => {
            ApiError::BadRequest(msgs.get_message(&MessageKey::with_value(
                "api-application-users-too-many-subs",
                MAX_SUBJECTS.to_string(),
            )))
        }
        ApplicationUserDirectoryError::Internal(m) => ApiError::Internal(m),
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
