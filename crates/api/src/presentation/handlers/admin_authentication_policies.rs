//! 認証ポリシーの管理エンドポイント（`/{tenant_id}/admin/authentication-policies`、
//! ユーザー認証・認証ポリシー仕様書 §7）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。作成・更新・削除は `audit_log`
//! に記録する（`authentication_policy.created` / `.updated` / `.deleted`）。検証・判定は Application 層
//! （`AuthenticationPolicyManagementService`）が行い、本ハンドラは HTTP への写像のみを担う。

use crate::application::authentication_policy_management::{
    AuthenticationPolicyDraft, AuthenticationPolicyManagementError,
};
use crate::domain::authentication_policy::{AuthenticationPolicy, RequiredMethods, TimeWindow};
use crate::domain::values::AuthenticationMethod;
use crate::presentation::admin::{
    AuthenticationPoliciesRead, AuthenticationPoliciesWrite, RequirePerms,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AuthenticationPoliciesResponse, AuthenticationPolicyResponse,
    AuthenticationPolicyUpsertRequest, RequiredMethodsDto, TimeWindowDto,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use uuid::Uuid;

/// テナントの認証ポリシーを一覧する（無効を含む。priority 昇順）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/authentication-policies",
    tag = "admin",
    responses(
        (status = 200, description = "認証ポリシー一覧（priority 昇順）", body = AuthenticationPoliciesResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_authentication_policies(
    RequirePerms(_admin, _): RequirePerms<AuthenticationPoliciesRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<AuthenticationPoliciesResponse>, ApiError> {
    let policies = state
        .authentication_policies_admin
        .list(tenant.context())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(AuthenticationPoliciesResponse {
        policies: policies.iter().map(to_response).collect(),
    }))
}

/// 認証ポリシーを作成する。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/authentication-policies",
    tag = "admin",
    request_body = AuthenticationPolicyUpsertRequest,
    responses(
        (status = 200, description = "作成したポリシー", body = AuthenticationPolicyResponse),
        (status = 400, description = "バリデーションエラー（コード形式・effect・条件）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 409, description = "policy_code がテナント内で重複"),
    )
)]
pub async fn create_authentication_policy(
    RequirePerms(admin, _): RequirePerms<AuthenticationPoliciesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<AuthenticationPolicyUpsertRequest>,
) -> Result<Json<AuthenticationPolicyResponse>, ApiError> {
    let draft = parse_draft(body, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let policy = state
        .authentication_policies_admin
        .create(tenant.context(), draft, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_response(&policy)))
}

/// 認証ポリシーを全項目置換で更新する。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/authentication-policies/{policy_id}",
    tag = "admin",
    params(("policy_id" = String, Path, description = "対象ポリシーの内部 ID（UUID）")),
    request_body = AuthenticationPolicyUpsertRequest,
    responses(
        (status = 200, description = "更新後のポリシー", body = AuthenticationPolicyResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "対象ポリシーが不存在"),
        (status = 409, description = "policy_code がテナント内で重複"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_authentication_policy(
    RequirePerms(admin, _): RequirePerms<AuthenticationPoliciesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
    Json(body): Json<AuthenticationPolicyUpsertRequest>,
) -> Result<Json<AuthenticationPolicyResponse>, ApiError> {
    let id = parse_uuid(&policy_id, locale)?;
    let draft = parse_draft(body, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let policy = state
        .authentication_policies_admin
        .update(tenant.context(), id, draft, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_response(&policy)))
}

/// 認証ポリシーを削除する。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/authentication-policies/{policy_id}",
    tag = "admin",
    params(("policy_id" = String, Path, description = "対象ポリシーの内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "対象ポリシーが不存在"),
    )
)]
pub async fn delete_authentication_policy(
    RequirePerms(admin, _): RequirePerms<AuthenticationPoliciesWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    let id = parse_uuid(&policy_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .authentication_policies_admin
        .delete(tenant.context(), id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

fn to_response(policy: &AuthenticationPolicy) -> AuthenticationPolicyResponse {
    AuthenticationPolicyResponse {
        id: policy.id.to_string(),
        policy_code: policy.policy_code.clone(),
        policy_name: policy.policy_name.clone(),
        priority: policy.priority,
        enabled: policy.enabled,
        effect: policy.effect.as_str().to_string(),
        effect_params: policy.effect_params.as_ref().map(|p| RequiredMethodsDto {
            methods: p.methods.iter().map(|m| m.as_str().to_string()).collect(),
            user_verification: p.user_verification,
        }),
        client_ids: policy.conditions.client_ids.clone(),
        user_ids: policy
            .conditions
            .user_ids
            .iter()
            .map(|u| u.to_string())
            .collect(),
        ip_cidrs: policy.conditions.ip_cidrs.clone(),
        time_windows: policy
            .conditions
            .time_windows
            .iter()
            .map(|w| TimeWindowDto {
                days: w.days.clone(),
                start_minute: w.start_minute,
                end_minute: w.end_minute,
                utc_offset_minutes: w.utc_offset_minutes,
            })
            .collect(),
        requested_acr: policy.conditions.requested_acr.clone(),
        created_at: policy.created_at.to_rfc3339(),
        updated_at: policy.updated_at.to_rfc3339(),
    }
}

/// リクエスト DTO を Application 層の入力へ変換する（`user_ids` の UUID 形式のみここで検証する。
/// 意味的な検証は Application 層）。
fn parse_draft(
    body: AuthenticationPolicyUpsertRequest,
    locale: ApiLocale,
) -> Result<AuthenticationPolicyDraft, ApiError> {
    let user_ids = body
        .user_ids
        .iter()
        .map(|raw| parse_uuid(raw, locale))
        .collect::<Result<Vec<_>, _>>()?;
    // 認証方式は DTO では文字列。ここで許可値へ写す（許可値の単一の出所はドメインの enum）。
    let effect_params = body
        .effect_params
        .map(|p| {
            let methods = p
                .methods
                .iter()
                .map(|raw| {
                    AuthenticationMethod::parse(raw).map_err(|_| {
                        ApiError::BadRequest(
                            ApiMessages::new(locale).get("api-auth-policy-effect-params-invalid"),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, ApiError>(RequiredMethods {
                methods,
                user_verification: p.user_verification,
            })
        })
        .transpose()?;
    Ok(AuthenticationPolicyDraft {
        policy_code: body.policy_code,
        policy_name: body.policy_name,
        priority: body.priority,
        enabled: body.enabled,
        effect: body.effect,
        effect_params,
        client_ids: body.client_ids,
        user_ids,
        ip_cidrs: body.ip_cidrs,
        time_windows: body
            .time_windows
            .into_iter()
            .map(|w| TimeWindow {
                days: w.days,
                start_minute: w.start_minute,
                end_minute: w.end_minute,
                utc_offset_minutes: w.utc_offset_minutes,
            })
            .collect(),
        requested_acr: body.requested_acr,
    })
}

fn parse_uuid(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))
}

fn map_error(e: AuthenticationPolicyManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        AuthenticationPolicyManagementError::Validation(m) => {
            ApiError::BadRequest(msgs.get_message(&m))
        }
        AuthenticationPolicyManagementError::NotFound => {
            ApiError::NotFound(msgs.get("api-auth-policy-not-found"))
        }
        AuthenticationPolicyManagementError::Conflict(m) => {
            ApiError::Conflict(msgs.get_message(&m))
        }
        AuthenticationPolicyManagementError::Internal(m) => ApiError::Internal(m),
    }
}
