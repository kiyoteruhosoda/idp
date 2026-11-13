//! Tenant member management endpoints (`/{tenant_id}/admin/members`, ADR-0009 §3, §6).
//!
//! Listing/getting needs `idp.members:read`; removing, suspending/resuming and updating notes need `idp.members:write`
//! (`RequirePerms<MembersRead>` / `<MembersWrite>`; `idp.tenant.admin` implies both). Admins of the joining tenant can only
//! view the member list and **remove, suspend/resume guest memberships** (MT24); HOME can be neither removed nor
//! suspended. Guests' `users` records (password, status, MFA, profile) cannot be operated on
//! (only by home tenant admins and the user themselves, §3).

use crate::application::account_note::AccountNoteError;
use crate::application::invitation::InvitationError;
use crate::application::member_directory::MemberSearchParams;
use crate::domain::account::AccountLocator;
use crate::domain::account_note::AccountNote;
use crate::domain::tenant_membership::TenantMember;
use crate::domain::values::MembershipStatus;
use crate::presentation::admin::{MembersRead, MembersWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AccountNoteResponse, MemberListQueryParams, MemberListResponse, MemberResponse,
    UpdateAccountNoteRequest, UpdateMemberStatusRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_admin_account_guard_error, request_context};
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Looks up one member by name (`GET /{tenant_id}/admin/members/{user_id}`).
///
/// Exists for the member detail screen. ⚠ **Don't make callers fetch the list and search it** -- the list is
/// paginated, so callers can't know which page the desired person is on.
///
/// 404 if not a member of the requesting tenant (doesn't let anyone infer the existence of other tenants' members).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "メンバー 1 人", body = MemberResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:read 必須）"),
        (status = 404, description = "このテナントのメンバーではない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_member(
    RequirePerms(_admin, _): RequirePerms<MembersRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // ⚠ **The route has two parameters, `{tenant_id}` and `{user_id}`.** Receiving just one `Path<Uuid>`
    //   **would take the leading tenant ID**, always yielding "not a member"
    //   (`revoke_member` / `update_member_status` on the same route also take two).
    Path((_tenant_id, user_id)): Path<(String, Uuid)>,
) -> Result<Json<MemberResponse>, ApiError> {
    let found = state
        .member_directory
        .find(tenant.context(), user_id)
        .await
        .map_err(|e| map_error(InvitationError::Internal(e.to_string()), locale))?;
    let now = state.clock.now();
    match found {
        Some(m) => Ok(Json(member_response(m, now))),
        None => Err(ApiError::NotFound(
            ApiMessages::new(locale).get("api-user-not-found"),
        )),
    }
}

/// Lists the tenant's members (HOME / GUEST) (paging and filtering added in MT22).
///
/// Filtering, sorting and paging all happen in the DB. Returning everything and filtering on the caller side
/// is not used, as responses would grow with tenant size.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members",
    tag = "admin",
    params(MemberListQueryParams),
    responses(
        (status = 200, description = "メンバー一覧（1 ページ分と総件数）", body = MemberListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_members(
    RequirePerms(_admin, _): RequirePerms<MembersRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<MemberListQueryParams>,
) -> Result<Json<MemberListResponse>, ApiError> {
    let search = MemberSearchParams {
        search: params.q,
        limit: params.limit,
        offset: params.offset,
    };
    let result = state
        .member_directory
        .search(tenant.context(), search)
        .await
        .map_err(|e| map_error(InvitationError::Internal(e.to_string()), locale))?;
    let now = state.clock.now();
    Ok(Json(MemberListResponse {
        members: result
            .page
            .members
            .into_iter()
            .map(|m| member_response(m, now))
            .collect(),
        total: result.page.total,
        limit: result.limit,
        offset: result.offset,
    }))
}

/// Removes a guest membership (expels the guest). HOME cannot be removed (403). On removal, that user's
/// permission rows scoped to this tenant are deleted too (§3).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "解除する利用者の内部 ID（UUID）")),
    responses(
        (status = 204, description = "解除成功"),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:write 必須）・HOME は解除不可"),
        (status = 404, description = "メンバーシップが不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn revoke_member(
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    state
        .admin_account_guard
        .ensure_may_manage_membership(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .invitations
        .revoke_membership(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Suspends / resumes a guest membership (`PATCH /{tenant_id}/admin/members/{user_id}`, MT24).
///
/// `status` of `SUSPENDED` suspends, `ACTIVE` resumes. Only GUEST `ACTIVE` can be suspended,
/// only `SUSPENDED` can be resumed (otherwise 403). Unlike removal (`DELETE`),
/// the membership row and the permission rows scoped to this tenant remain, so resuming restores the pre-suspension state.
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateMemberStatusRequest,
    responses(
        (status = 204, description = "更新成功"),
        (status = 400, description = "user_id が UUID でない・status が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:write 必須）・HOME は停止不可・遷移できない状態"),
        (status = 404, description = "メンバーシップが不存在"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_member_status(
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateMemberStatusRequest>,
) -> Result<StatusCode, ApiError> {
    // `ApiMessages` (a fluent bundle) is not `Send`, so it is not held across `.await`
    // (holding it would make the handler's future non-`Send`, failing axum's `Handler`).
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    state
        .admin_account_guard
        .ensure_may_manage_membership(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    // Only the two transitions suspend and resume are accepted. `INVITED` is a state managed by the invitation flow,
    // so it can't be set directly from here.
    let status = MembershipStatus::parse(body.status.trim())
        .ok()
        .filter(|s| matches!(s, MembershipStatus::Active | MembershipStatus::Suspended))
        .ok_or_else(|| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let result = match status {
        MembershipStatus::Suspended => {
            state
                .invitations
                .suspend_membership(tenant.context(), target, &admin.actor, &ctx)
                .await
        }
        _ => {
            state
                .invitations
                .resume_membership(tenant.context(), target, &admin.actor, &ctx)
                .await
        }
    };
    result.map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Writes / clears an admin note (`PUT /{tenant_id}/admin/members/{user_id}/note`, ADR-0063).
///
/// Writable for both HOME and GUEST (the note is this tenant's admins' memo and doesn't change the guest user
/// themselves). Sending empty (whitespace only) clears the note.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/members/{user_id}/note",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateAccountNoteRequest,
    responses(
        (status = 204, description = "保存した（空なら消した）"),
        (status = 400, description = "user_id が UUID でない・メモが長すぎる"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:write 必須）"),
        (status = 404, description = "このテナントのメンバーではない"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_member_note(
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateAccountNoteRequest>,
) -> Result<StatusCode, ApiError> {
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .account_notes
        .write(
            tenant.context(),
            AccountLocator::User { user_id: target },
            &body.note,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| {
            let msgs = ApiMessages::new(locale);
            match e {
                AccountNoteError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
                AccountNoteError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
                AccountNoteError::Internal(m) => ApiError::Internal(m),
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// Response for one member (shared by the list, lookup by name and the people rows of the account list).
pub(crate) fn member_response(m: TenantMember, now: DateTime<Utc>) -> MemberResponse {
    MemberResponse {
        user_id: m.user_id.to_string(),
        email: m.email,
        preferred_username: m.preferred_username,
        name: m.name,
        membership_type: m.membership_type.as_str().to_string(),
        status: m.status.as_str().to_string(),
        user_status: m.user_status.map(|s| s.as_str().to_string()),
        // An expired lock is returned as "not locked" (decided at read time).
        locked: m.locked_until.is_some_and(|until| until > now),
        pending_setup: m.pending_setup,
        // The expiry only matters for provisionally registered people (a link for someone who finished setup is of no use).
        setup_link_expires_at: m
            .setup_link_expires_at
            .filter(|_| m.pending_setup)
            .map(|t| t.to_rfc3339()),
        setup_link_expired: m.pending_setup
            && !m.setup_link_expires_at.is_some_and(|until| until > now),
        note: note_response(m.note),
    }
}

/// Admin note response (same shape for people and service accounts, ADR-0065).
pub(crate) fn note_response(note: Option<AccountNote>) -> Option<AccountNoteResponse> {
    note.map(|n| AccountNoteResponse {
        text: n.text,
        updated_at: n.updated_at.to_rfc3339(),
    })
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict(msgs.get("api-member-already")),
        InvitationError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        InvitationError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        InvitationError::InvalidOrExpired => ApiError::BadRequest(msgs.get("api-invalid-request")),
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
