//! Guest invitation creation endpoint (`/{tenant_id}/admin/invitations`, ADR-0009 §3, §6).
//!
//! Requires `idp.members:write` (`RequirePerms<MembersWrite>`; implied by `idp.tenant.admin`). When an admin of the
//! joining tenant invites an existing user (home tenant elsewhere), a one-time **invitation token** is returned. The invitee
//! is identified by **email address or internal ID (UUID)** (ADR-0061; disambiguated in the application layer). Only the token hash is stored,
//! and it never appears in logs / audit logs (same pattern as `generated_password`, §3). The admin passes the token
//! to the invitee separately, who presents it to `/invitations/accept` with a session signed in to their home tenant.

use crate::application::invitation::InvitationError;
use crate::presentation::admin::{MembersWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{CreateInvitationRequest, InvitationCreatedResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// Creates a guest invitation and returns the invitation token **only in this response**.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/invitations",
    tag = "admin",
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "招待作成（招待トークンを含む）", body = InvitationCreatedResponse),
        (status = 400, description = "invitee がメールアドレスでも UUID でもない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:write 必須）"),
        (status = 404, description = "被招待利用者が不存在"),
        (status = 409, description = "既に当該テナントのメンバー"),
    ),
    security(("bearer_token" = []))
)]
pub async fn create_invitation(
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationCreatedResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let created = state
        .invitations
        .create_invitation(tenant.context(), &body.invitee, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((
        StatusCode::CREATED,
        Json(InvitationCreatedResponse {
            token: created.token,
            expires_at: created.expires_at.to_rfc3339(),
            email_sent: created.email_sent,
            invitee_email: created.invitee_email,
        }),
    ))
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-invitation-user-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict(msgs.get("api-member-already")),
        InvitationError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        InvitationError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        InvitationError::InvalidOrExpired => ApiError::BadRequest(msgs.get("api-invalid-request")),
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
