//! Invitation acceptance endpoint (`/{tenant_id}/invitations/accept`, ADR-0009 §3, §6).
//!
//! Used not via the admin API (`/admin/*`) but by **the signed-in user themselves** (no permission needed). The invitee,
//! with a session signed in to their home tenant, presents the invitation token to the joining tenant's (`{tenant_id}`)
//! accept endpoint. Identity is confirmed by possession of the token + a signed-in session (the `AuthenticatedUser`
//! extractor resolves the user from the SSO session and the use case matches it with the token, §3).

use crate::application::invitation::InvitationError;
use crate::presentation::admin::AuthenticatedUser;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::AcceptInvitationRequest;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// Accepts an invitation and makes the membership `ACTIVE`. The acceptor must be the invitee (signed in)
/// themselves. 400 if the token is not this tenant's invitation, expired or nonexistent; 403 if not the invitee.
#[utoipa::path(
    post,
    path = "/{tenant_id}/invitations/accept",
    tag = "auth",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 204, description = "承諾成功"),
        (status = 400, description = "トークンが無効・期限切れ・別テナントの招待"),
        (status = 401, description = "未認証（ログインが必要）"),
        (status = 403, description = "被招待者本人でない"),
    )
)]
pub async fn accept_invitation(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<AcceptInvitationRequest>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .invitations
        .accept_invitation(tenant.context(), user_id, &body.token, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-invitation-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict(msgs.get("api-member-already")),
        InvitationError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        InvitationError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        InvitationError::InvalidOrExpired => {
            ApiError::BadRequest(msgs.get("api-invitation-invalid-or-expired"))
        }
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
