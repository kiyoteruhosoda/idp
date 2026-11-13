//! Internal API for RP-initiated Logout (`POST /internal/logout/rp`, OIDC RP-initiated Logout 1.0,
//! ADR-0018 decision 2).
//!
//! `end_session_endpoint` is received by web (`GET /{tenant_id}/logout`). The api does not read browser cookies;
//! with the `sso_session_id` forwarded by web (its own domain's host-only cookie value) and the query parameters
//! it handles:
//!
//! 1. Validating `id_token_hint` (signature, issuer), identifying and ending the SSO session (LogoutService), and auditing.
//! 2. Validating `post_logout_redirect_uri` and building the redirect URL with `state` attached.
//! 3. Listing the front-channel logout URIs (with the `iss` query attached).
//!
//! Discarding the SSO cookie and rendering the front-channel iframe page are done by web.
//!
//! ⚠ **No back-channel logout notifications are queued** (ADR-0055). The SSO session is shared across
//! the same user's RPs, and closing other RPs' sessions on sign-out from one RP is a side effect the user
//! did not ask for. RPs are notified only when an admin stops the user
//! (`stop_announcement`, ADR-0053).

use crate::application::audit::RequestContext;
use crate::application::logout::LogoutOutcome;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;

/// Internal endpoint for RP-initiated logout.
pub async fn rp_logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalRpLogoutRequest>,
) -> Result<Json<InternalRpLogoutResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let result = match state
        .logout
        .logout(
            tenant,
            req.sso_session_id.as_deref(),
            req.client_id.as_deref(),
            req.id_token_hint.as_deref(),
            req.post_logout_redirect_uri.as_deref(),
            &ctx,
        )
        .await
    {
        LogoutOutcome::Completed(result) => result,
        // `id_token_hint` pointed at a different user (G12). The session is kept, so
        // just tell web not to redirect and not to delete the cookie.
        LogoutOutcome::SubjectMismatch => {
            return Ok(Json(InternalRpLogoutResponse::SubjectMismatch))
        }
    };

    // Transparently attach the state parameter to the validated post_logout_redirect_uri.
    let redirect_to = result.post_logout_redirect_uri.map(|uri| {
        match req.state.as_deref().filter(|s| !s.is_empty()) {
            Some(state_val) => {
                let sep = if uri.contains('?') { '&' } else { '?' };
                let encoded = percent_encoding::utf8_percent_encode(
                    state_val,
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                format!("{uri}{sep}state={encoded}")
            }
            None => uri,
        }
    });

    Ok(Json(InternalRpLogoutResponse::Ok {
        frontchannel_uris: result.frontchannel_uris,
        redirect_to,
    }))
}
