//! Admin token exchange API (`POST /internal/admin/token`, ADR-0037).
//!
//! The admin console (web) holds the browser's SSO session cookie, but the api's admin APIs
//! **only accept Bearer tokens**. This bridges the two. web exchanges at this endpoint on every
//! request before calling `/{tenant_id}/admin/*`.
//!
//! The exchange result is not cached so that **session revocation, permission removal and guest suspension take effect
//! immediately**. Caching would keep a stale decision alive for the token's lifetime. Admin console traffic is low, and
//! closing the "disabled but can still operate" window is worth more than one extra round trip.
//!
//! Protected by the service auth token shared by `/internal/*` (`X-Internal-Auth-Token`). Since it receives
//! SSO session values, it is never exposed on the public surface.

use crate::application::management_token::ManagementTokenError;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::admin::{ManagementTokenRequest, ManagementTokenResponse};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Exchanges an SSO session for an admin token.
///
/// Returns 200 even for users holding no permissions (token with empty `permission_codes`). Returning 403 here
/// would leave web unable to tell "not signed in (go to login)" from "insufficient permission (say so)".
pub async fn issue_management_token(
    State(state): State<AppState>,
    Json(body): Json<ManagementTokenRequest>,
) -> Result<Json<ManagementTokenResponse>, Response> {
    let tenant = require_internal_tenant(&state.tenant_resolution, Some(&body.tenant_id)).await?;
    match state
        .management_tokens
        .issue_for_session(tenant, Some(body.sso_session_id.as_str()))
        .await
    {
        Ok(issued) => Ok(Json(ManagementTokenResponse {
            access_token: issued.access_token,
            token_type: "Bearer".to_string(),
            expires_in: issued.expires_in,
            permission_codes: issued.permission_codes,
            name: issued.name,
            preferred_username: issued.preferred_username,
        })),
        Err(ManagementTokenError::Unauthenticated) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response()),
        Err(ManagementTokenError::Internal(e)) => {
            tracing::error!(error = %e, "failed to issue a management token");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
                .into_response())
        }
    }
}
