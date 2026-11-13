//! api restart endpoint (`POST /{tenant_id}/admin/restart`, ADR-0017).
//!
//! Requires `idp.system.admin` (same permission as runtime settings; effectively only root tenant system admins).
//!
//! **Responds first, then exits.** Triggering graceful shutdown first would cut this very request's connection,
//! looking like "I pressed it and nothing happened". By returning acceptance and stopping after a short wait,
//! web can render the restarting screen before moving on to its own stop.
//!
//! It only stops; starting a new process is the deployment's restart policy (see the `service_restart`
//! module docs). Without such a policy **the service stays stopped**, so
//! the screen must always state that assumption.

use crate::presentation::admin::{IdpSystemAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::RestartServiceResponse;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// Restarts the api (graceful shutdown -> the deployment's restart policy starts a new process).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/restart",
    tag = "admin",
    responses(
        (status = 202, description = "再起動を受理した（応答後に停止する）", body = RestartServiceResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn restart_service(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<RestartServiceResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    tracing::warn!("restart requested from the admin console");
    state
        .service_restart
        .request(tenant.context(), &admin.actor, "api", &ctx)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RestartServiceResponse {
            service: "api".to_string(),
            restarting: true,
        }),
    ))
}
