//! Consent API (`/internal/consent-info`, `/internal/consent/approve`, `/internal/consent/deny`).
//!
//! Internal endpoints that provide what the consent screen needs and handle granting/denying consent.
//! As with the login screen, `/internal/*` is not exposed externally (protected by `require_service_token`).

use crate::application::audit::RequestContext;
use crate::application::consent::ConsentOutcome;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalConsentApproveRequest, InternalConsentApproveResponse, InternalConsentDenyRequest,
    InternalConsentDenyResponse, InternalConsentInfoRequest, InternalConsentInfoResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Consent screen info (`GET /internal/consent-info`).
/// Checks the AuthSession of `auth_session_id` and returns the client name and requested scopes.
pub async fn consent_info(
    State(state): State<AppState>,
    Query(req): Query<InternalConsentInfoRequest>,
) -> Result<Json<InternalConsentInfoResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(
        match state.consent.info(tenant, &req.auth_session_id).await {
            Ok(Some(info)) => Json(InternalConsentInfoResponse::Ok {
                auth_session_id: info.auth_session_id,
                client_name: info.client_name,
                client_id: info.client_id,
                requested_scopes: info.requested_scopes,
                redirect_uri: Some(info.redirect_uri),
            }),
            Ok(None) => Json(InternalConsentInfoResponse::SessionExpired),
            Err(e) => {
                tracing::error!(error = %e, "consent_info: failed to get consent info");
                Json(InternalConsentInfoResponse::SessionExpired)
            }
        },
    )
}

/// Consent approval (`POST /internal/consent/approve`). Records consent and issues a code.
pub async fn consent_approve(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalConsentApproveRequest>,
) -> Result<impl IntoResponse, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .consent
        .approve(tenant, &req.auth_session_id, &ctx)
        .await;
    Ok(Json(match outcome {
        ConsentOutcome::Approved {
            location,
            form_post,
        } => InternalConsentApproveResponse::Success {
            form_post,
            redirect_to: location,
        },
        ConsentOutcome::ApplicationNotPermitted { application_name } => {
            InternalConsentApproveResponse::ApplicationNotPermitted { application_name }
        }
        ConsentOutcome::SessionExpired => InternalConsentApproveResponse::SessionExpired,
        ConsentOutcome::Internal(e) => {
            tracing::error!(error = %e, "consent_approve: internal error");
            InternalConsentApproveResponse::Internal
        }
        ConsentOutcome::Denied { .. } => {
            // Denied cannot happen at the approve endpoint, but just in case.
            InternalConsentApproveResponse::Internal
        }
    }))
}

/// Consent denial (`POST /internal/consent/deny`). Redirects an `access_denied` error to the RP.
pub async fn consent_deny(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalConsentDenyRequest>,
) -> Result<impl IntoResponse, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state.consent.deny(tenant, &req.auth_session_id, &ctx).await;
    Ok((
        StatusCode::OK,
        Json(match outcome {
            ConsentOutcome::Denied {
                location,
                form_post,
            } => InternalConsentDenyResponse::Ok {
                redirect_to: location,
                form_post,
            },
            // The deny endpoint never reaches the decision (no code is issued).
            ConsentOutcome::ApplicationNotPermitted { .. } => InternalConsentDenyResponse::Internal,
            ConsentOutcome::SessionExpired => InternalConsentDenyResponse::SessionExpired,
            ConsentOutcome::Internal(e) => {
                tracing::error!(error = %e, "consent_deny: internal error");
                InternalConsentDenyResponse::Internal
            }
            ConsentOutcome::Approved { .. } => {
                // Approved cannot happen at the deny endpoint, but just in case.
                InternalConsentDenyResponse::Internal
            }
        }),
    ))
}
