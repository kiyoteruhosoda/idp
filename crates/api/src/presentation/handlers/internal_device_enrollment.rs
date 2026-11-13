//! Endpoints letting someone who correctly signs in on an unregistered device register it on the spot (`/internal/device-enrollment/*`,
//! task #916, ADR-0079).
//!
//! Internal endpoints called only by web (behind the service token). Decisions are in the application layer (`DeviceEnrollmentService`);
//! this only repacks DTOs. Whether the ticket belongs to the current browser is checked by the application layer
//! using the device mark attached by web (`client_device`).

use crate::application::audit::RequestContext;
use crate::application::device_enrollment::{
    BeginEnrollmentOutcome, CompleteEnrollment, CompleteEnrollmentOutcome,
    DescribeEnrollmentOutcome,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalDeviceEnrollmentBeginRequest, InternalDeviceEnrollmentBeginResponse,
    InternalDeviceEnrollmentCompleteRequest, InternalDeviceEnrollmentCompleteResponse,
    InternalDeviceEnrollmentDescribeRequest, InternalDeviceEnrollmentDescribeResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// Ticket contents (`POST /internal/device-enrollment/describe`).
pub async fn describe(
    State(state): State<AppState>,
    Json(req): Json<InternalDeviceEnrollmentDescribeRequest>,
) -> Result<Json<InternalDeviceEnrollmentDescribeResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .device_enrollment
            .describe(tenant.tenant_id(), &req.ticket)
            .await
        {
            DescribeEnrollmentOutcome::Ok(view) => InternalDeviceEnrollmentDescribeResponse::Ok {
                username: view.username,
            },
            DescribeEnrollmentOutcome::TicketInvalid => {
                InternalDeviceEnrollmentDescribeResponse::TicketInvalid
            }
            DescribeEnrollmentOutcome::Internal(e) => {
                tracing::error!(error = %e, "device enrollment describe failed with internal error");
                InternalDeviceEnrollmentDescribeResponse::Internal
            }
        },
    ))
}

/// Starts passkey verification (`POST /internal/device-enrollment/passkey/begin`).
pub async fn begin(
    State(state): State<AppState>,
    Json(req): Json<InternalDeviceEnrollmentBeginRequest>,
) -> Result<Json<InternalDeviceEnrollmentBeginResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .device_enrollment
            .begin(tenant.tenant_id(), &req.ticket)
            .await
        {
            BeginEnrollmentOutcome::Ok {
                challenge_id,
                options,
            } => InternalDeviceEnrollmentBeginResponse::Ok {
                challenge_id: challenge_id.to_string(),
                options,
            },
            BeginEnrollmentOutcome::TicketInvalid => {
                InternalDeviceEnrollmentBeginResponse::TicketInvalid
            }
            BeginEnrollmentOutcome::Internal(e) => {
                tracing::error!(error = %e, "device enrollment begin failed with internal error");
                InternalDeviceEnrollmentBeginResponse::Internal
            }
        },
    ))
}

/// Verifies with a passkey, registers and signs in (`POST /internal/device-enrollment/passkey/complete`).
pub async fn complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalDeviceEnrollmentCompleteRequest>,
) -> Result<Json<InternalDeviceEnrollmentCompleteResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(challenge_id) = Uuid::parse_str(&req.challenge_id) else {
        return Ok(Json(
            InternalDeviceEnrollmentCompleteResponse::PasskeyRejected,
        ));
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .device_enrollment
        .complete(
            tenant.tenant_id(),
            CompleteEnrollment {
                ticket: &req.ticket,
                challenge_id,
                credential: req.credential,
                device_name: &req.device_name,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        CompleteEnrollmentOutcome::Enrolled(sso) => {
            InternalDeviceEnrollmentCompleteResponse::Enrolled {
                sso_session_id: sso.session_id().to_string(),
                sso_absolute_ttl_secs: sso.absolute_ttl_secs(),
            }
        }
        CompleteEnrollmentOutcome::TicketInvalid => {
            InternalDeviceEnrollmentCompleteResponse::TicketInvalid
        }
        CompleteEnrollmentOutcome::PasskeyRejected => {
            InternalDeviceEnrollmentCompleteResponse::PasskeyRejected
        }
        CompleteEnrollmentOutcome::InvalidName => {
            InternalDeviceEnrollmentCompleteResponse::InvalidName
        }
        CompleteEnrollmentOutcome::AccountUnavailable => {
            InternalDeviceEnrollmentCompleteResponse::AccountUnavailable
        }
        CompleteEnrollmentOutcome::Internal(e) => {
            tracing::error!(error = %e, "device enrollment complete failed with internal error");
            InternalDeviceEnrollmentCompleteResponse::Internal
        }
    }))
}
