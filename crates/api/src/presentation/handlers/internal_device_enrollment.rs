//! 登録していない端末で正しく入ろうとした人が、その場で端末を登録する口（`/internal/device-enrollment/*`。
//! task #916。ADR-0079）。
//!
//! web だけが呼ぶ内部の口（サービストークンの内側）。判定は Application 層（`DeviceEnrollmentService`）
//! にあり、ここは DTO の詰め替えだけを行う。札が今のブラウザのものかは、web が添えた端末の印
//! （`client_device`）で Application 層が確かめる。

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

/// 札の中身（`POST /internal/device-enrollment/describe`）。
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

/// パスキーの確かめを始める（`POST /internal/device-enrollment/passkey/begin`）。
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

/// パスキーで確かめて登録し、ログインする（`POST /internal/device-enrollment/passkey/complete`）。
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
