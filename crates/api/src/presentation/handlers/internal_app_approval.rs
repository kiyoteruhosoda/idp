//! Endpoints called by web for "continue with the app" and authenticator app keys (`/internal/app-approval/*`,
//! `/internal/account/app-approver/*`, task #892, ADR-0077). Behind the service token.
//!
//! Decisions are in the application layer (`AppApprovalService`). This only repacks DTOs.

use crate::application::app_approval::{
    ApproverKeysOutcome, CompleteApprovalOutcome, ConfirmEnrollmentOutcome, EnrollmentViewOutcome,
    RevokeApproverKeyOutcome, StartApproval, StartApprovalOutcome,
};
use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountApproverKeySummary, InternalAccountApproverConfirmResponse,
    InternalAccountApproverEnrollmentRequest, InternalAccountApproverEnrollmentResponse,
    InternalAccountApproverKeysRequest, InternalAccountApproverKeysResponse,
    InternalAccountRevokeApproverKeyRequest, InternalAccountRevokeApproverKeyResponse,
    InternalAppApprovalCompleteRequest, InternalAppApprovalCompleteResponse,
    InternalAppApprovalStartRequest, InternalAppApprovalStartResponse,
};
use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::SecondsFormat;
use uuid::Uuid;

/// Starts a "continue with the app" request (`POST /internal/app-approval/start`).
pub async fn start(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAppApprovalStartRequest>,
) -> Response {
    let tenant =
        match require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await {
            Ok(t) => t,
            Err(response) => return response,
        };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .app_approval
        .start_request(
            tenant,
            StartApproval {
                auth_session_id: req.auth_session_id.as_deref(),
                country: req.country.as_deref(),
            },
            &ctx,
        )
        .await;
    Json(match outcome {
        StartApprovalOutcome::Started {
            request_id,
            browser_binding,
        } => InternalAppApprovalStartResponse::Started {
            request_id,
            browser_binding,
        },
        StartApprovalOutcome::Disabled => InternalAppApprovalStartResponse::Disabled,
        StartApprovalOutcome::RateLimited => InternalAppApprovalStartResponse::RateLimited,
        StartApprovalOutcome::Internal(e) => {
            tracing::error!(error = %e, "app approval could not be started");
            InternalAppApprovalStartResponse::Internal
        }
    })
    .into_response()
}

/// Completes in the browser opened by the app (`POST /internal/app-approval/complete`).
pub async fn complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAppApprovalCompleteRequest>,
) -> Response {
    let tenant =
        match require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await {
            Ok(t) => t,
            Err(response) => return response,
        };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .app_approval
        .complete_request(
            tenant,
            &req.request_id,
            &req.code,
            req.browser_binding.as_deref(),
            &ctx,
        )
        .await;
    Json(match outcome {
        CompleteApprovalOutcome::Success {
            location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAppApprovalCompleteResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        CompleteApprovalOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAppApprovalCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        CompleteApprovalOutcome::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAppApprovalCompleteResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        CompleteApprovalOutcome::Invalid => InternalAppApprovalCompleteResponse::Invalid,
        CompleteApprovalOutcome::AnotherBrowser => {
            InternalAppApprovalCompleteResponse::AnotherBrowser
        }
        CompleteApprovalOutcome::PolicyDenied => InternalAppApprovalCompleteResponse::PolicyDenied,
        CompleteApprovalOutcome::UserUnavailable => {
            InternalAppApprovalCompleteResponse::UserUnavailable
        }
        CompleteApprovalOutcome::Internal(e) => {
            tracing::error!(error = %e, "app approval could not be completed");
            InternalAppApprovalCompleteResponse::Internal
        }
    })
    .into_response()
}

/// Contents of the enrollment confirmation screen (`POST /internal/account/app-approver/enrollment`).
pub async fn account_enrollment(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountApproverEnrollmentRequest>,
) -> Response {
    let tenant =
        match require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await {
            Ok(t) => t,
            Err(response) => return response,
        };
    Json(
        match state
            .app_approval
            .enrollment_for_confirmation(tenant, &req.sso_session_id, &req.enrollment_id)
            .await
        {
            EnrollmentViewOutcome::Ready(view) => {
                InternalAccountApproverEnrollmentResponse::Ready {
                    device_name: view.device_name,
                    security_level: view.security_level.as_str().to_string(),
                    created_at: view.created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                }
            }
            EnrollmentViewOutcome::NotFound => InternalAccountApproverEnrollmentResponse::NotFound,
            EnrollmentViewOutcome::SessionExpired => {
                InternalAccountApproverEnrollmentResponse::SessionExpired
            }
            EnrollmentViewOutcome::Internal(e) => {
                tracing::error!(error = %e, "approver enrollment could not be read");
                InternalAccountApproverEnrollmentResponse::Internal
            }
        },
    )
    .into_response()
}

/// Confirms enrollment (`POST /internal/account/app-approver/confirm`).
pub async fn account_confirm(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountApproverEnrollmentRequest>,
) -> Response {
    let tenant =
        match require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await {
            Ok(t) => t,
            Err(response) => return response,
        };
    Json(
        match state
            .app_approval
            .confirm_enrollment(tenant, &req.sso_session_id, &req.enrollment_id)
            .await
        {
            ConfirmEnrollmentOutcome::Confirmed { code } => {
                InternalAccountApproverConfirmResponse::Confirmed { code }
            }
            ConfirmEnrollmentOutcome::PasskeyRequired => {
                InternalAccountApproverConfirmResponse::PasskeyRequired
            }
            ConfirmEnrollmentOutcome::NotFound => InternalAccountApproverConfirmResponse::NotFound,
            ConfirmEnrollmentOutcome::SessionExpired => {
                InternalAccountApproverConfirmResponse::SessionExpired
            }
            ConfirmEnrollmentOutcome::Internal(e) => {
                tracing::error!(error = %e, "approver enrollment could not be confirmed");
                InternalAccountApproverConfirmResponse::Internal
            }
        },
    )
    .into_response()
}

/// List of "authenticator apps" (`POST /internal/account/app-approver/keys`).
pub async fn account_keys(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountApproverKeysRequest>,
) -> Response {
    if let Err(response) =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await
    {
        return response;
    }
    let enabled = state.app_approval.is_enabled();
    Json(
        match state
            .app_approval
            .keys_for_account(&req.sso_session_id)
            .await
        {
            ApproverKeysOutcome::Listed(keys) => InternalAccountApproverKeysResponse::Listed {
                enabled,
                keys: keys
                    .into_iter()
                    .map(|k| AccountApproverKeySummary {
                        id: k.id.to_string(),
                        device_name: k.device_name,
                        security_level: k.security_level.as_str().to_string(),
                        registered_at: k.registered_at.to_rfc3339_opts(SecondsFormat::Secs, true),
                        last_used_at: k
                            .last_used_at
                            .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
                    })
                    .collect(),
            },
            ApproverKeysOutcome::SessionExpired => {
                InternalAccountApproverKeysResponse::SessionExpired
            }
            ApproverKeysOutcome::Internal(e) => {
                tracing::error!(error = %e, "approver keys could not be listed");
                InternalAccountApproverKeysResponse::Internal
            }
        },
    )
    .into_response()
}

/// Revokes a key (`POST /internal/account/app-approver/keys/revoke`).
pub async fn account_revoke_key(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeApproverKeyRequest>,
) -> Response {
    let tenant =
        match require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await {
            Ok(t) => t,
            Err(response) => return response,
        };
    let Ok(key) = Uuid::parse_str(&req.key_id) else {
        return Json(InternalAccountRevokeApproverKeyResponse::NotFound).into_response();
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    Json(
        match state
            .app_approval
            .revoke_from_account(tenant, &req.sso_session_id, key, &ctx)
            .await
        {
            RevokeApproverKeyOutcome::Revoked { sessions } => {
                InternalAccountRevokeApproverKeyResponse::Revoked { sessions }
            }
            RevokeApproverKeyOutcome::NotFound => {
                InternalAccountRevokeApproverKeyResponse::NotFound
            }
            RevokeApproverKeyOutcome::SessionExpired => {
                InternalAccountRevokeApproverKeyResponse::SessionExpired
            }
            RevokeApproverKeyOutcome::Internal(e) => {
                tracing::error!(error = %e, "approver key could not be revoked");
                InternalAccountRevokeApproverKeyResponse::Internal
            }
        },
    )
    .into_response()
}
