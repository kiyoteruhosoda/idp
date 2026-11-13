//! MFA (TOTP) API handlers (`/internal/mfa/*`).
//!
//! Handles TOTP self-enrollment (setup/confirm/delete) and TOTP verification in the login flow (verify).
//! All belong to the `/internal/*` router and are protected by the service auth token.

use crate::application::audit::RequestContext;
use crate::application::mfa_login::{MfaLoginCommand, MfaLoginOutcome};
use crate::application::totp_registration::TotpRegistrationError;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalTotpConfirmRequest, InternalTotpConfirmResponse, InternalTotpDeleteRequest,
    InternalTotpDeleteResponse, InternalTotpSetupRequest, InternalTotpSetupResponse,
    InternalVerifyTotpRequest, InternalVerifyTotpResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;

/// Starts TOTP setup (`POST /internal/mfa/totp/setup`).
///
/// Returns the QR URI and the raw secret (base32). `AlreadyConfigured` if an active TOTP already exists.
pub async fn setup_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpSetupRequest>,
) -> Json<InternalTotpSetupResponse> {
    match state.totp_registration.setup(&req.sso_session_id).await {
        Ok(data) => Json(InternalTotpSetupResponse::Ok {
            totp_uri: data.totp_uri,
            secret_base32: data.secret_base32,
        }),
        Err(TotpRegistrationError::AlreadyConfigured) => {
            Json(InternalTotpSetupResponse::AlreadyConfigured)
        }
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpSetupResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp setup internal error");
            Json(InternalTotpSetupResponse::Internal)
        }
    }
}

/// Confirms TOTP (`POST /internal/mfa/totp/confirm`). Verifies a 6-digit code and enables it.
pub async fn confirm_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpConfirmRequest>,
) -> Json<InternalTotpConfirmResponse> {
    match state
        .totp_registration
        .confirm(&req.sso_session_id, &req.code)
        .await
    {
        Ok(()) => Json(InternalTotpConfirmResponse::Ok),
        Err(TotpRegistrationError::InvalidCode) => Json(InternalTotpConfirmResponse::InvalidCode),
        Err(TotpRegistrationError::NotFound) => Json(InternalTotpConfirmResponse::NotFound),
        Err(TotpRegistrationError::AlreadyConfigured) => {
            Json(InternalTotpConfirmResponse::AlreadyConfigured)
        }
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpConfirmResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp confirm internal error");
            Json(InternalTotpConfirmResponse::Internal)
        }
    }
}

/// Deletes TOTP (`POST /internal/mfa/totp/delete`). Disables MFA.
pub async fn delete_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpDeleteRequest>,
) -> Json<InternalTotpDeleteResponse> {
    match state.totp_registration.delete(&req.sso_session_id).await {
        Ok(()) => Json(InternalTotpDeleteResponse::Ok),
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpDeleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp delete internal error");
            Json(InternalTotpDeleteResponse::Internal)
        }
    }
}

/// TOTP verification in the login flow (`POST /internal/mfa/totp/verify`).
///
/// Verifies the TOTP code on a password-authenticated AuthSession (`password_verified_at` set), and
/// on success issues an SSO session -> issues a code (or leads to the consent screen).
pub async fn verify_totp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalVerifyTotpRequest>,
) -> Result<Json<InternalVerifyTotpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .mfa_login
        .verify(
            tenant,
            MfaLoginCommand {
                auth_session_id: req.auth_session_id,
                totp_code: req.totp_code,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        MfaLoginOutcome::Success {
            location,
            form_post,
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalVerifyTotpResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        MfaLoginOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalVerifyTotpResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        MfaLoginOutcome::SessionExpired => InternalVerifyTotpResponse::SessionExpired,
        MfaLoginOutcome::CsrfMismatch => InternalVerifyTotpResponse::CsrfMismatch,
        MfaLoginOutcome::InvalidCode => InternalVerifyTotpResponse::InvalidCode,
        MfaLoginOutcome::RateLimited => InternalVerifyTotpResponse::RateLimited,
        MfaLoginOutcome::Locked => InternalVerifyTotpResponse::Locked,
        MfaLoginOutcome::PolicyDenied => InternalVerifyTotpResponse::PolicyDenied,
        MfaLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalVerifyTotpResponse::DeviceEnrollmentRequired { ticket }
        }
        MfaLoginOutcome::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalVerifyTotpResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        MfaLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "mfa verify internal error");
            InternalVerifyTotpResponse::Internal
        }
    }))
}
