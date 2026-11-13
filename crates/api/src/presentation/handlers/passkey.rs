//! Passkey (WebAuthn) API handlers (`/internal/passkey/*`).
//!
//! Provides self-registration (register/begin, register/complete, delete, list) and authentication for the 3 login paths
//! (login/begin, plus per-path login/complete, login/admin/complete, login/portal/complete).
//! **Begin is shared by the 3 paths**; whether `auth_session_id` is passed directly decides
//! the challenge's purpose (passed = OIDC authorization flow, not passed = direct login). Deciding that value
//! from the cookie is web's job; the api only looks at the value passed.
//! All belong to the `/internal/*` router and are protected by the service auth token.

use crate::application::admin_login::{AdminLoginOutcome, AdminPasskeyLoginCommand};
use crate::application::audit::RequestContext;
use crate::application::passkey_authentication::PasskeyAuthOutcome;
use crate::application::passkey_registration::PasskeyRegistrationError;
use crate::application::portal_login::{PortalLoginOutcome, PortalPasskeyLoginCommand};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalAdminPasskeyLoginCompleteRequest, InternalAdminPasskeyLoginCompleteResponse,
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse, InternalPasskeyListRequest,
    InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginBeginResponse, InternalPasskeyLoginCompleteRequest,
    InternalPasskeyLoginCompleteResponse, InternalPasskeyRegisterBeginRequest,
    InternalPasskeyRegisterBeginResponse, InternalPasskeyRegisterCompleteRequest,
    InternalPasskeyRegisterCompleteResponse, InternalPortalPasskeyLoginCompleteRequest,
    InternalPortalPasskeyLoginCompleteResponse, PasskeyCredentialInfo,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// Starts passkey registration (`POST /internal/passkey/register/begin`).
pub async fn register_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyRegisterBeginRequest>,
) -> Json<InternalPasskeyRegisterBeginResponse> {
    match state
        .passkey_registration
        .begin(&req.sso_session_id, &req.user_name)
        .await
    {
        Ok((challenge_id, options)) => Json(InternalPasskeyRegisterBeginResponse::Ok {
            challenge_id: challenge_id.to_string(),
            options,
        }),
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyRegisterBeginResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey register begin error");
            Json(InternalPasskeyRegisterBeginResponse::Internal)
        }
    }
}

/// Completes passkey registration (`POST /internal/passkey/register/complete`).
pub async fn register_complete(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyRegisterCompleteRequest>,
) -> Json<InternalPasskeyRegisterCompleteResponse> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Json(InternalPasskeyRegisterCompleteResponse::ChallengeNotFound),
    };
    match state
        .passkey_registration
        .complete(&req.sso_session_id, challenge_id, &req.name, req.credential)
        .await
    {
        Ok(cred_id) => Json(InternalPasskeyRegisterCompleteResponse::Ok {
            credential_id: cred_id.to_string(),
        }),
        Err(PasskeyRegistrationError::ChallengeNotFound) => {
            Json(InternalPasskeyRegisterCompleteResponse::ChallengeNotFound)
        }
        Err(PasskeyRegistrationError::InvalidCredential(msg)) => {
            tracing::warn!(error = %msg, "passkey register complete: invalid credential");
            Json(InternalPasskeyRegisterCompleteResponse::InvalidCredential)
        }
        Err(PasskeyRegistrationError::DuplicateCredential) => {
            Json(InternalPasskeyRegisterCompleteResponse::DuplicateCredential)
        }
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyRegisterCompleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey register complete error");
            Json(InternalPasskeyRegisterCompleteResponse::Internal)
        }
    }
}

/// Deletes a passkey (`POST /internal/passkey/delete`).
pub async fn passkey_delete(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyDeleteRequest>,
) -> Json<InternalPasskeyDeleteResponse> {
    let credential_id = match req.credential_id.parse::<Uuid>() {
        // An unparseable id means "no such passkey", not an internal error.
        Ok(id) => id,
        Err(_) => return Json(InternalPasskeyDeleteResponse::NotFound),
    };
    match state
        .passkey_registration
        .delete(&req.sso_session_id, credential_id)
        .await
    {
        Ok(()) => Json(InternalPasskeyDeleteResponse::Ok),
        Err(PasskeyRegistrationError::NotFound) => Json(InternalPasskeyDeleteResponse::NotFound),
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyDeleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey delete error");
            Json(InternalPasskeyDeleteResponse::Internal)
        }
    }
}

/// Lists registered passkeys (`POST /internal/passkey/list`).
pub async fn passkey_list(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyListRequest>,
) -> Json<InternalPasskeyListResponse> {
    match state.passkey_registration.list(&req.sso_session_id).await {
        Ok(infos) => {
            let credentials = infos
                .into_iter()
                .map(|c| PasskeyCredentialInfo {
                    id: c.id.to_string(),
                    name: c.name,
                    created_at: c.created_at.to_rfc3339(),
                    last_used_at: c.last_used_at.map(|d| d.to_rfc3339()),
                    suspended: c.suspended,
                })
                .collect();
            Json(InternalPasskeyListResponse::Ok { credentials })
        }
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyListResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey list error");
            Json(InternalPasskeyListResponse::Internal)
        }
    }
}

/// Starts passkey authentication (`POST /internal/passkey/login/begin`).
pub async fn login_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyLoginBeginRequest>,
) -> Json<InternalPasskeyLoginBeginResponse> {
    match state
        .passkey_authentication
        .begin(req.auth_session_id.as_deref())
        .await
    {
        Ok((challenge_id, options)) => Json(InternalPasskeyLoginBeginResponse::Ok {
            challenge_id: challenge_id.to_string(),
            options,
        }),
        Err(e) => {
            tracing::error!(error = %e, "passkey login begin error");
            Json(InternalPasskeyLoginBeginResponse::Internal)
        }
    }
}

/// Completes passkey authentication (`POST /internal/passkey/login/complete`).
pub async fn login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasskeyLoginCompleteRequest>,
) -> Result<Json<InternalPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .passkey_authentication
        .complete(tenant, challenge_id, req.credential, &ctx)
        .await;
    Ok(Json(match outcome {
        PasskeyAuthOutcome::Success {
            location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalPasskeyLoginCompleteResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        PasskeyAuthOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalPasskeyLoginCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        PasskeyAuthOutcome::ChallengeNotFound => {
            InternalPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        PasskeyAuthOutcome::SessionExpired => InternalPasskeyLoginCompleteResponse::SessionExpired,
        PasskeyAuthOutcome::InvalidCredential => {
            InternalPasskeyLoginCompleteResponse::InvalidCredential
        }
        PasskeyAuthOutcome::PolicyDenied => InternalPasskeyLoginCompleteResponse::PolicyDenied,
        PasskeyAuthOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket }
        }
        PasskeyAuthOutcome::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalPasskeyLoginCompleteResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        PasskeyAuthOutcome::RateLimited => InternalPasskeyLoginCompleteResponse::RateLimited,
        PasskeyAuthOutcome::Internal(e) => {
            tracing::error!(error = %e, "passkey login complete error");
            InternalPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// Completes the admin console passkey login (`POST /internal/passkey/login/admin/complete`).
///
/// Unlike the authorization flow's `login_complete`, neither `auth_session` nor an authorization code is involved.
/// Checks admin permission and issues an SSO session directly (`AdminLoginService` applies the same decision as
/// the password path).
pub async fn admin_login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminPasskeyLoginCompleteRequest>,
) -> Result<Json<InternalAdminPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .login_with_passkey(
            tenant,
            AdminPasskeyLoginCommand {
                challenge_id,
                credential: req.credential,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        AdminLoginOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAdminPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        AdminLoginOutcome::PasskeyChallengeNotFound => {
            InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminPasskeyLoginCompleteResponse::InvalidCredential
        }
        AdminLoginOutcome::Forbidden => InternalAdminPasskeyLoginCompleteResponse::Forbidden,
        AdminLoginOutcome::PolicyDenied => InternalAdminPasskeyLoginCompleteResponse::PolicyDenied,
        AdminLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalAdminPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket }
        }
        AdminLoginOutcome::RateLimited => InternalAdminPasskeyLoginCompleteResponse::RateLimited,
        // Outcomes that only occur on the password path (unreachable on the passkey path).
        other => {
            tracing::error!(
                outcome = admin_outcome_label(&other),
                "unexpected outcome from admin passkey login"
            );
            InternalAdminPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// Completes the portal passkey login (`POST /internal/passkey/login/portal/complete`).
///
/// Differs from the admin console version in not requiring admin permission, and in having the email verification gate (SEC6b)
/// and returning the display language. No TOTP step (a passkey satisfies `require_mfa`).
pub async fn portal_login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalPasskeyLoginCompleteRequest>,
) -> Result<Json<InternalPortalPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .login_with_passkey(
            tenant,
            PortalPasskeyLoginCommand {
                challenge_id,
                credential: req.credential,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        PortalLoginOutcome::Success {
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalPortalPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        PortalLoginOutcome::PasskeyChallengeNotFound => {
            InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        PortalLoginOutcome::InvalidCredentials => {
            InternalPortalPasskeyLoginCompleteResponse::InvalidCredential
        }
        PortalLoginOutcome::EmailVerificationRequired => {
            InternalPortalPasskeyLoginCompleteResponse::EmailVerificationRequired
        }
        PortalLoginOutcome::PolicyDenied => {
            InternalPortalPasskeyLoginCompleteResponse::PolicyDenied
        }
        PortalLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalPortalPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket }
        }
        PortalLoginOutcome::RateLimited => InternalPortalPasskeyLoginCompleteResponse::RateLimited,
        // Outcomes that only occur on the password path (unreachable on the passkey path).
        other => {
            tracing::error!(
                outcome = portal_outcome_label(&other),
                "unexpected outcome from portal passkey login"
            );
            InternalPortalPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// Name for logging an outcome that should be unreachable (internal log, so the ops language = English, no PII).
fn admin_outcome_label(outcome: &AdminLoginOutcome) -> &'static str {
    match outcome {
        AdminLoginOutcome::Success { .. } => "success",
        AdminLoginOutcome::PasswordChangeRequired { .. } => "password_change_required",
        AdminLoginOutcome::RateLimited => "rate_limited",
        AdminLoginOutcome::InvalidCredentials => "invalid_credentials",
        AdminLoginOutcome::Locked => "locked",
        AdminLoginOutcome::Forbidden => "forbidden",
        AdminLoginOutcome::WeakPassword(_) => "weak_password",
        AdminLoginOutcome::PolicyDenied => "policy_denied",
        AdminLoginOutcome::DeviceEnrollmentRequired { .. } => "device_enrollment_required",
        AdminLoginOutcome::PasskeyChallengeNotFound => "passkey_challenge_not_found",
        AdminLoginOutcome::MfaEnrollmentRequired => "mfa_enrollment_required",
        AdminLoginOutcome::MfaRequired => "mfa_required",
        AdminLoginOutcome::Internal(_) => "internal",
    }
}

/// Name for logging an outcome that should be unreachable (internal log, so the ops language = English, no PII).
fn portal_outcome_label(outcome: &PortalLoginOutcome) -> &'static str {
    match outcome {
        PortalLoginOutcome::Success { .. } => "success",
        PortalLoginOutcome::MfaRequired { .. } => "mfa_required",
        PortalLoginOutcome::EmailVerificationRequired => "email_verification_required",
        PortalLoginOutcome::PasswordChangeRequired { .. } => "password_change_required",
        PortalLoginOutcome::PolicyDenied => "policy_denied",
        PortalLoginOutcome::DeviceEnrollmentRequired { .. } => "device_enrollment_required",
        PortalLoginOutcome::MfaEnrollmentRequired => "mfa_enrollment_required",
        PortalLoginOutcome::PasskeyChallengeNotFound => "passkey_challenge_not_found",
        PortalLoginOutcome::RateLimited => "rate_limited",
        PortalLoginOutcome::InvalidCredentials => "invalid_credentials",
        PortalLoginOutcome::Locked => "locked",
        PortalLoginOutcome::Internal(_) => "internal",
    }
}
