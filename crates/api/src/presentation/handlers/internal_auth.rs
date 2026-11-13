//! Internal authentication API (`/internal/*`, ADR-0007 §3, §5).
//!
//! **Internal endpoints outside the OIDC standard** for separating the login screens (the future `web` crate) from
//! the authorization server (api). web only renders forms and redirects, forwarding credentials, the `auth_session_id` reference and
//! client connection info (IP from `X-Forwarded-For`, User-Agent) to this API. Credential verification, lockout
//! (design spec §4.3), IP rate limiting, SSO/code issuance and audit recording are all done by the api (the sole DB owner);
//! building cookies and localizing error messages are web's job.
//!
//! In P2 (ADR-0007) api and web are the same process, so the existing HTML login screen handlers
//! keep calling [`crate::application::login::LoginService`] directly. This module exposes the same use cases
//! **in a form callable through internal endpoints**, used from an HTTP client once web becomes a crate
//! in P3.
//!
//! Protection (§5): `/internal/*` is never exposed externally (blocked at the reverse proxy). As defense in depth,
//! web->api calls require the service auth token (a shared secret, `X-Internal-Auth-Token` header).
//! The token is injected via settings (through `config`).

use crate::application::account_language::{UpdateLanguageCommand, UpdateLanguageOutcome};
use crate::application::account_password::{AccountPasswordCommand, AccountPasswordOutcome};
use crate::application::account_profile::{ProfileOutcome, UpdateNameCommand, UpdateNameOutcome};
use crate::application::account_security::{
    ReissueTokensOutcome, RevokeConsentOutcome, RevokeSessionOutcome, SecurityOverviewOutcome,
};
use crate::application::account_tenants::ListTenantsOutcome;
use crate::application::account_theme::{UpdateThemeCommand, UpdateThemeOutcome};
use crate::application::admin_login::{
    AdminChangePasswordCommand, AdminLoginCommand, AdminLoginOutcome,
};
use crate::application::audit::RequestContext;
use crate::application::authenticator_management::AuthenticatorManagementError;
use crate::application::change_password::{ChangePasswordCommand, ChangePasswordOutcome};
use crate::application::external_login::{
    CallbackCommand, CallbackOutcome, SamlAcsCommand, StartOutcome, SuccessLocation,
};
use crate::application::login::{LoginCommand, LoginOutcome};
use crate::application::password_reset::{RequestResetOutcome, ResetPasswordOutcome};
use crate::application::portal_login::{
    PortalChangePasswordCommand, PortalChangePasswordOutcome, PortalLoginCommand,
    PortalLoginOutcome, PortalMfaCommand, PortalMfaOutcome,
};
use crate::application::step_up::{
    StepUpCheckOutcome, StepUpPasskeyVerifyCommand, StepUpVerifyCommand, StepUpVerifyOutcome,
};
use crate::domain::password_policy::PasswordRejection;
use crate::domain::step_up::SensitiveOperation;
use crate::domain::user_authenticator::AuthenticatorStatus;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountConnectedAppSummary, AccountSessionSummary, AccountTenantSummary,
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountProfileRequest, InternalAccountProfileResponse,
    InternalAccountReissueTokensRequest, InternalAccountReissueTokensResponse,
    InternalAccountRevokeConsentRequest, InternalAccountRevokeConsentResponse,
    InternalAccountRevokeSessionRequest, InternalAccountRevokeSessionResponse,
    InternalAccountSecurityRequest, InternalAccountSecurityResponse, InternalAccountTenantsRequest,
    InternalAccountTenantsResponse, InternalAccountUpdateLanguageRequest,
    InternalAccountUpdateLanguageResponse, InternalAccountUpdateNameRequest,
    InternalAccountUpdateNameResponse, InternalAccountUpdateThemeRequest,
    InternalAccountUpdateThemeResponse, InternalAdminAuthenticateRequest,
    InternalAdminAuthenticateResponse, InternalAdminChangePasswordRequest,
    InternalAdminChangePasswordResponse, InternalAuthenticateRequest, InternalAuthenticateResponse,
    InternalChangePasswordRequest, InternalChangePasswordResponse, InternalLogoutRequest,
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
    InternalPasswordResetRequestRequest, InternalPasswordResetRequestResponse,
    InternalPortalAuthenticateRequest, InternalPortalAuthenticateResponse,
    InternalPortalChangePasswordRequest, InternalPortalChangePasswordResponse,
    InternalPortalMfaRequest, InternalPortalMfaResponse, InternalStepUpCheckRequest,
    InternalStepUpCheckResponse, InternalStepUpPasskeyBeginRequest,
    InternalStepUpPasskeyBeginResponse, InternalStepUpPasskeyVerifyRequest,
    InternalStepUpPasskeyVerifyResponse, InternalStepUpVerifyRequest, InternalStepUpVerifyResponse,
    PasswordRejectionReason,
};
use assay_contracts::auth::{
    AuthenticatorSummaryResponse, InternalAuthenticatorStatusRequest,
    InternalAuthenticatorStatusResponse, InternalAuthenticatorsRequest,
    InternalAuthenticatorsResponse, InternalEmailOtpRequest, InternalEmailOtpResponse,
    InternalPhoneConfirmationRequest, InternalPhoneConfirmationResponse,
    InternalPhoneRegistrationRequest, InternalPhoneRegistrationResponse,
    InternalRecoveryCodesRequest, InternalRecoveryCodesResponse, InternalSmsOtpRequest,
    InternalSmsOtpResponse,
};
use assay_contracts::auth::{
    ExternalIdpButton, InternalExternalCallbackRequest, InternalExternalCallbackResponse,
    InternalExternalProvidersRequest, InternalExternalProvidersResponse,
    InternalExternalStartRequest, InternalExternalStartResponse,
};
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use assay_contracts::internal_auth::{service_token_matches, SERVICE_TOKEN_HEADER};

/// Middleware protecting `/internal/*` (ADR-0007 §5). Compares the configured service token with the header value
/// in constant time, blocking with 401 on mismatch.
pub async fn require_service_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(SERVICE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !service_token_matches(presented, state.config.internal_service_token()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

/// Authentication (OIDC login). Runs [`LoginService`](crate::application::login::LoginService) with the credentials,
/// `auth_session_id` and client connection info forwarded by web, returning the result as JSON.
pub async fn authenticate(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthenticateRequest>,
) -> Result<Json<InternalAuthenticateResponse>, Response> {
    // Client connection info is forwarded by web (the api is not directly behind the proxy, so it doesn't read X-Forwarded-For itself).
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .login
        .login(
            tenant,
            LoginCommand {
                auth_session_id: req.auth_session_id,
                username: req.username,
                password: req.password,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        LoginOutcome::Success {
            location,
            form_post,
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalAuthenticateResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        LoginOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAuthenticateResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        LoginOutcome::MfaRequired { auth_session_id } => {
            InternalAuthenticateResponse::MfaRequired { auth_session_id }
        }
        LoginOutcome::PasswordChangeRequired { auth_session_id } => {
            InternalAuthenticateResponse::PasswordChangeRequired { auth_session_id }
        }
        LoginOutcome::EmailVerificationRequired => {
            InternalAuthenticateResponse::EmailVerificationRequired
        }
        LoginOutcome::PolicyDenied => InternalAuthenticateResponse::PolicyDenied,
        LoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalAuthenticateResponse::DeviceEnrollmentRequired { ticket }
        }
        LoginOutcome::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAuthenticateResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        LoginOutcome::MfaEnrollmentRequired => InternalAuthenticateResponse::MfaEnrollmentRequired,
        LoginOutcome::SessionExpired => InternalAuthenticateResponse::SessionExpired,
        LoginOutcome::CsrfMismatch => InternalAuthenticateResponse::CsrfMismatch,
        LoginOutcome::RateLimited => InternalAuthenticateResponse::RateLimited,
        LoginOutcome::InvalidCredentials => InternalAuthenticateResponse::InvalidCredentials,
        LoginOutcome::Locked => InternalAuthenticateResponse::Locked,
        LoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal authenticate failed with internal error");
            InternalAuthenticateResponse::Internal
        }
    }))
}

/// Password change (`POST /internal/change-password`, ADR-0009 §5). Following `must_change_password` detected by
/// `LoginService`, sets a new password with a password-verified `auth_session_id`.
/// Self-service password change (`POST /internal/account/change-password`, MT15). A signed-in
/// user, identified by the SSO session, re-verifies the current password and sets a new one.
pub async fn account_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountChangePasswordRequest>,
) -> Json<InternalAccountChangePasswordResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .account_password
        .change(
            AccountPasswordCommand {
                sso_session_id: req.sso_session_id,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    Json(match outcome {
        AccountPasswordOutcome::Ok => InternalAccountChangePasswordResponse::Ok,
        AccountPasswordOutcome::SessionExpired => {
            InternalAccountChangePasswordResponse::SessionExpired
        }
        AccountPasswordOutcome::InvalidCurrentPassword => {
            InternalAccountChangePasswordResponse::InvalidCurrentPassword
        }
        AccountPasswordOutcome::WeakPassword(rejection) => {
            InternalAccountChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        AccountPasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "account change-password failed with internal error");
            InternalAccountChangePasswordResponse::Internal
        }
    })
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalChangePasswordRequest>,
) -> Result<Json<InternalChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .change_password
        .change(
            tenant,
            ChangePasswordCommand {
                auth_session_id: req.auth_session_id,
                current_password: req.current_password,
                new_password: req.new_password,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        ChangePasswordOutcome::Success {
            location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalChangePasswordResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        ChangePasswordOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalChangePasswordResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        ChangePasswordOutcome::MfaRequired { auth_session_id } => {
            InternalChangePasswordResponse::MfaRequired { auth_session_id }
        }
        ChangePasswordOutcome::PolicyDenied => InternalChangePasswordResponse::PolicyDenied,
        ChangePasswordOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalChangePasswordResponse::DeviceEnrollmentRequired { ticket }
        }
        ChangePasswordOutcome::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalChangePasswordResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        ChangePasswordOutcome::MfaEnrollmentRequired => {
            InternalChangePasswordResponse::MfaEnrollmentRequired
        }
        ChangePasswordOutcome::SessionExpired => InternalChangePasswordResponse::SessionExpired,
        ChangePasswordOutcome::CsrfMismatch => InternalChangePasswordResponse::CsrfMismatch,
        ChangePasswordOutcome::InvalidCurrentPassword => {
            InternalChangePasswordResponse::InvalidCurrentPassword
        }
        ChangePasswordOutcome::WeakPassword(rejection) => {
            InternalChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        ChangePasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal change-password failed with internal error");
            InternalChangePasswordResponse::Internal
        }
    }))
}

/// Maps the domain's rejection reason to the contracts reason code (AP7).
///
/// web shows different wording per reason. A **reason code** is passed rather than the translation itself because
/// looking up translations is the displaying side's (web's) job, and the api does not decide the language.
fn rejection_reason(rejection: &PasswordRejection) -> PasswordRejectionReason {
    match rejection {
        PasswordRejection::Strength(_) => PasswordRejectionReason::Policy,
        PasswordRejection::Breached => PasswordRejectionReason::Breached,
        PasswordRejection::Reused => PasswordRejectionReason::Reused,
    }
}

/// Admin console authentication. CSRF already verified by web (ADR-0007 §4). Returns the SSO session id on success.
pub async fn authenticate_admin(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminAuthenticateRequest>,
) -> Result<Json<InternalAdminAuthenticateResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .login(
            tenant,
            AdminLoginCommand {
                username: req.username,
                password: req.password,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        AdminLoginOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAdminAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        AdminLoginOutcome::RateLimited => InternalAdminAuthenticateResponse::RateLimited,
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminAuthenticateResponse::InvalidCredentials
        }
        AdminLoginOutcome::Locked => InternalAdminAuthenticateResponse::Locked,
        AdminLoginOutcome::Forbidden => InternalAdminAuthenticateResponse::Forbidden,
        AdminLoginOutcome::PasswordChangeRequired { username } => {
            InternalAdminAuthenticateResponse::PasswordChangeRequired { username }
        }
        AdminLoginOutcome::PolicyDenied => InternalAdminAuthenticateResponse::PolicyDenied,
        AdminLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalAdminAuthenticateResponse::DeviceEnrollmentRequired { ticket }
        }
        AdminLoginOutcome::MfaEnrollmentRequired => {
            InternalAdminAuthenticateResponse::MfaEnrollmentRequired
        }
        AdminLoginOutcome::MfaRequired => InternalAdminAuthenticateResponse::MfaRequired,
        AdminLoginOutcome::WeakPassword(_) => {
            tracing::error!("unexpected WeakPassword outcome from admin authenticate");
            InternalAdminAuthenticateResponse::Internal
        }
        // Outcomes that only occur on the passkey path (unreachable on the password path).
        AdminLoginOutcome::PasskeyChallengeNotFound => {
            tracing::error!(
                "unexpected PasskeyChallengeNotFound outcome from admin password login"
            );
            InternalAdminAuthenticateResponse::Internal
        }
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal admin authenticate failed with internal error");
            InternalAdminAuthenticateResponse::Internal
        }
    }))
}

/// End-user portal authentication (`POST /internal/authenticate/portal`). CSRF already verified by web.
/// Returns the SSO session id on success (no code/redirect). Returns `mfa_ticket` if TOTP is configured.
pub async fn authenticate_portal(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalAuthenticateRequest>,
) -> Result<Json<InternalPortalAuthenticateResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .login(
            tenant,
            PortalLoginCommand {
                username: req.username,
                password: req.password,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        PortalLoginOutcome::Success {
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalPortalAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        PortalLoginOutcome::MfaRequired { mfa_ticket } => {
            InternalPortalAuthenticateResponse::MfaRequired { mfa_ticket }
        }
        PortalLoginOutcome::EmailVerificationRequired => {
            InternalPortalAuthenticateResponse::EmailVerificationRequired
        }
        PortalLoginOutcome::PasswordChangeRequired { username } => {
            InternalPortalAuthenticateResponse::PasswordChangeRequired { username }
        }
        PortalLoginOutcome::PolicyDenied => InternalPortalAuthenticateResponse::PolicyDenied,
        PortalLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalPortalAuthenticateResponse::DeviceEnrollmentRequired { ticket }
        }
        PortalLoginOutcome::MfaEnrollmentRequired => {
            InternalPortalAuthenticateResponse::MfaEnrollmentRequired
        }
        PortalLoginOutcome::RateLimited => InternalPortalAuthenticateResponse::RateLimited,
        PortalLoginOutcome::InvalidCredentials => {
            InternalPortalAuthenticateResponse::InvalidCredentials
        }
        PortalLoginOutcome::Locked => InternalPortalAuthenticateResponse::Locked,
        // Outcomes that only occur on the passkey path (unreachable on the password path).
        PortalLoginOutcome::PasskeyChallengeNotFound => {
            tracing::error!(
                "unexpected PasskeyChallengeNotFound outcome from portal password login"
            );
            InternalPortalAuthenticateResponse::Internal
        }
        PortalLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal authenticate failed with internal error");
            InternalPortalAuthenticateResponse::Internal
        }
    }))
}

/// Portal TOTP verification (`POST /internal/authenticate/portal/mfa`). Verifies `mfa_ticket` + TOTP code
/// and returns the SSO session id on success.
pub async fn authenticate_portal_mfa(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalMfaRequest>,
) -> Result<Json<InternalPortalMfaResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .verify_mfa(
            tenant,
            PortalMfaCommand {
                mfa_ticket: req.mfa_ticket,
                totp_code: req.totp_code,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        PortalMfaOutcome::Success {
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalPortalMfaResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        PortalMfaOutcome::InvalidCode => InternalPortalMfaResponse::InvalidCode,
        PortalMfaOutcome::TicketExpired => InternalPortalMfaResponse::TicketExpired,
        PortalMfaOutcome::PolicyDenied => InternalPortalMfaResponse::PolicyDenied,
        PortalMfaOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalPortalMfaResponse::DeviceEnrollmentRequired { ticket }
        }
        PortalMfaOutcome::RateLimited => InternalPortalMfaResponse::RateLimited,
        PortalMfaOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal mfa failed with internal error");
            InternalPortalMfaResponse::Internal
        }
    }))
}

/// Forced password change in the portal (`POST /internal/authenticate/portal/change-password`, ADR-0009 §5).
/// Portal login holds no temporary state, so everything including the current password is fully re-verified (no admin permission needed).
pub async fn authenticate_portal_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalChangePasswordRequest>,
) -> Result<Json<InternalPortalChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .change_password(
            tenant,
            PortalChangePasswordCommand {
                username: req.username,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        PortalChangePasswordOutcome::Success {
            sso_session_id,
            user_language,
            sso_absolute_ttl_secs,
        } => InternalPortalChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        },
        PortalChangePasswordOutcome::MfaRequired { mfa_ticket } => {
            InternalPortalChangePasswordResponse::MfaRequired { mfa_ticket }
        }
        PortalChangePasswordOutcome::PolicyDenied => {
            InternalPortalChangePasswordResponse::PolicyDenied
        }
        PortalChangePasswordOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalPortalChangePasswordResponse::DeviceEnrollmentRequired { ticket }
        }
        PortalChangePasswordOutcome::MfaEnrollmentRequired => {
            InternalPortalChangePasswordResponse::MfaEnrollmentRequired
        }
        PortalChangePasswordOutcome::EmailVerificationRequired => {
            InternalPortalChangePasswordResponse::EmailVerificationRequired
        }
        PortalChangePasswordOutcome::RateLimited => {
            InternalPortalChangePasswordResponse::RateLimited
        }
        PortalChangePasswordOutcome::InvalidCredentials => {
            InternalPortalChangePasswordResponse::InvalidCredentials
        }
        PortalChangePasswordOutcome::Locked => InternalPortalChangePasswordResponse::Locked,
        PortalChangePasswordOutcome::WeakPassword(rejection) => {
            InternalPortalChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        PortalChangePasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal change-password failed with internal error");
            InternalPortalChangePasswordResponse::Internal
        }
    }))
}

/// Forced password change in the admin console (`POST /internal/authenticate/admin/change-password`,
/// ADR-0009 §5). Admin login holds no temporary state, so everything including the current password is fully re-verified.
pub async fn admin_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminChangePasswordRequest>,
) -> Result<Json<InternalAdminChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .change_password(
            tenant,
            AdminChangePasswordCommand {
                username: req.username,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        AdminLoginOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => InternalAdminChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        },
        AdminLoginOutcome::RateLimited => InternalAdminChangePasswordResponse::RateLimited,
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminChangePasswordResponse::InvalidCredentials
        }
        AdminLoginOutcome::Locked => InternalAdminChangePasswordResponse::Locked,
        AdminLoginOutcome::Forbidden => InternalAdminChangePasswordResponse::Forbidden,
        AdminLoginOutcome::WeakPassword(rejection) => {
            InternalAdminChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        AdminLoginOutcome::PolicyDenied => InternalAdminChangePasswordResponse::PolicyDenied,
        AdminLoginOutcome::DeviceEnrollmentRequired { ticket } => {
            InternalAdminChangePasswordResponse::DeviceEnrollmentRequired { ticket }
        }
        AdminLoginOutcome::MfaEnrollmentRequired => {
            InternalAdminChangePasswordResponse::MfaEnrollmentRequired
        }
        AdminLoginOutcome::MfaRequired => InternalAdminChangePasswordResponse::MfaRequired,
        AdminLoginOutcome::PasswordChangeRequired { .. } => {
            tracing::error!("unexpected PasswordChangeRequired outcome from admin change-password");
            InternalAdminChangePasswordResponse::Internal
        }
        // Outcomes that only occur on the passkey path (unreachable on the password path).
        AdminLoginOutcome::PasskeyChallengeNotFound => {
            tracing::error!(
                "unexpected PasskeyChallengeNotFound outcome from admin change-password"
            );
            InternalAdminChangePasswordResponse::Internal
        }
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal admin change-password failed with internal error");
            InternalAdminChangePasswordResponse::Internal
        }
    }))
}

/// Logout (`POST /internal/logout`). Called by web on admin console logout. Revokes the SSO session
/// in the DB and audits it (cookie removal is done by web). Unknown or invalid sessions are idempotently ignored.
pub async fn logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalLogoutRequest>,
) -> Result<StatusCode, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    state
        .admin_login
        .logout(tenant, &req.sso_session_id, &ctx)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Password reset request (`POST /internal/password-reset/request`, MT18). The response does not branch on
/// whether the account exists (preventing enumeration is the use case's responsibility).
pub async fn password_reset_request(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasswordResetRequestRequest>,
) -> Result<Json<InternalPasswordResetRequestResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .password_reset
        .request_reset(tenant, &req.email, &ctx)
        .await;
    Ok(Json(match outcome {
        RequestResetOutcome::Accepted => InternalPasswordResetRequestResponse::Accepted,
        RequestResetOutcome::Unavailable => InternalPasswordResetRequestResponse::Unavailable,
        RequestResetOutcome::RateLimited => InternalPasswordResetRequestResponse::RateLimited,
    }))
}

/// Password reset execution (`POST /internal/password-reset/complete`, MT18).
pub async fn password_reset_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasswordResetCompleteRequest>,
) -> Result<Json<InternalPasswordResetCompleteResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .password_reset
        .reset_password(tenant, &req.token, &req.new_password, &ctx)
        .await;
    Ok(Json(match outcome {
        ResetPasswordOutcome::Ok => InternalPasswordResetCompleteResponse::Ok,
        ResetPasswordOutcome::InvalidOrExpired => {
            InternalPasswordResetCompleteResponse::InvalidOrExpired
        }
        ResetPasswordOutcome::WeakPassword(rejection) => {
            InternalPasswordResetCompleteResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        ResetPasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "password reset failed with internal error");
            InternalPasswordResetCompleteResponse::Internal
        }
    }))
}

/// Self-service display language change (`POST /internal/account/update-language`, MT20).
/// A signed-in user updates their own language setting via the SSO session.
pub async fn account_update_language(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountUpdateLanguageRequest>,
) -> Json<InternalAccountUpdateLanguageResponse> {
    let outcome = state
        .account_language
        .update(UpdateLanguageCommand {
            sso_session_id: req.sso_session_id,
            language: req.language,
        })
        .await;
    Json(match outcome {
        UpdateLanguageOutcome::Ok => InternalAccountUpdateLanguageResponse::Ok,
        UpdateLanguageOutcome::SessionExpired => {
            InternalAccountUpdateLanguageResponse::SessionExpired
        }
        UpdateLanguageOutcome::InvalidLanguage => {
            InternalAccountUpdateLanguageResponse::InvalidLanguage
        }
        UpdateLanguageOutcome::Internal(e) => {
            tracing::error!(error = %e, "account update-language failed with internal error");
            InternalAccountUpdateLanguageResponse::Internal
        }
    })
}

/// Self-service color scheme change (`POST /internal/account/update-theme`).
/// A signed-in user updates their own color scheme setting via the SSO session.
pub async fn account_update_theme(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountUpdateThemeRequest>,
) -> Json<InternalAccountUpdateThemeResponse> {
    let outcome = state
        .account_theme
        .update(UpdateThemeCommand {
            sso_session_id: req.sso_session_id,
            theme: req.theme,
        })
        .await;
    Json(match outcome {
        UpdateThemeOutcome::Ok => InternalAccountUpdateThemeResponse::Ok,
        UpdateThemeOutcome::SessionExpired => InternalAccountUpdateThemeResponse::SessionExpired,
        UpdateThemeOutcome::InvalidTheme => InternalAccountUpdateThemeResponse::InvalidTheme,
        UpdateThemeOutcome::Internal(e) => {
            tracing::error!(error = %e, "account update-theme failed with internal error");
            InternalAccountUpdateThemeResponse::Internal
        }
    })
}

/// Self-service profile fetch (`POST /internal/account/profile`). The settings screen fetches the user's own profile
/// via the SSO session to redisplay the display name etc. (no side effects).
pub async fn account_profile(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountProfileRequest>,
) -> Json<InternalAccountProfileResponse> {
    let outcome = state.account_profile.get(&req.sso_session_id).await;
    Json(match outcome {
        ProfileOutcome::Ok {
            name,
            preferred_username,
            email,
            language,
            theme,
        } => InternalAccountProfileResponse::Ok {
            name,
            preferred_username,
            email,
            language,
            theme,
        },
        ProfileOutcome::SessionExpired => InternalAccountProfileResponse::SessionExpired,
        ProfileOutcome::Internal(e) => {
            tracing::error!(error = %e, "account profile fetch failed with internal error");
            InternalAccountProfileResponse::Internal
        }
    })
}

/// Self-service display name update (`POST /internal/account/update-name`). A signed-in user
/// updates their own display name (`users.name`) via the SSO session. Empty or whitespace-only clears it.
pub async fn account_update_name(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountUpdateNameRequest>,
) -> Json<InternalAccountUpdateNameResponse> {
    let outcome = state
        .account_profile
        .update_name(UpdateNameCommand {
            sso_session_id: req.sso_session_id,
            name: req.name,
        })
        .await;
    Json(match outcome {
        UpdateNameOutcome::Ok => InternalAccountUpdateNameResponse::Ok,
        UpdateNameOutcome::SessionExpired => InternalAccountUpdateNameResponse::SessionExpired,
        UpdateNameOutcome::Invalid => InternalAccountUpdateNameResponse::Invalid,
        UpdateNameOutcome::Internal(e) => {
            tracing::error!(error = %e, "account update-name failed with internal error");
            InternalAccountUpdateNameResponse::Internal
        }
    })
}

/// Lists the tenants the signed-in user belongs to (`POST /internal/account/tenants`). Called by the tenant switcher UI
/// to get the candidate tenants (those with an `ACTIVE` membership).
pub async fn account_tenants(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountTenantsRequest>,
) -> Json<InternalAccountTenantsResponse> {
    let outcome = state.account_tenants.list(&req.sso_session_id).await;
    Json(match outcome {
        ListTenantsOutcome::Ok(tenants) => InternalAccountTenantsResponse::Ok {
            tenants: tenants
                .into_iter()
                .map(|t| AccountTenantSummary {
                    tenant_id: t.tenant_id,
                    name: t.name,
                    membership_type: t.membership_type,
                })
                .collect(),
        },
        ListTenantsOutcome::SessionExpired => InternalAccountTenantsResponse::SessionExpired,
        ListTenantsOutcome::Internal(e) => {
            tracing::error!(error = %e, "account tenants list failed with internal error");
            InternalAccountTenantsResponse::Internal
        }
    })
}

/// Self-service security screen (`POST /internal/account/security`, G10).
///
/// Returns the list of signed-in sessions and connected apps. CSRF already verified by web.
pub async fn account_security(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSecurityRequest>,
) -> Result<Json<InternalAccountSecurityResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .overview(tenant, &req.sso_session_id)
        .await;
    Ok(Json(match outcome {
        SecurityOverviewOutcome::Ok(overview) => InternalAccountSecurityResponse::Ok {
            sessions: overview
                .sessions
                .into_iter()
                .map(|s| AccountSessionSummary {
                    id: s.id,
                    current: s.current,
                    auth_time: s.auth_time.to_rfc3339(),
                    multi_factor: s.multi_factor,
                    user_agent: s.user_agent,
                    ip_address: s.ip_address,
                    created_at: s.created_at.to_rfc3339(),
                    idle_expires_at: s.idle_expires_at.to_rfc3339(),
                    absolute_expires_at: s.absolute_expires_at.to_rfc3339(),
                })
                .collect(),
            connected_apps: overview
                .connected_apps
                .into_iter()
                .map(|a| AccountConnectedAppSummary {
                    client_id: a.client_id,
                    app_name: a.app_name,
                    scopes: a.scopes,
                    granted_at: a.granted_at.to_rfc3339(),
                    updated_at: a.updated_at.to_rfc3339(),
                })
                .collect(),
        },
        SecurityOverviewOutcome::SessionExpired => InternalAccountSecurityResponse::SessionExpired,
        SecurityOverviewOutcome::Internal(e) => {
            tracing::error!(error = %e, "account security overview failed with internal error");
            InternalAccountSecurityResponse::Internal
        }
    }))
}

/// Revokes a signed-in session (`POST /internal/account/security/revoke-session`, G10).
pub async fn account_revoke_session(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeSessionRequest>,
) -> Result<Json<InternalAccountRevokeSessionResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .revoke_session(tenant, &req.sso_session_id, &req.session_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeSessionOutcome::Ok => InternalAccountRevokeSessionResponse::Ok,
        RevokeSessionOutcome::NotFound => InternalAccountRevokeSessionResponse::NotFound,
        RevokeSessionOutcome::CurrentSession => {
            InternalAccountRevokeSessionResponse::CurrentSession
        }
        RevokeSessionOutcome::SessionExpired => {
            InternalAccountRevokeSessionResponse::SessionExpired
        }
        RevokeSessionOutcome::Internal(e) => {
            tracing::error!(error = %e, "account session revocation failed with internal error");
            InternalAccountRevokeSessionResponse::Internal
        }
    }))
}

/// Disconnects a connected app (`POST /internal/account/security/revoke-consent`, G10).
pub async fn account_revoke_consent(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeConsentRequest>,
) -> Result<Json<InternalAccountRevokeConsentResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .revoke_consent(tenant, &req.sso_session_id, &req.client_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeConsentOutcome::Ok => InternalAccountRevokeConsentResponse::Ok,
        RevokeConsentOutcome::SessionExpired => {
            InternalAccountRevokeConsentResponse::SessionExpired
        }
        RevokeConsentOutcome::Internal(e) => {
            tracing::error!(error = %e, "account consent revocation failed with internal error");
            InternalAccountRevokeConsentResponse::Internal
        }
    }))
}

/// Reissues issued tokens (`POST /internal/account/security/reissue-tokens`, ADR-0047).
///
/// Revokes all of the user's refresh tokens. Neither sessions nor consents are touched, so apps
/// re-obtain them through SSO on the next refresh.
pub async fn account_reissue_tokens(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountReissueTokensRequest>,
) -> Result<Json<InternalAccountReissueTokensResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .reissue_tokens(tenant, &req.sso_session_id, &ctx)
        .await;
    Ok(Json(match outcome {
        ReissueTokensOutcome::Ok { revoked } => {
            InternalAccountReissueTokensResponse::Ok { revoked }
        }
        ReissueTokensOutcome::SessionExpired => {
            InternalAccountReissueTokensResponse::SessionExpired
        }
        ReissueTokensOutcome::Internal(e) => {
            tracing::error!(error = %e, "account token reissue failed with internal error");
            InternalAccountReissueTokensResponse::Internal
        }
    }))
}

/// Step-up decision (`POST /internal/step-up/check`, AP5).
///
/// Called by web right before a sensitive operation; on `ChallengeRequired` it leads to the identity check screen.
pub async fn step_up_check(
    State(state): State<AppState>,
    Json(req): Json<InternalStepUpCheckRequest>,
) -> Result<Json<InternalStepUpCheckResponse>, Response> {
    // Tenant is required (fail-closed like the other `/internal/*`; used for the audit's tenant record).
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(operation) = SensitiveOperation::parse(&req.operation) else {
        return Ok(Json(InternalStepUpCheckResponse::UnknownOperation));
    };
    Ok(Json(
        match state.step_up.check(&req.sso_session_id, operation).await {
            StepUpCheckOutcome::Satisfied => InternalStepUpCheckResponse::Satisfied,
            StepUpCheckOutcome::ChallengeRequired {
                second_factor_required,
                passkey_available,
                passkey_only,
            } => InternalStepUpCheckResponse::ChallengeRequired {
                second_factor_required,
                passkey_available,
                passkey_only,
            },
            StepUpCheckOutcome::SessionExpired => InternalStepUpCheckResponse::SessionExpired,
            StepUpCheckOutcome::Internal(e) => {
                tracing::error!(error = %e, "step-up check failed with internal error");
                InternalStepUpCheckResponse::Internal
            }
        },
    ))
}

/// Step-up verification (`POST /internal/step-up/verify`, AP5). CSRF already verified by web.
pub async fn step_up_verify(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalStepUpVerifyRequest>,
) -> Result<Json<InternalStepUpVerifyResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(operation) = SensitiveOperation::parse(&req.operation) else {
        return Ok(Json(InternalStepUpVerifyResponse::UnknownOperation));
    };
    let outcome = state
        .step_up
        .verify(
            tenant,
            StepUpVerifyCommand {
                sso_session_id: req.sso_session_id,
                operation,
                password: req.password,
                totp_code: req.totp_code,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        StepUpVerifyOutcome::Ok => InternalStepUpVerifyResponse::Ok,
        StepUpVerifyOutcome::InvalidCredentials => InternalStepUpVerifyResponse::InvalidCredentials,
        StepUpVerifyOutcome::SecondFactorRequired => {
            InternalStepUpVerifyResponse::SecondFactorRequired
        }
        StepUpVerifyOutcome::RateLimited => InternalStepUpVerifyResponse::RateLimited,
        StepUpVerifyOutcome::SessionExpired => InternalStepUpVerifyResponse::SessionExpired,
        StepUpVerifyOutcome::Internal(e) => {
            tracing::error!(error = %e, "step-up verify failed with internal error");
            InternalStepUpVerifyResponse::Internal
        }
    }))
}

/// Starts passkey identity verification (`POST /internal/step-up/passkey/begin`, AP5, T38).
///
/// It is separate from starting a login **in order to issue challenges with a different purpose**. A challenge issued here
/// cannot be used to log in, and a login challenge does not pass identity verification.
pub async fn step_up_passkey_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalStepUpPasskeyBeginRequest>,
) -> Result<Json<InternalStepUpPasskeyBeginResponse>, Response> {
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    // Don't hand challenges to someone not signed in (verification is an operation that "elevates an existing session";
    // without anything to elevate, don't start).
    if state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
        .is_none()
    {
        return Ok(Json(InternalStepUpPasskeyBeginResponse::SessionExpired));
    }
    Ok(Json(match state.step_up.begin_passkey().await {
        Ok((challenge_id, options)) => InternalStepUpPasskeyBeginResponse::Ok {
            challenge_id: challenge_id.to_string(),
            options,
        },
        Err(e) => {
            tracing::error!(error = %e, "step-up passkey begin failed");
            InternalStepUpPasskeyBeginResponse::Internal
        }
    }))
}

/// Passkey identity verification (`POST /internal/step-up/passkey/verify`, AP5, T38). CSRF already verified by web.
pub async fn step_up_passkey_verify(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalStepUpPasskeyVerifyRequest>,
) -> Result<Json<InternalStepUpPasskeyVerifyResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(operation) = SensitiveOperation::parse(&req.operation) else {
        return Ok(Json(InternalStepUpPasskeyVerifyResponse::UnknownOperation));
    };
    let Ok(challenge_id) = req.challenge_id.parse::<uuid::Uuid>() else {
        // An unparseable id means "no such challenge", not an internal error.
        return Ok(Json(InternalStepUpPasskeyVerifyResponse::InvalidCredential));
    };
    let outcome = state
        .step_up
        .verify_with_passkey(
            tenant,
            StepUpPasskeyVerifyCommand {
                sso_session_id: req.sso_session_id,
                operation,
                challenge_id,
                credential: req.credential,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        StepUpVerifyOutcome::Ok => InternalStepUpPasskeyVerifyResponse::Ok,
        StepUpVerifyOutcome::InvalidCredentials => {
            InternalStepUpPasskeyVerifyResponse::InvalidCredential
        }
        StepUpVerifyOutcome::RateLimited => InternalStepUpPasskeyVerifyResponse::RateLimited,
        StepUpVerifyOutcome::SessionExpired => InternalStepUpPasskeyVerifyResponse::SessionExpired,
        // Outcomes that only occur on the password path (a passkey satisfies multi-factor in one go).
        StepUpVerifyOutcome::SecondFactorRequired => {
            tracing::error!("unexpected second-factor request from a passkey step-up");
            InternalStepUpPasskeyVerifyResponse::Internal
        }
        StepUpVerifyOutcome::Internal(e) => {
            tracing::error!(error = %e, "step-up passkey verify failed with internal error");
            InternalStepUpPasskeyVerifyResponse::Internal
        }
    }))
}

/// Lists registered authenticators (`POST /internal/account/authenticators`, AP9).
pub async fn account_authenticators(
    State(state): State<AppState>,
    Json(req): Json<InternalAuthenticatorsRequest>,
) -> Result<Json<InternalAuthenticatorsResponse>, Response> {
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalAuthenticatorsResponse::SessionExpired));
    };

    let authenticators = match state.authenticators.list(user_id).await {
        Ok(list) => list,
        Err(e) => {
            tracing::error!(error = %e, "authenticator list failed");
            return Ok(Json(InternalAuthenticatorsResponse::Internal));
        }
    };
    let recovery_codes_remaining = match state
        .authenticators
        .usable_recovery_code_count(user_id)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "recovery code count failed");
            return Ok(Json(InternalAuthenticatorsResponse::Internal));
        }
    };

    Ok(Json(InternalAuthenticatorsResponse::Ok {
        authenticators: authenticators
            .into_iter()
            .map(|a| AuthenticatorSummaryResponse {
                id: a.id.to_string(),
                authenticator_type: a.authenticator_type.as_str().to_string(),
                status: a.status.as_str().to_string(),
                label: a.label,
                created_at: a.created_at.to_rfc3339(),
                last_used_at: a.last_used_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
        recovery_codes_remaining,
        phone_registered: state
            .authenticators
            .has_confirmed_phone(user_id)
            .await
            .unwrap_or(false),
        // Without a configured gateway, don't offer registration (don't show a screen that can register but cannot send).
        sms_available: state
            .system_settings
            .sms_gateway()
            .await
            .ok()
            .flatten()
            .is_some_and(|g| g.is_usable()),
    }))
}

/// Sends an SMS OTP (`POST /internal/account/sms-otp`, AP13).
///
/// Like email OTP, sent **only to users awaiting MFA** (unauthenticated requests can't fire SMS.
/// Each SMS costs money, so this restriction is also a cost defense).
pub async fn account_sms_otp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSmsOtpRequest>,
) -> Result<Json<InternalSmsOtpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let user_id = match (req.auth_session_id.as_deref(), req.mfa_ticket.as_deref()) {
        (Some(auth_session_id), _) if !auth_session_id.is_empty() => {
            state
                .mfa_login
                .pending_mfa_user(tenant, auth_session_id)
                .await
        }
        (_, Some(ticket)) if !ticket.is_empty() => {
            state.portal_login.pending_mfa_user(tenant, ticket)
        }
        _ => None,
    };
    let Some(user_id) = user_id else {
        return Ok(Json(InternalSmsOtpResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .send_sms_otp(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(()) => InternalSmsOtpResponse::Sent,
            Err(AuthenticatorManagementError::SmsUnavailable) => {
                InternalSmsOtpResponse::Unavailable
            }
            Err(AuthenticatorManagementError::PhoneNotRegistered) => {
                InternalSmsOtpResponse::NotRegistered
            }
            Err(AuthenticatorManagementError::OtpRateLimited) => {
                InternalSmsOtpResponse::RateLimited
            }
            Err(e) => {
                tracing::error!(error = %e, "sms otp send failed");
                InternalSmsOtpResponse::Internal
            }
        },
    ))
}

/// Starts phone number registration (`POST /internal/account/phone/register`, AP13).
/// A self-service operation for signed-in users, so the target is resolved from the SSO session.
pub async fn account_phone_register(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPhoneRegistrationRequest>,
) -> Result<Json<InternalPhoneRegistrationResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalPhoneRegistrationResponse::Unauthenticated));
    };

    Ok(Json(
        match state
            .authenticators
            .start_phone_registration(tenant.tenant_id(), user_id, &req.phone_number, &ctx)
            .await
        {
            Ok(()) => InternalPhoneRegistrationResponse::Sent,
            Err(AuthenticatorManagementError::InvalidPhoneNumber) => {
                InternalPhoneRegistrationResponse::InvalidPhoneNumber
            }
            Err(AuthenticatorManagementError::SmsUnavailable) => {
                InternalPhoneRegistrationResponse::Unavailable
            }
            Err(e) => {
                // Phone numbers are PII, so they are not put in failure logs either (nor contained in the error).
                tracing::error!(error = %e, "phone registration failed");
                InternalPhoneRegistrationResponse::Internal
            }
        },
    ))
}

/// Confirms phone number registration (`POST /internal/account/phone/confirm`, AP13).
pub async fn account_phone_confirm(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPhoneConfirmationRequest>,
) -> Result<Json<InternalPhoneConfirmationResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalPhoneConfirmationResponse::Unauthenticated));
    };

    Ok(Json(
        match state
            .authenticators
            .confirm_phone_registration(tenant.tenant_id(), user_id, &req.code, &ctx)
            .await
        {
            Ok(true) => InternalPhoneConfirmationResponse::Confirmed,
            Ok(false) => InternalPhoneConfirmationResponse::InvalidCode,
            Err(e) => {
                tracing::error!(error = %e, "phone confirmation failed");
                InternalPhoneConfirmationResponse::Internal
            }
        },
    ))
}

/// Changes an authenticator's status (`POST /internal/account/authenticators/status`, AP9).
pub async fn account_authenticator_status(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthenticatorStatusRequest>,
) -> Result<Json<InternalAuthenticatorStatusResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(status) = AuthenticatorStatus::parse(&req.status) else {
        return Ok(Json(InternalAuthenticatorStatusResponse::UnknownStatus));
    };
    let Ok(authenticator_id) = uuid::Uuid::parse_str(&req.authenticator_id) else {
        return Ok(Json(InternalAuthenticatorStatusResponse::NotFound));
    };
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalAuthenticatorStatusResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .set_status(tenant.tenant_id(), user_id, authenticator_id, status, &ctx)
            .await
        {
            Ok(()) => InternalAuthenticatorStatusResponse::Ok,
            Err(AuthenticatorManagementError::NotFound) => {
                InternalAuthenticatorStatusResponse::NotFound
            }
            Err(AuthenticatorManagementError::InvalidTransition) => {
                InternalAuthenticatorStatusResponse::InvalidTransition
            }
            Err(e) => {
                tracing::error!(error = %e, "authenticator status change failed");
                InternalAuthenticatorStatusResponse::Internal
            }
        },
    ))
}

/// Issues recovery codes (`POST /internal/account/recovery-codes`, AP9).
///
/// The plaintext is returned only in this response. web shows it once and does not store it.
pub async fn account_recovery_codes(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalRecoveryCodesRequest>,
) -> Result<Json<InternalRecoveryCodesResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalRecoveryCodesResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .issue_recovery_codes(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(issued) => InternalRecoveryCodesResponse::Ok {
                codes: issued.codes,
            },
            Err(e) => {
                tracing::error!(error = %e, "recovery code issuance failed");
                InternalRecoveryCodesResponse::Internal
            }
        },
    ))
}

/// Sends an email OTP (`POST /internal/account/email-otp`, AP9).
///
/// Sent **only to users awaiting MFA**. So that unauthenticated requests can't trigger mail sending,
/// only when the user can be resolved from a password-verified `auth_session_id` (OIDC)
/// or a signed `mfa_ticket` (portal).
pub async fn account_email_otp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalEmailOtpRequest>,
) -> Result<Json<InternalEmailOtpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let user_id = match (req.auth_session_id.as_deref(), req.mfa_ticket.as_deref()) {
        (Some(auth_session_id), _) if !auth_session_id.is_empty() => {
            state
                .mfa_login
                .pending_mfa_user(tenant, auth_session_id)
                .await
        }
        (_, Some(ticket)) if !ticket.is_empty() => {
            state.portal_login.pending_mfa_user(tenant, ticket)
        }
        _ => None,
    };
    let Some(user_id) = user_id else {
        return Ok(Json(InternalEmailOtpResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .send_email_otp(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(()) => InternalEmailOtpResponse::Sent,
            Err(AuthenticatorManagementError::MailUnavailable) => {
                InternalEmailOtpResponse::Unavailable
            }
            Err(AuthenticatorManagementError::OtpRateLimited) => {
                InternalEmailOtpResponse::RateLimited
            }
            Err(e) => {
                tracing::error!(error = %e, "email otp delivery failed");
                InternalEmailOtpResponse::Internal
            }
        },
    ))
}

/// Lists enabled external IdPs (`POST /internal/external/providers`, AP10).
/// Called by web to draw the buttons on the login screen.
pub async fn external_providers(
    State(state): State<AppState>,
    Json(req): Json<InternalExternalProvidersRequest>,
) -> Result<Json<InternalExternalProvidersResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_providers
            .list_enabled_for_tenant(tenant.tenant_id())
            .await
        {
            Ok(providers) => InternalExternalProvidersResponse::Ok {
                providers: providers
                    .into_iter()
                    .map(|p| ExternalIdpButton {
                        provider_code: p.provider_code,
                        display_name: p.display_name,
                    })
                    .collect(),
            },
            Err(e) => {
                tracing::error!(error = %e, "external idp list failed");
                InternalExternalProvidersResponse::Internal
            }
        },
    ))
}

/// Starts an external IdP login (`POST /internal/external/start`, AP10).
pub async fn external_start(
    State(state): State<AppState>,
    Json(req): Json<InternalExternalStartRequest>,
) -> Result<Json<InternalExternalStartResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_login
            .start(tenant, &req.provider_code, req.auth_session_id)
            .await
        {
            StartOutcome::Redirect {
                location,
                browser_binding,
            } => InternalExternalStartResponse::Redirect {
                location,
                browser_binding: Some(browser_binding),
            },
            StartOutcome::ProviderUnavailable => InternalExternalStartResponse::ProviderUnavailable,
            StartOutcome::Internal(e) => {
                tracing::error!(error = %e, "external idp login start failed");
                InternalExternalStartResponse::Internal
            }
        },
    ))
}

/// Callback from an external IdP (`POST /internal/external/callback`, AP10).
pub async fn external_callback(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalExternalCallbackRequest>,
) -> Result<Json<InternalExternalCallbackResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_login
            .callback(
                tenant,
                CallbackCommand {
                    state: req.state,
                    code: req.code,
                    browser_binding: req.browser_binding,
                },
                &ctx,
            )
            .await
        {
            CallbackOutcome::Success {
                location,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => {
                // If it continues an authorization flow, pass both the destination and the form fields (G12).
                // Outside an authorization flow (linking started from account settings), web decides where to return.
                let (redirect_to, form_post) = match location {
                    SuccessLocation::Redirect {
                        location,
                        form_post,
                    } => (Some(location), form_post),
                    SuccessLocation::Account => (None, None),
                };
                InternalExternalCallbackResponse::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs,
                    redirect_to,
                    form_post,
                    user_language,
                }
            }
            CallbackOutcome::ConsentRequired {
                auth_session_id,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => InternalExternalCallbackResponse::ConsentRequired {
                auth_session_id,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language,
            },
            CallbackOutcome::StateExpired => InternalExternalCallbackResponse::StateExpired,
            CallbackOutcome::NotLinked => InternalExternalCallbackResponse::NotLinked,
            CallbackOutcome::UserUnavailable => InternalExternalCallbackResponse::UserUnavailable,
            CallbackOutcome::PolicyDenied => InternalExternalCallbackResponse::PolicyDenied,
            CallbackOutcome::DeviceEnrollmentRequired { ticket } => {
                InternalExternalCallbackResponse::DeviceEnrollmentRequired { ticket }
            }
            CallbackOutcome::ApplicationNotPermitted {
                application_name,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => InternalExternalCallbackResponse::ApplicationNotPermitted {
                application_name,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language,
            },
            CallbackOutcome::ExternalFailure => InternalExternalCallbackResponse::ExternalFailure,
            CallbackOutcome::Internal(e) => {
                tracing::error!(error = %e, "external idp callback failed");
                InternalExternalCallbackResponse::Internal
            }
        },
    ))
}

/// Receives an assertion from an external SAML IdP (ACS, AP12).
///
/// The response shape is **the same** as the OIDC callback (`InternalExternalCallbackResponse`). The protocols
/// differ only in "how to confirm who was authenticated"; the result from there on is the same.
pub async fn external_saml_acs(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<assay_contracts::auth::InternalExternalSamlAcsRequest>,
) -> Result<Json<InternalExternalCallbackResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_login
            .saml_acs(
                tenant,
                SamlAcsCommand {
                    saml_response: req.saml_response,
                    relay_state: req.relay_state,
                    browser_binding: req.browser_binding,
                },
                &ctx,
            )
            .await
        {
            CallbackOutcome::Success {
                location,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => {
                let (redirect_to, form_post) = match location {
                    SuccessLocation::Redirect {
                        location,
                        form_post,
                    } => (Some(location), form_post),
                    SuccessLocation::Account => (None, None),
                };
                InternalExternalCallbackResponse::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs,
                    redirect_to,
                    form_post,
                    user_language,
                }
            }
            CallbackOutcome::ConsentRequired {
                auth_session_id,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => InternalExternalCallbackResponse::ConsentRequired {
                auth_session_id,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language,
            },
            CallbackOutcome::StateExpired => InternalExternalCallbackResponse::StateExpired,
            CallbackOutcome::NotLinked => InternalExternalCallbackResponse::NotLinked,
            CallbackOutcome::UserUnavailable => InternalExternalCallbackResponse::UserUnavailable,
            CallbackOutcome::PolicyDenied => InternalExternalCallbackResponse::PolicyDenied,
            CallbackOutcome::DeviceEnrollmentRequired { ticket } => {
                InternalExternalCallbackResponse::DeviceEnrollmentRequired { ticket }
            }
            CallbackOutcome::ApplicationNotPermitted {
                application_name,
                sso_session_id,
                user_language,
                sso_absolute_ttl_secs,
            } => InternalExternalCallbackResponse::ApplicationNotPermitted {
                application_name,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language,
            },
            CallbackOutcome::ExternalFailure => InternalExternalCallbackResponse::ExternalFailure,
            CallbackOutcome::Internal(e) => {
                tracing::error!(error = %e, "external saml acs failed");
                InternalExternalCallbackResponse::Internal
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        // The comparison itself is defined once in contracts (`internal_auth`). Here we only
        // check that the api goes through that function.
        assert!(service_token_matches("secret-token", "secret-token"));
        assert!(!service_token_matches("secret-token", "secret-tokeN"));
    }

    #[test]
    fn authenticate_response_is_tagged_by_result() {
        let success = InternalAuthenticateResponse::Success {
            form_post: None,
            redirect_to: "https://rp.example.com/cb?code=abc&state=s".to_string(),
            sso_session_id: "sso-123".to_string(),
            sso_absolute_ttl_secs: 86_400,
            user_language: None,
        };
        let json = serde_json::to_value(&success).unwrap();
        assert_eq!(json["result"], "success");
        assert_eq!(json["sso_session_id"], "sso-123");
        assert_eq!(json["sso_absolute_ttl_secs"], 86_400);

        let invalid =
            serde_json::to_value(InternalAuthenticateResponse::InvalidCredentials).unwrap();
        assert_eq!(invalid["result"], "invalid_credentials");
        // Failure variants have no fields other than the discriminator.
        assert_eq!(invalid.as_object().unwrap().len(), 1);
    }

    #[test]
    fn admin_response_is_tagged_by_result() {
        let forbidden = serde_json::to_value(InternalAdminAuthenticateResponse::Forbidden).unwrap();
        assert_eq!(forbidden["result"], "forbidden");

        let ok = serde_json::to_value(InternalAdminAuthenticateResponse::Success {
            sso_session_id: "sso-9".to_string(),
            sso_absolute_ttl_secs: 3_600,
        })
        .unwrap();
        assert_eq!(ok["result"], "success");
        assert_eq!(ok["sso_session_id"], "sso-9");
    }
}
