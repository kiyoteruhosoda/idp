//! Authenticator management screen (web. `/{tenant_id}/settings/authenticators`. AP9).
//!
//! Shows the registry across kinds (TOTP, passkey) on one screen and provides suspend, resume, revoke,
//! and issuing recovery codes. Decisions and persistence are done by the api (`/internal/account/authenticators*`);
//! web only handles CSRF, the step-up gate and rendering.
//!
//! Every operation touching authenticators is subject to step-up (AP5). If a stolen session could add an authenticator,
//! it would afterwards act as a legitimate credential.

use super::{api_internal_error, internal_call_status};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AuthenticatorView, RecoveryCodes, UserAuthenticators};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAuthenticatorStatusRequest, InternalAuthenticatorStatusResponse,
    InternalAuthenticatorsRequest, InternalAuthenticatorsResponse, InternalRecoveryCodesRequest,
    InternalRecoveryCodesResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AuthenticatorsQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// On `confirm`, shows the phone number confirmation code field (AP13).
    #[serde(default)]
    pub phone: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatusForm {
    pub authenticator_id: String,
    /// `suspended` / `active` / `revoked`.
    pub status: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoveryCodesForm {
    pub csrf_token: String,
}

/// Authenticator list (`GET /{tenant_id}/settings/authenticators`).
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AuthenticatorsQuery>,
) -> Response {
    let locale = locale(&headers);
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    let request = InternalAuthenticatorsRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
    };
    let outcome = match state
        .api
        .account_authenticators(&correlation.0, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "authenticator list call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    let (authenticators, recovery_codes_remaining, phone_registered, sms_available) = match outcome
    {
        InternalAuthenticatorsResponse::Ok {
            authenticators,
            recovery_codes_remaining,
            phone_registered,
            sms_available,
        } => (
            authenticators,
            recovery_codes_remaining,
            phone_registered,
            sms_available,
        ),
        InternalAuthenticatorsResponse::SessionExpired => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        InternalAuthenticatorsResponse::Internal => {
            return api_internal_error("authenticators");
        }
    };

    let messages = Messages::new(locale);
    let views: Vec<AuthenticatorView> = authenticators
        .into_iter()
        .map(|a| AuthenticatorView {
            // Map kind and status to translation keys (showing raw values would mix English into the screen).
            type_key: type_message_key(&a.authenticator_type),
            status_key: status_message_key(&a.status),
            suspendable: a.status == "active",
            resumable: a.status == "suspended",
            id: a.id,
            label: a.label,
            created_at: a.created_at,
            last_used_at: a.last_used_at.unwrap_or_default(),
        })
        .collect();

    Html(render(&UserAuthenticators {
        messages: &messages,
        tenant: &tenant.prefix(),
        csrf: &csrf,
        authenticators: &views,
        recovery_codes_remaining,
        // SMS OTP (AP13): if no gateway is configured, hide the whole entry point (do not show a screen that
        // can register but cannot send). Show the code field only while awaiting confirmation.
        sms_available,
        phone_registered,
        awaiting_phone_code: query.phone.as_deref() == Some("confirm"),
        saved_key: query.saved.as_deref().and_then(saved_key_for),
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// Changes an authenticator's status (`POST /{tenant_id}/settings/authenticators/status`).
pub async fn set_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<StatusForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_AUTHENTICATORS,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAuthenticatorStatusRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        authenticator_id: form.authenticator_id,
        status: form.status,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_authenticator_status(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalAuthenticatorStatusResponse::Ok) => see_other(&format!("{base}?saved=status")),
        Ok(InternalAuthenticatorStatusResponse::NotFound) => {
            see_other(&format!("{base}?error=not-found"))
        }
        Ok(InternalAuthenticatorStatusResponse::InvalidTransition)
        | Ok(InternalAuthenticatorStatusResponse::UnknownStatus) => {
            see_other(&format!("{base}?error=transition"))
        }
        Ok(InternalAuthenticatorStatusResponse::SessionExpired) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(InternalAuthenticatorStatusResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "authenticator status call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// Issues recovery codes (`POST /{tenant_id}/settings/recovery-codes`).
///
/// The plaintext is **shown only in this response**. The result is rendered directly instead of PRG because a redirect
/// would put the codes in the URL or in a server-side temporary store (neither should remain).
pub async fn issue_recovery_codes(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RecoveryCodesForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_AUTHENTICATORS,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalRecoveryCodesRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let codes = match state
        .api
        .account_recovery_codes(&ctx.correlation_id, &request)
        .await
    {
        Ok(InternalRecoveryCodesResponse::Ok { codes }) => codes,
        Ok(InternalRecoveryCodesResponse::SessionExpired) => {
            return found(&format!("{}/login", tenant.prefix()));
        }
        Ok(InternalRecoveryCodesResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "recovery code issuance call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&RecoveryCodes {
        messages: &messages,
        tenant: &tenant.prefix(),
        codes: &codes,
    }))
    .into_response()
}

/// Maps an authenticator kind to a translation key (unknown values fall back to "other").
fn type_message_key(value: &str) -> &'static str {
    match value {
        "totp" => "authenticator-type-totp",
        "webauthn" => "authenticator-type-webauthn",
        "email_otp" => "authenticator-type-email-otp",
        "sms_otp" => "authenticator-type-sms-otp",
        "recovery_code" => "authenticator-type-recovery-code",
        _ => "authenticator-type-unknown",
    }
}

fn status_message_key(value: &str) -> &'static str {
    match value {
        "pending" => "authenticator-status-pending",
        "active" => "authenticator-status-active",
        "suspended" => "authenticator-status-suspended",
        "revoked" => "authenticator-status-revoked",
        _ => "authenticator-status-unknown",
    }
}

fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "status" => Some("authenticator-saved-status"),
        "phone" => Some("authenticator-saved-phone"),
        // Returning from finishing TOTP setup (`mfa_totp::setup_confirm`).
        "totp" => Some("authenticator-saved-totp"),
        // Returning from deleting TOTP (`mfa_totp::setup_delete`).
        "totp-deleted" => Some("authenticator-saved-totp-deleted"),
        _ => None,
    }
}

fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "csrf" => Some("user-security-error-csrf"),
        "not-found" => Some("authenticator-error-not-found"),
        "transition" => Some("authenticator-error-transition"),
        "phone-invalid" => Some("authenticator-error-phone-invalid"),
        "phone-code" => Some("authenticator-error-phone-code"),
        "sms-unavailable" => Some("authenticator-error-sms-unavailable"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kinds and statuses returned by the api are never shown as is but always mapped to translation keys
    /// (so raw English identifiers do not leak to the screen when new values are added).
    #[test]
    fn unknown_types_and_statuses_fall_back_to_a_known_key() {
        assert_eq!(type_message_key("totp"), "authenticator-type-totp");
        assert_eq!(type_message_key("quantum"), "authenticator-type-unknown");
        assert_eq!(status_message_key("active"), "authenticator-status-active");
        assert_eq!(status_message_key("weird"), "authenticator-status-unknown");
    }

    #[test]
    fn only_known_banner_values_map_to_message_keys() {
        assert_eq!(saved_key_for("status"), Some("authenticator-saved-status"));
        assert_eq!(saved_key_for("totp"), Some("authenticator-saved-totp"));
        assert_eq!(
            saved_key_for("totp-deleted"),
            Some("authenticator-saved-totp-deleted")
        );
        assert_eq!(saved_key_for("<script>"), None);
        assert_eq!(error_key_for("anything"), None);
    }
}

// ── Phone number registration (AP13) ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PhoneRegistrationForm {
    pub phone_number: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct PhoneConfirmationForm {
    pub code: String,
    pub csrf_token: String,
}

/// Starts phone number registration (`POST /{tenant_id}/settings/authenticators/phone`).
///
/// Adding an authenticator is a sensitive operation, so like status changes it requires step-up (recent re-auth).
/// Letting it through would allow swapping the second factor's destination from an unattended screen.
pub async fn start_phone_registration(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PhoneRegistrationForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return see_other(&format!("{base}?error=csrf"));
    }
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        step_up::MANAGE_AUTHENTICATORS,
        &base,
    )
    .await
    {
        return response;
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = assay_contracts::auth::InternalPhoneRegistrationRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        phone_number: form.phone_number,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_phone_register(&ctx.correlation_id, &request)
        .await
    {
        Ok(assay_contracts::auth::InternalPhoneRegistrationResponse::Sent) => {
            see_other(&format!("{base}?phone=confirm"))
        }
        Ok(assay_contracts::auth::InternalPhoneRegistrationResponse::InvalidPhoneNumber) => {
            see_other(&format!("{base}?error=phone-invalid"))
        }
        Ok(assay_contracts::auth::InternalPhoneRegistrationResponse::Unavailable) => {
            see_other(&format!("{base}?error=sms-unavailable"))
        }
        Ok(assay_contracts::auth::InternalPhoneRegistrationResponse::Unauthenticated) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(assay_contracts::auth::InternalPhoneRegistrationResponse::Internal) => {
            api_internal_error("phone_registration")
        }
        Err(e) => {
            // A phone number is PII, so it is not logged even on failure (the request itself is not logged).
            tracing::error!(error = %e, "phone registration call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// Confirms phone number registration (`POST /{tenant_id}/settings/authenticators/phone/confirm`).
pub async fn confirm_phone_registration(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PhoneConfirmationForm>,
) -> Response {
    let base = format!("{}/settings/authenticators", tenant.prefix());
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return see_other(&format!("{base}?error=csrf"));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = assay_contracts::auth::InternalPhoneConfirmationRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: sso,
        code: form.code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_phone_confirm(&ctx.correlation_id, &request)
        .await
    {
        Ok(assay_contracts::auth::InternalPhoneConfirmationResponse::Confirmed) => {
            see_other(&format!("{base}?saved=phone"))
        }
        Ok(assay_contracts::auth::InternalPhoneConfirmationResponse::InvalidCode) => {
            // Return to the awaiting-confirmation screen (so another code can be entered).
            see_other(&format!("{base}?phone=confirm&error=phone-code"))
        }
        Ok(assay_contracts::auth::InternalPhoneConfirmationResponse::Unauthenticated) => {
            found(&format!("{}/login", tenant.prefix()))
        }
        Ok(assay_contracts::auth::InternalPhoneConfirmationResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "phone confirmation call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}
