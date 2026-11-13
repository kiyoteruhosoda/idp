//! MFA TOTP self-enrollment handlers (`GET/POST /account/mfa/totp/*`) and
//! login flow TOTP input handlers (`GET/POST /mfa/totp`).
//!
//! * Setup screen (`/account/mfa/totp/setup`): an SSO-authenticated user self-enrolls TOTP.
//!   Shows a QR code (SVG) and the raw secret (base32). If the QR cannot be used, the raw code is entered.
//!   The POSTs for sending the confirmation code (enabling) and deletion are protected by the same CSRF synchronizer
//!   token as other post-login account screens (`console_csrf_token`, derived from the SSO session id) (task #118). It differs
//!   from the login-side TOTP input (`login_csrf_token`, derived from the authorization session) only in the seed; the practice
//!   is the same (on mismatch do nothing, return via PRG and report with the `?error=csrf` banner).
//! * Login TOTP screen (`/mfa/totp`): asks for TOTP input after password authentication.

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::dto::{FormPageQuery, TotpConfirmForm, TotpDeleteForm};
use crate::handlers::step_up::{self, MANAGE_AUTHENTICATORS};
use crate::handlers::{form_retry_error_key, forwarded_context, found, see_other};
use crate::i18n::Messages;
use crate::login_context::RpLoginContext;
use crate::state::WebState;
use crate::templates::{
    render, MessagePage, TotpAccountErrorTemplate, TotpSetupTemplate, TotpVerifyTemplate,
};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalTotpConfirmRequest, InternalTotpDeleteRequest, InternalTotpSetupRequest,
    InternalVerifyTotpRequest, InternalVerifyTotpResponse,
};
use assay_contracts::csrf::login_csrf_token;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

// ── TOTP setup ────────────────────────────────────────────────────────

/// TOTP setup screen (`GET /account/mfa/totp/setup`).
///
/// Requires the SSO cookie. Fetches the QR URI and raw secret from the api and shows the QR SVG + raw code.
/// `?error=csrf` shows the error banner when coming back via PRG from a confirmation POST with a CSRF mismatch.
pub async fn setup_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<FormPageQuery>,
) -> Response {
    // Adding an authenticator is subject to step-up (AP5). If a stolen session could add its own authenticator,
    // it would afterwards act as a legitimate credential.
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/mfa/totp/setup", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // FluentBundle is !Send, so create and consume it before the await.
        let messages = Messages::new(locale(&headers));
        return account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };

    // The account label shown in the authenticator app is looked up by the api from the SSO session's user (web does not know the user name).
    let req = InternalTotpSetupRequest {
        sso_session_id: sso_session_id.clone(),
    };
    let result = match state.api.totp_setup(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp setup call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    // FluentBundle is !Send, so create it after the await.
    let messages = Messages::new(locale(&headers));

    use assay_contracts::auth::InternalTotpSetupResponse;
    match result {
        InternalTotpSetupResponse::Ok {
            totp_uri,
            secret_base32,
        } => {
            let qr_svg = generate_qr_svg(&totp_uri);
            Html(render(&TotpSetupTemplate {
                messages: &messages,
                tenant_prefix: &tenant.prefix(),
                qr_svg: &qr_svg,
                secret_base32: &secret_base32,
                error_key: setup_banner_key(query.error.as_deref()),
                csrf: &console_csrf_token(&sso_session_id, state.config.csrf_secret()),
            }))
            .into_response()
        }
        InternalTotpSetupResponse::AlreadyConfigured => account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::CONFLICT,
            "mfa-error-already-configured",
        ),
        InternalTotpSetupResponse::SessionExpired => account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            "mfa-error-session-expired",
        ),
        InternalTotpSetupResponse::Internal => api_internal_error("totp_setup"),
    }
}

/// TOTP confirmation form (`POST /account/mfa/totp/setup`). Verifies the 6-digit code and enables it.
pub async fn setup_confirm(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };
    // Check CSRF before step-up (same order as state changes on the authenticator screen). On mismatch send nothing
    // to the api and make the user reload the settings screen.
    if !console_csrf_valid(
        &sso_session_id,
        &form.csrf_token,
        state.config.csrf_secret(),
    ) {
        tracing::warn!("totp setup confirmation rejected: csrf token mismatch");
        return see_other(&format!(
            "{}/account/mfa/totp/setup?error=csrf",
            tenant.prefix()
        ));
    }
    // This POST is what enables the authenticator (the screen gate alone cannot protect it; same reason as passkey).
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/mfa/totp/setup", tenant.prefix()),
    )
    .await
    {
        return response;
    }

    let req = InternalTotpConfirmRequest {
        sso_session_id: sso_session_id.clone(),
        code: form.code.trim().to_string(),
    };
    let result = match state.api.totp_confirm(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp confirm call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // For InvalidCode, await once more first to re-fetch the QR (before getting Messages).
    use assay_contracts::auth::InternalTotpConfirmResponse;
    let refetch_qr = matches!(result, InternalTotpConfirmResponse::InvalidCode);
    let qr_data = if refetch_qr {
        let setup_req = InternalTotpSetupRequest {
            sso_session_id: sso_session_id.clone(),
        };
        state.api.totp_setup(&correlation.0, &setup_req).await.ok()
    } else {
        None
    };

    // FluentBundle is !Send, so create it after all awaits.
    let messages = Messages::new(locale(&headers));

    match result {
        // On completion return to the authenticator screen and report with a banner (PRG). A screen that only announced completion
        // was a dead end with nothing telling where to go next (task #82).
        InternalTotpConfirmResponse::Ok => see_other(&format!(
            "{}/settings/authenticators?saved=totp",
            tenant.prefix()
        )),
        InternalTotpConfirmResponse::InvalidCode => {
            if let Some(assay_contracts::auth::InternalTotpSetupResponse::Ok {
                totp_uri,
                secret_base32,
            }) = qr_data
            {
                let qr_svg = generate_qr_svg(&totp_uri);
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Html(render(&TotpSetupTemplate {
                        messages: &messages,
                        tenant_prefix: &tenant.prefix(),
                        qr_svg: &qr_svg,
                        secret_base32: &secret_base32,
                        error_key: Some("mfa-error-invalid-code"),
                        csrf: &console_csrf_token(&sso_session_id, state.config.csrf_secret()),
                    })),
                )
                    .into_response();
            }
            account_error_page(
                &messages,
                &tenant.prefix(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "mfa-error-invalid-code",
            )
        }
        InternalTotpConfirmResponse::NotFound | InternalTotpConfirmResponse::SessionExpired => {
            account_error_page(
                &messages,
                &tenant.prefix(),
                StatusCode::UNAUTHORIZED,
                "mfa-error-session-expired",
            )
        }
        InternalTotpConfirmResponse::AlreadyConfigured => account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::CONFLICT,
            "mfa-error-already-configured",
        ),
        InternalTotpConfirmResponse::Internal => api_internal_error("totp_confirm"),
    }
}

/// TOTP deletion (`POST /account/mfa/totp/delete`). Disables MFA.
///
/// Requires the same CSRF synchronizer token as setup (the confirmation POST) (task #118). Removing MFA is not protected by
/// SameSite=Lax alone. On mismatch do nothing, return to the authenticator screen and report with the `?error=csrf` banner.
pub async fn setup_delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<TotpDeleteForm>,
) -> Response {
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
            tracing::warn!("totp deletion rejected: csrf token mismatch");
            return see_other(&format!(
                "{}/settings/authenticators?error=csrf",
                tenant.prefix()
            ));
        }
    }
    // Deleting an authenticator is also subject to step-up (AP5). If MFA can be removed, single-factor sign-in is possible from then on.
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/settings", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            "mfa-error-not-signed-in",
        );
    };

    let req = InternalTotpDeleteRequest { sso_session_id };
    let result = match state.api.totp_delete(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "totp delete call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    // FluentBundle is !Send, so create it after the await.
    let messages = Messages::new(locale(&headers));

    use assay_contracts::auth::InternalTotpDeleteResponse;
    match result {
        // Deletion also returns to the authenticator screen with a banner (PRG; same shape as setup completion, task #82).
        // The screen that only announced completion had no path back to account settings (task #121).
        InternalTotpDeleteResponse::Ok => see_other(&format!(
            "{}/settings/authenticators?saved=totp-deleted",
            tenant.prefix()
        )),
        InternalTotpDeleteResponse::SessionExpired => account_error_page(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            "mfa-error-session-expired",
        ),
        InternalTotpDeleteResponse::Internal => api_internal_error("totp_delete"),
    }
}

// ── Login flow TOTP input ─────────────────────────────────────────────────

/// TOTP input page (`GET /mfa/totp`). Shown during the login flow (after password authentication).
/// `?error=csrf` shows the error banner when coming back via PRG from a POST with a CSRF mismatch.
pub async fn verify_page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    Extension(rp_context): Extension<RpLoginContext>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        );
    };
    let body = render_verify_form(
        &messages,
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        // Guidance about send results is carried in the same `?error=` (because of PRG).
        verify_banner_key(query.error.as_deref()),
        &tenant.prefix(),
    );
    // If no consent is needed, the TOTP submission ends in a redirect straight to the RP. As on the login
    // screen, only the RP's origin is allowed in `form-action` (SEC3).
    crate::security_headers::html_with_form_action_csp(
        rp_context.redirect_uri.as_deref().unwrap_or_default(),
        body,
    )
}

/// TOTP input processing (`POST /mfa/totp`). Verifies the code and, on success, issues the SSO cookie and redirects.
pub async fn verify(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    Extension(rp_context): Extension<RpLoginContext>,
    headers: HeaderMap,
    Form(form): Form<TotpLoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    let req = InternalVerifyTotpRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        totp_code: form.totp_code,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state.api.verify_totp(&ctx.correlation_id, &req).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "verify_totp call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));

    match outcome {
        InternalVerifyTotpResponse::Success {
            redirect_to,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            let mut set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            // If the user has a DB language setting, sync it into the lang cookie (MT20: DB > Cookie priority).
            if let Some(lang) = user_language
                .as_deref()
                .and_then(crate::i18n::Locale::from_tag)
            {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
                );
            }
            (
                set_cookies.into_headers(),
                crate::authorization_response::respond(&messages, &redirect_to, form_post),
            )
                .into_response()
        }
        InternalVerifyTotpResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &new_auth_session_id,
                    state.config.auth_session_ttl_secs(),
                );
            (
                set_cookies.into_headers(),
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalVerifyTotpResponse::InvalidCode => reshow_verify_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "mfa-error-invalid-code",
            state.config.csrf_secret(),
            &tenant.prefix(),
            rp_context.redirect_uri.as_deref().unwrap_or_default(),
        ),
        // Rate limiting/lockout cannot be retried by showing the form, so make it a guidance-only page (SEC3).
        InternalVerifyTotpResponse::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "mfa-error-rate-limited",
        ),
        InternalVerifyTotpResponse::Locked => {
            error_page(&messages, StatusCode::FORBIDDEN, "mfa-error-locked")
        }
        // The second factor passed, but use of this app is not permitted (ADR-0054).
        // The SSO cookie is issued (the user is signed in to assay).
        InternalVerifyTotpResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => (
            state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE)
                .into_headers(),
            crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
        )
            .into_response(),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalVerifyTotpResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &format!("{}/login", tenant.prefix()),
            )
        }
        InternalVerifyTotpResponse::PolicyDenied => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-policy-denied",
        ),
        InternalVerifyTotpResponse::CsrfMismatch => {
            // PRG: switch to GET with 303 and automatically re-show the form with a new token derived from the
            // current cookie (previously it just returned an error page, and reloading resent the POST with no recovery).
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "totp verify failed: csrf token mismatch; redirecting to fresh form"
            );
            see_other(&format!("{}/mfa/totp?error=csrf", tenant.prefix()))
        }
        InternalVerifyTotpResponse::SessionExpired => {
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "totp verify failed: auth session expired"
            );
            error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "mfa-error-session-expired",
            )
        }
        InternalVerifyTotpResponse::Internal => api_internal_error("verify_totp"),
    }
}

// ── QR code generation ────────────────────────────────────────────────────────────

/// Generates a QR code as an SVG string from an `otpauth://` URI.
/// Embedded directly in the template (output raw with `|safe`).
pub fn generate_qr_svg(uri: &str) -> String {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    let code = match QrCode::with_error_correction_level(uri.as_bytes(), EcLevel::M) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to generate QR code");
            return String::new();
        }
    };
    code.render::<svg::Color<'_>>()
        .min_dimensions(200, 200)
        .build()
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Maps the `?error=` value to a translation key for the TOTP input screen's banner.
///
/// Besides CSRF/retry errors (`form_retry_error_key`), email OTP send results are carried in the same query
/// (because of PRG). Unknown values show nothing.
fn verify_banner_key(value: Option<&str>) -> Option<&'static str> {
    match value {
        Some("email-sent") => Some("mfa-verify-email-sent"),
        Some("email-unavailable") => Some("mfa-verify-email-unavailable"),
        Some("sms-sent") => Some("mfa-verify-sms-sent"),
        Some("sms-unavailable") => Some("mfa-verify-sms-unavailable"),
        Some("sms-not-registered") => Some("mfa-verify-sms-not-registered"),
        Some("otp-rate-limited") => Some("mfa-verify-otp-rate-limited"),
        Some("session") => Some("mfa-error-session-expired"),
        other => form_retry_error_key(other),
    }
}

fn render_verify_form(
    messages: &Messages,
    csrf: &str,
    error_key: Option<&str>,
    tenant_prefix: &str,
) -> String {
    render(&TotpVerifyTemplate {
        messages,
        csrf,
        error_key,
        // Whether email can be sent (SMTP configured or not) is known only to the api, so the entry point is always shown,
        // and if not configured it is reported as the send result (do not let the screen reveal the configuration state).
        email_otp_available: true,
        email_otp_action: &format!("{tenant_prefix}/mfa/totp/email-code"),
        // SMS also always shows the entry point for the same reason (not configured / not registered are reported as send results).
        // Do not let the screen reveal "whether this user has registered a phone number".
        sms_otp_action: &format!("{tenant_prefix}/mfa/totp/sms-code"),
    })
}

/// email OTP send request (`POST /{tenant_id}/mfa/totp/email-code`. AP9).
///
/// Passes the MFA-pending `auth_session_id` to the api and has it send a short-lived code to the registered email address.
/// The outcome is returned via the screen banner; in either case it stays on the TOTP input screen.
pub async fn send_email_code(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<EmailCodeForm>,
) -> Response {
    let messages_locale = locale(&headers);
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(messages_locale);
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        );
    };
    // CSRF is verified with the same synchronizer token as the TOTP form (derived from `auth_session_id`).
    if !assay_contracts::csrf::verify(
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return see_other(&format!("{}/mfa/totp?error=csrf", tenant.prefix()));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = assay_contracts::auth::InternalEmailOtpRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: Some(auth_session_id),
        mfa_ticket: None,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let error = match state
        .api
        .account_email_otp(&ctx.correlation_id, &request)
        .await
    {
        Ok(assay_contracts::auth::InternalEmailOtpResponse::Sent) => "email-sent",
        Ok(assay_contracts::auth::InternalEmailOtpResponse::Unavailable) => "email-unavailable",
        Ok(assay_contracts::auth::InternalEmailOtpResponse::RateLimited) => "otp-rate-limited",
        Ok(assay_contracts::auth::InternalEmailOtpResponse::SessionExpired) => "session",
        Ok(assay_contracts::auth::InternalEmailOtpResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "email otp request to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    see_other(&format!("{}/mfa/totp?error={error}", tenant.prefix()))
}

/// SMS OTP send request (`POST /{tenant_id}/mfa/totp/sms-code`. AP13).
///
/// Same shape as email OTP. Has a short-lived code sent to the registered phone number and returns the result via a banner.
/// **Not registered and not configured return different wording** because what the user can do (register / ask an admin)
/// differs; rounding both to "could not send" leaves them stuck.
pub async fn send_sms_code(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<EmailCodeForm>,
) -> Response {
    let messages_locale = locale(&headers);
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(messages_locale);
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        );
    };
    if !assay_contracts::csrf::verify(
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return see_other(&format!("{}/mfa/totp?error=csrf", tenant.prefix()));
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = assay_contracts::auth::InternalSmsOtpRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: Some(auth_session_id),
        mfa_ticket: None,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let error = match state
        .api
        .account_sms_otp(&ctx.correlation_id, &request)
        .await
    {
        Ok(assay_contracts::auth::InternalSmsOtpResponse::Sent) => "sms-sent",
        Ok(assay_contracts::auth::InternalSmsOtpResponse::Unavailable) => "sms-unavailable",
        Ok(assay_contracts::auth::InternalSmsOtpResponse::NotRegistered) => "sms-not-registered",
        Ok(assay_contracts::auth::InternalSmsOtpResponse::RateLimited) => "otp-rate-limited",
        Ok(assay_contracts::auth::InternalSmsOtpResponse::SessionExpired) => "session",
        Ok(assay_contracts::auth::InternalSmsOtpResponse::Internal) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "sms otp request to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    see_other(&format!("{}/mfa/totp?error={error}", tenant.prefix()))
}

/// email OTP / SMS OTP send form (CSRF token only).
#[derive(Debug, Deserialize)]
pub struct EmailCodeForm {
    pub csrf_token: String,
}

/// **Attach the same CSP as the first render.** With the default one, only resubmission from a form re-shown after
/// a mistyped code would be unable to return to the RP.
fn reshow_verify_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
    tenant_prefix: &str,
    redirect_uri: &str,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            crate::security_headers::html_with_form_action_csp(
                redirect_uri,
                render_verify_form(
                    messages,
                    &login_csrf_token(id, csrf_secret),
                    Some(error_key),
                    tenant_prefix,
                ),
            ),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "mfa-error-session-expired",
        ),
    }
}

/// Failure screen for TOTP setup coming from account settings (`/account/mfa/totp/*`).
///
/// Separate from the login flow's [`error_page`] because the exits differ. This one is a branch of account settings,
/// so it has a back path (task #119). The login flow is on its way back to the RP and gets no path
/// leading out. 401 is a state where signing in again is the only option, so the path points to sign-in.
fn account_error_page(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    error_key: &str,
) -> Response {
    let body = render(&TotpAccountErrorTemplate {
        messages,
        tenant_prefix,
        message_key: error_key,
        sign_in_required: status == StatusCode::UNAUTHORIZED,
    });
    (status, Html(body)).into_response()
}

/// Setup screen `?error=` → banner translation key (unknown values show nothing).
fn setup_banner_key(value: Option<&str>) -> Option<&'static str> {
    match value {
        // Same wording as the authenticator and session list screens (task #118).
        Some("csrf") => Some("user-security-error-csrf"),
        _ => None,
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("mfa-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}

/// Login flow TOTP input form.
#[derive(Deserialize)]
pub struct TotpLoginForm {
    pub totp_code: String,
    pub csrf_token: String,
}
