//! Forced password change screen (`GET/POST /{tenant_id}/password-change`, ADR-0009 §5).
//!
//! Shown during the login flow (when `LoginService` has verified the password and detected `must_change_password`).
//! Delegates to the api's `POST /internal/change-password`; on success it 302s to the result (`redirect_to`)
//! of SSO issuance → consent/code issuance, same as `LoginService`.

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{FormPageQuery, PasswordChangeForm};
use crate::handlers::{form_retry_error_key, forwarded_context, found, see_other};
use crate::i18n::Messages;
use crate::login_context::RpLoginContext;
use crate::state::WebState;
use crate::templates::{render, MessagePage, PasswordChangeTemplate};
use crate::tenant::WebTenant;
use assay_contracts::auth::{InternalChangePasswordRequest, InternalChangePasswordResponse};
use assay_contracts::csrf::login_csrf_token;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// Shows the password change form. Requires the `auth_session_id` cookie (password-verified state).
/// `?error=csrf` shows the error banner when coming back via PRG from a POST with a CSRF mismatch.
pub async fn page(
    State(state): State<WebState>,
    Extension(rp_context): Extension<RpLoginContext>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        );
    };
    let body = render_form(
        &messages,
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        form_retry_error_key(query.error.as_deref()),
    );
    // If no consent is needed, submitting this form ends in a redirect straight to the RP. As on the login
    // screen, only the RP's origin is allowed in `form-action` (SEC3).
    crate::security_headers::html_with_form_action_csp(
        rp_context.redirect_uri.as_deref().unwrap_or_default(),
        body,
    )
}

/// Performs the password change. On success it issues the SSO cookie like `LoginService` → 302 to `redirect_to`.
pub async fn submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    Extension(rp_context): Extension<RpLoginContext>,
    headers: HeaderMap,
    Form(form): Form<PasswordChangeForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);
    // The re-rendered form also gets the same `form-action` allowance as the first render.
    let rp_redirect_uri = rp_context.redirect_uri.as_deref().unwrap_or_default();

    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return reshow_form(
            &messages,
            StatusCode::UNPROCESSABLE_ENTITY,
            auth_session_id.as_deref(),
            "password-change-error-mismatch",
            state.config.csrf_secret(),
            rp_redirect_uri,
        );
    }

    let request = InternalChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state
        .api
        .change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "internal change-password call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalChangePasswordResponse::Success {
            redirect_to,
            form_post,
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
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            (
                set_cookies.into_headers(),
                crate::authorization_response::respond(&messages, &redirect_to, form_post),
            )
                .into_response()
        }
        InternalChangePasswordResponse::ConsentRequired {
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
        InternalChangePasswordResponse::MfaRequired { auth_session_id } => {
            // Changed, and policy requires MFA (TOTP configured): keep the auth_session_id cookie and
            // go to the TOTP input screen (same transition as MfaRequired in the login flow).
            let set_cookies = state.set_cookies().set_session(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/mfa/totp", tenant.prefix())),
            )
                .into_response()
        }
        // Denied by the authentication policy (the password change itself has completed).
        // The change went through, but use of this app is not permitted (ADR-0054).
        InternalChangePasswordResponse::ApplicationNotPermitted {
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
        InternalChangePasswordResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &format!("{}/login", tenant.prefix()),
            )
        }
        InternalChangePasswordResponse::PolicyDenied => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-policy-denied",
        ),
        // Policy requires MFA but no authenticator (TOTP) is set up. Guide the user to set it up in the portal.
        InternalChangePasswordResponse::MfaEnrollmentRequired => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-mfa-enrollment-required",
        ),
        InternalChangePasswordResponse::SessionExpired => {
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "password change failed: auth session expired or not in must-change state"
            );
            error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "login-error-session-expired",
            )
        }
        InternalChangePasswordResponse::CsrfMismatch => {
            // PRG: switch to GET with 303 and automatically re-show the form with a new token derived from the
            // current cookie (previously it just returned an error page, and reloading resent the POST with no recovery).
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "password change failed: csrf token mismatch; redirecting to fresh form"
            );
            see_other(&format!("{}/password-change?error=csrf", tenant.prefix()))
        }
        InternalChangePasswordResponse::InvalidCurrentPassword => {
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "password change failed: current password mismatch"
            );
            reshow_form(
                &messages,
                StatusCode::UNAUTHORIZED,
                auth_session_id.as_deref(),
                "password-change-error-invalid-current",
                state.config.csrf_secret(),
                rp_redirect_uri,
            )
        }
        InternalChangePasswordResponse::WeakPassword { reason } => reshow_form(
            &messages,
            StatusCode::UNPROCESSABLE_ENTITY,
            auth_session_id.as_deref(),
            super::password_rejection_key(reason, "password-change-error-weak"),
            state.config.csrf_secret(),
            rp_redirect_uri,
        ),
        InternalChangePasswordResponse::Internal => api_internal_error("change_password"),
    }
}

fn render_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    render(&PasswordChangeTemplate {
        messages,
        csrf,
        error_key,
    })
}

/// Re-shows the form with an error (the AuthSession is still valid, so the user can re-enter).
///
/// **Attach the same CSP as the first render.** With the default one, only resubmission from a form that
/// was rejected once and shown again would be unable to return to the RP.
fn reshow_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
    redirect_uri: &str,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            crate::security_headers::html_with_form_action_csp(
                redirect_uri,
                render_form(
                    messages,
                    &login_csrf_token(id, csrf_secret),
                    Some(error_key),
                ),
            ),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("password-change-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
