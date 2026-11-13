//! End-user portal login (the OIDC-independent path of `/{tenant_id}/login`).
//!
//! `/{tenant_id}/login` works as the normal OIDC login ([`crate::handlers::login`]) when arriving from an OIDC-linked app
//! (with the `auth_session_id` cookie). For direct access without `auth_session_id`, it works as this module's
//! **portal login** (a direct login into the IdP's own account screen `/{tenant_id}/settings`).
//! [`crate::handlers::login`] dispatches by the presence of the cookie and delegates to this module.
//!
//! Authentication, SSO issuance and TOTP verification are delegated to the api (`/internal/authenticate/portal*`); web handles only
//! CSRF (synchronizer token), building cookies, rendering and redirects (same split of duties as the admin console login).

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_valid, portal_csrf_token, portal_csrf_valid};
use crate::dto::{ForcedPasswordChangeForm, LoginForm, LogoutForm, PortalTotpForm};
use crate::handlers::{forwarded_context, found, see_other};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ForcedPasswordChange, MessagePage, PortalLogin, PortalMfa};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalPortalAuthenticateRequest, InternalPortalAuthenticateResponse,
    InternalPortalChangePasswordRequest, InternalPortalChangePasswordResponse,
    InternalPortalMfaRequest, InternalPortalMfaResponse,
};
use axum::extract::rejection::FormRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// Lifetime (seconds) of the portal CSRF seed cookie. Covers login through TOTP input.
const PORTAL_CSRF_TTL_SECS: u64 = 900;
/// Lifetime (seconds) of the `mfa_ticket` cookie. Matches the api-side ticket validity (5 minutes).
const PORTAL_MFA_TTL_SECS: u64 = 300;

/// Portal login form (`GET /{tenant_id}/login`, without `auth_session_id`).
/// `error_key` is the error banner when returning via PRG (CSRF mismatch → `?error=csrf`).
pub async fn login_page(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    error_key: Option<&str>,
) -> Response {
    // External IdP buttons (AP10). Even if they cannot be fetched, password login is shown (fail-soft).
    // Messages is !Send, so finish this before the api await.
    let external_providers = load_external_providers(state, correlation, tenant).await;
    let messages = Messages::new(locale(headers));
    // Pass the CSRF seed (an unguessable random value) to both the cookie and the form (same as admin login).
    // If a valid seed cookie exists, reuse it and extend its TTL. Rotating on every GET would make the form in old tabs
    // always mismatch CSRF when the login screen is opened in multiple tabs (the seed is a session-independent
    // random value, so reusing it does not weaken protection).
    let csrf_id = cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
    )
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let csrf = portal_csrf_token(&csrf_id, state.config.csrf_secret());
    let set_cookies = state.set_cookies().set_local(
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
        &csrf_id,
        PORTAL_CSRF_TTL_SECS,
    );
    (
        set_cookies.into_headers(),
        Html(render(&PortalLogin {
            messages: &messages,
            tenant_prefix: &tenant.prefix(),
            csrf: &csrf,
            error_key,
            external_providers: &external_providers,
        })),
    )
        .into_response()
}

/// Performs portal login (`POST /{tenant_id}/login`, without `auth_session_id`).
pub async fn login(
    state: &WebState,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
    tenant: &WebTenant,
    headers: &HeaderMap,
    form: LoginForm,
) -> Response {
    // CSRF verification (recompute the token from the cookie seed and compare).
    let csrf_id = cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
    );
    let csrf_ok = portal_csrf_valid(
        csrf_id.as_deref(),
        &form.csrf_token,
        state.config.csrf_secret(),
    );
    if !csrf_ok {
        // PRG: switch to GET with 303 and automatically re-show the form with a new seed cookie and token
        //(previously it re-rendered a form with an empty CSRF, so resubmitting could not recover).
        tracing::warn!(
            correlation_id = %correlation.0,
            "portal login failed: csrf token mismatch or seed cookie expired; redirecting to fresh form"
        );
        return see_other(&format!("{}/login?error=csrf", tenant.prefix()));
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let ctx = forwarded_context(headers, correlation, client_ip);
    let request = InternalPortalAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username,
        password: form.password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal authenticate call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(headers));
    match outcome {
        InternalPortalAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            state,
            headers,
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            tenant,
            &[cookies::PORTAL_CSRF_COOKIE],
        ),
        InternalPortalAuthenticateResponse::MfaRequired { mfa_ticket } => {
            // Store `mfa_ticket` in a cookie and go to the TOTP input screen. The portal_csrf cookie is reused by the MFA form.
            let set_cookies = state.set_cookies().set_local(
                &state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE),
                &mfa_ticket,
                PORTAL_MFA_TTL_SECS,
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/login/mfa", tenant.prefix())),
            )
                .into_response()
        }
        InternalPortalAuthenticateResponse::EmailVerificationRequired => message_page(
            &messages,
            "login-error-email-not-verified",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalAuthenticateResponse::PasswordChangeRequired { username } => {
            // Forced password change (ADR-0009 §5). Reuses the same shared screen as the admin console; SSO is not
            // issued yet. Keep the portal_csrf cookie and embed the same csrf in the change form.
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &username,
                None,
            ))
            .into_response()
        }
        InternalPortalAuthenticateResponse::RateLimited => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        InternalPortalAuthenticateResponse::InvalidCredentials => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        InternalPortalAuthenticateResponse::Locked => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalPortalAuthenticateResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                state,
                tenant,
                &ticket,
                &portal_destination(state, headers, tenant),
            )
        }
        // Authentication policy (AP2). The credentials are already verified, so show wording different from a credential error.
        InternalPortalAuthenticateResponse::PolicyDenied => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-policy-denied",
        ),
        InternalPortalAuthenticateResponse::MfaEnrollmentRequired => message_page(
            &messages,
            "login-error-mfa-enrollment-required",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalAuthenticateResponse::Internal => api_internal_error("portal_authenticate"),
    }
}

/// Portal forced password change page (`GET /{tenant_id}/login/password-change`, ADR-0009 §5).
/// Against bookmarks/reloads, direct access is led to the login screen (identity requires the username confirmed via the form
/// transition from `POST /login`, so a GET alone cannot start a change; same as the admin console).
pub async fn password_change_page(Extension(tenant): Extension<WebTenant>) -> Response {
    found(&format!("{}/login", tenant.prefix()))
}

/// Performs the portal forced password change (`POST /{tenant_id}/login/password-change`, ADR-0009 §5).
/// On success issues the SSO cookie and 302s to the account screen (reuses the same shared screen as the admin console).
pub async fn password_change(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForcedPasswordChangeForm>,
) -> Response {
    // CSRF verification (compared with the same portal_csrf seed as at login).
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
    );
    let csrf_ok = portal_csrf_valid(
        csrf_id.as_deref(),
        &form.csrf_token,
        state.config.csrf_secret(),
    );
    if !csrf_ok {
        // PRG: the forced change form can only be started via the form transition from `POST /login` (it carries the username),
        // so 303 back to the login screen to start over (previously it re-rendered a form with an empty CSRF,
        // so resubmitting could not recover).
        tracing::warn!(
            correlation_id = %correlation.0,
            "portal forced password change failed: csrf token mismatch or seed cookie expired; redirecting to login"
        );
        return see_other(&format!("{}/login?error=csrf", tenant.prefix()));
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &form.username,
                Some("password-change-error-mismatch"),
            )),
        )
            .into_response();
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPortalChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal change-password call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalPortalChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            &state,
            &headers,
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            &tenant,
            &[cookies::PORTAL_CSRF_COOKIE],
        ),
        InternalPortalChangePasswordResponse::MfaRequired { mfa_ticket } => {
            // Password changed, MFA required (MFA gate): store `mfa_ticket` in a cookie and go to the TOTP input screen.
            // The portal_csrf cookie is reused by the MFA form (same as login's MfaRequired).
            let set_cookies = state.set_cookies().set_local(
                &state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE),
                &mfa_ticket,
                PORTAL_MFA_TTL_SECS,
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/login/mfa", tenant.prefix())),
            )
                .into_response()
        }
        InternalPortalChangePasswordResponse::EmailVerificationRequired => message_page(
            &messages,
            "login-error-email-not-verified",
            StatusCode::FORBIDDEN,
        ),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalPortalChangePasswordResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &portal_destination(&state, &headers, &tenant),
            )
        }
        InternalPortalChangePasswordResponse::PolicyDenied => message_page(
            &messages,
            "login-error-policy-denied",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalChangePasswordResponse::MfaEnrollmentRequired => message_page(
            &messages,
            "login-error-mfa-enrollment-required",
            StatusCode::FORBIDDEN,
        ),
        InternalPortalChangePasswordResponse::RateLimited => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            &form.username,
            "login-error-rate-limited",
        ),
        InternalPortalChangePasswordResponse::InvalidCredentials => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            &form.username,
            "password-change-error-invalid-current",
        ),
        InternalPortalChangePasswordResponse::Locked => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-locked",
        ),
        InternalPortalChangePasswordResponse::WeakPassword { reason } => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNPROCESSABLE_ENTITY,
            &csrf,
            &form.username,
            super::password_rejection_key(reason, "password-change-error-weak"),
        ),
        InternalPortalChangePasswordResponse::Internal => {
            api_internal_error("portal_change_password")
        }
    }
}

/// Portal TOTP input page (`GET /{tenant_id}/login/mfa`). Requires the `mfa_ticket` cookie.
pub async fn mfa_page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // Without a ticket, start over from login.
    if cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE),
    )
    .is_none()
    {
        return found(&format!("{}/login", tenant.prefix()));
    }
    let messages = Messages::new(locale(&headers));
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
    )
    .unwrap_or_default();
    let csrf = portal_csrf_token(&csrf_id, state.config.csrf_secret());
    Html(render(&PortalMfa {
        messages: &messages,
        tenant_prefix: &tenant.prefix(),
        csrf: &csrf,
        error_key: None,
    }))
    .into_response()
}

/// Portal TOTP verification (`POST /{tenant_id}/login/mfa`).
pub async fn mfa_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PortalTotpForm>,
) -> Response {
    // Note: `Messages` (FluentBundle) is !Send, so it is not held across the api await
    //(created when needed in each branch).

    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::PORTAL_CSRF_COOKIE),
    );
    let csrf_ok = portal_csrf_valid(
        csrf_id.as_deref(),
        &form.csrf_token,
        state.config.csrf_secret(),
    );
    if !csrf_ok {
        tracing::warn!(
            correlation_id = %correlation.0,
            "portal mfa failed: csrf token mismatch or seed cookie expired"
        );
        let Some(id) = csrf_id.as_deref().filter(|s| !s.is_empty()) else {
            // No seed cookie (expired etc.): re-showing the form could not be verified,
            // so start over from login (PRG).
            return see_other(&format!("{}/login?error=csrf", tenant.prefix()));
        };
        // Resubmission from an old form: re-show with a new token derived from the current seed.
        let messages = Messages::new(locale(&headers));
        let csrf = portal_csrf_token(id, state.config.csrf_secret());
        return reshow_mfa(
            &messages,
            &tenant.prefix(),
            StatusCode::BAD_REQUEST,
            &csrf,
            "login-error-csrf-retry",
        );
    }
    let csrf = portal_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let Some(mfa_ticket) = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE),
    ) else {
        return found(&format!("{}/login", tenant.prefix()));
    };

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPortalMfaRequest {
        tenant_id: Some(tenant.0.clone()),
        mfa_ticket,
        totp_code: form.totp_code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_portal_mfa(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal mfa call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // Create Messages after the await (do not let a !Send value live across an await).
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalPortalMfaResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => sso_success_response(
            &state,
            &headers,
            &sso_session_id,
            sso_absolute_ttl_secs,
            user_language.as_deref(),
            &tenant,
            &[cookies::PORTAL_CSRF_COOKIE, cookies::PORTAL_MFA_COOKIE],
        ),
        InternalPortalMfaResponse::InvalidCode => reshow_mfa(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "mfa-error-invalid-code",
        ),
        // Expired ticket / rate limit: start over from login (expire the ticket cookie).
        InternalPortalMfaResponse::TicketExpired | InternalPortalMfaResponse::RateLimited => {
            let set_cookies = state
                .set_cookies()
                .expire_local(&state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE));
            (
                set_cookies.into_headers(),
                found(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalPortalMfaResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &portal_destination(&state, &headers, &tenant),
            )
        }
        // A policy denial expires the ticket and finishes (retrying would not change the result).
        InternalPortalMfaResponse::PolicyDenied => {
            let set_cookies = state
                .set_cookies()
                .expire_local(&state.origin_bound_cookie(cookies::PORTAL_MFA_COOKIE));
            (
                set_cookies.into_headers(),
                message_page(
                    &messages,
                    "login-error-policy-denied",
                    StatusCode::FORBIDDEN,
                ),
            )
                .into_response()
        }
        InternalPortalMfaResponse::Internal => api_internal_error("portal_mfa"),
    }
}

/// End-user logout (`POST /{tenant_id}/logout`, from the account settings form). Revokes SSO in the api,
/// expires the cookies and 302s to the login screen.
///
/// When signed in (SSO cookie present), the form's CSRF token (`console_csrf_token`) is verified; if it does not match,
/// nothing is done (SSO and cookies unchanged) and it returns to the settings screen with `?error=csrf` — preventing forced logout
/// from external pages (task #143; previously protected only by SameSite=Lax). Without an SSO cookie there is nothing
/// to revoke, so it goes to the login screen without checking the token. When the form cannot be read (no Content-Type etc.),
/// it is not a 422 but falls into verification as an empty token.
///
/// Logout from an RP (OIDC end_session_endpoint = `GET /logout`) is received by `rp_logout` and does not come here.
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    form: Result<Form<LogoutForm>, FormRejection>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        let form = form.map(|Form(f)| f).unwrap_or_default();
        if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
            tracing::warn!(
                correlation_id = %correlation.0,
                "logout rejected: csrf token mismatch"
            );
            let suffix = if form.from.as_deref() == Some("admin") {
                "&from=admin"
            } else {
                ""
            };
            return found(&format!("{}/settings?error=csrf{suffix}", tenant.prefix()));
        }
        let _ = state
            .api
            .logout(
                &ctx.correlation_id,
                &assay_contracts::auth::InternalLogoutRequest {
                    tenant_id: Some(tenant.0.clone()),
                    sso_session_id: sso,
                    ip_address: ctx.ip_address,
                    user_agent: ctx.user_agent,
                },
            )
            .await;
    }
    let set_cookies = state
        .set_cookies()
        .expire_session(cookies::SSO_SESSION_COOKIE);
    (
        set_cookies.into_headers(),
        found(&format!("{}/login", tenant.prefix())),
    )
        .into_response()
}

/// Shared processing that issues the SSO cookie, expires any temporary cookies and 302s to the account screen.
/// The SSO cookie is a host-only session cookie (ADR-0018 decision 2; passed to the api via body forwarding).
/// The temporary cookies to expire (CSRF, MFA ticket) are web-local.
///
/// When led to login from SAML SSO (with the `saml_request_id` cookie), it returns to `/saml/continue`
/// instead of the account screen to complete the flow.
fn sso_success_response(
    state: &WebState,
    headers: &HeaderMap,
    sso_session_id: &str,
    sso_absolute_ttl_secs: u64,
    user_language: Option<&str>,
    tenant: &WebTenant,
    expire_cookies: &[&str],
) -> Response {
    let (set_cookies, destination) = sso_success_parts(
        state,
        headers,
        sso_session_id,
        sso_absolute_ttl_secs,
        user_language,
        tenant,
        expire_cookies,
    );
    (set_cookies.into_headers(), found(&destination)).into_response()
}

/// The body of [`sso_success_response`] (building cookies and deciding the destination). Only passkey login
/// responds with JSON (received by browser JS) and cannot return a 302, so it is split out to share the same decision.
pub(crate) fn sso_success_parts(
    state: &WebState,
    headers: &HeaderMap,
    sso_session_id: &str,
    sso_absolute_ttl_secs: u64,
    user_language: Option<&str>,
    tenant: &WebTenant,
    expire_cookies: &[&str],
) -> (crate::cookies::SetCookies, String) {
    let mut set_cookies = state.set_cookies().set_session(
        cookies::SSO_SESSION_COOKIE,
        sso_session_id,
        sso_absolute_ttl_secs,
    );
    // `expire_cookies` receives bare (unprefixed) names and resolves them to origin-bound names here
    // (writing the resolution in each of the 3 callers would leave one deleting by the bare name. SEC5).
    for name in expire_cookies {
        set_cookies = set_cookies.expire_local(&state.origin_bound_cookie(name));
    }
    // If the user has a DB language setting, sync it into the lang cookie (MT20: DB > Cookie).
    if let Some(lang) = user_language.and_then(Locale::from_tag) {
        set_cookies = set_cookies.set_local(
            cookies::LANG_COOKIE,
            lang.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    (set_cookies, portal_destination(state, headers, tenant))
}

/// Destination after portal login (SAML continuation, authenticator app registration confirmation, settings screen).
///
/// Also used to return to the same place after enrollment when device registration (task #916) was inserted.
pub(crate) fn portal_destination(
    state: &WebState,
    headers: &HeaderMap,
    tenant: &WebTenant,
) -> String {
    let enrollment = cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::APP_APPROVER_ENROLLMENT_COOKIE),
    )
    .filter(|id| crate::handlers::app_approval::is_enrollment_id(id));
    if cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE),
    )
    .is_some()
    {
        format!("{}/saml/continue", tenant.prefix())
    } else if let Some(enrollment) = enrollment {
        // Came from the authenticator app registration confirmation (task #892). Return to that screen after login.
        format!(
            "{}/settings/app-approver/confirm?enrollment={enrollment}",
            tenant.prefix()
        )
    } else {
        format!("{}/settings", tenant.prefix())
    }
}

fn render_login_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&PortalLogin {
        messages,
        tenant_prefix,
        csrf,
        error_key,
        // On re-display (credential errors etc.) the external IdP buttons are omitted. This is a synchronous render
        // function that cannot await the api, and distributing the list to every caller for that is not worth it.
        // Users can see the buttons by going back to the login screen once (`GET /login`).
        external_providers: &[],
    })
}

/// Fetches enabled external IdPs (empty on failure; the login screen itself is always shown).
async fn load_external_providers(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
) -> Vec<assay_contracts::auth::ExternalIdpButton> {
    let request = assay_contracts::auth::InternalExternalProvidersRequest {
        tenant_id: Some(tenant.0.clone()),
    };
    match state.api.external_providers(&correlation.0, &request).await {
        Ok(assay_contracts::auth::InternalExternalProvidersResponse::Ok { providers }) => providers,
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::error!(error = %e, "external idp list call to api failed");
            Vec::new()
        }
    }
}

/// Renders the forced password change form HTML from the shared template ([`ForcedPasswordChange`]).
/// Submits to the portal's `POST /{tenant_id}/login/password-change` (the admin console uses a different action).
fn render_password_change_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    username: &str,
    error_key: Option<&str>,
) -> String {
    render(&ForcedPasswordChange {
        messages,
        action: &format!("{tenant_prefix}/login/password-change"),
        csrf,
        username,
        error_key,
    })
}

fn reshow_password_change(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    username: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render_password_change_form(
            messages,
            tenant_prefix,
            csrf,
            username,
            Some(error_key),
        )),
    )
        .into_response()
}

fn reshow_login(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render_login_form(
            messages,
            tenant_prefix,
            csrf,
            Some(error_key),
        )),
    )
        .into_response()
}

fn reshow_mfa(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    csrf: &str,
    error_key: &str,
) -> Response {
    (
        status,
        Html(render(&PortalMfa {
            messages,
            tenant_prefix,
            csrf,
            error_key: Some(error_key),
        })),
    )
        .into_response()
}

fn message_page(messages: &Messages, key: &str, status: StatusCode) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("portal-login-title"),
        message: messages.get(key),
    });
    (status, Html(body)).into_response()
}
