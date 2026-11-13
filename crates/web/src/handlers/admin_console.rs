//! Admin console (web) login, home, logout and forced password change
//! (ADR-0006 §6, ADR-0007 §4, ADR-0009 §5, §6).
//!
//! web only renders screens; authentication, authorization and session revocation are delegated to the api:
//! - Login is the api's `POST /internal/authenticate/admin` (protected by the service token).
//! - Auth state and identity come from the api's `GET /{tenant_id}/admin/whoami` (forwarding the admin's SSO cookie.
//!   `RequirePerms<IdpAdmin>`).
//! - Logout is the api's `POST /internal/logout` (revokes the SSO session).
//! - Forced password change (`must_change_password`. ADR-0009 §5) has no SSO yet, so it re-verifies including
//!   the current password via `POST /internal/authenticate/admin/change-password`.
//!
//! Building cookies (SSO issue/expiry, CSRF seed) is done by web. CSRF is self-contained in web (`crate::csrf`).

use super::{api_internal_error, internal_call_status, locale};
use crate::api_client::{AdminIdentity, AdminSession};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{admin_csrf_token, admin_csrf_valid, console_csrf_token, console_csrf_valid};
use crate::dto::{ForcedPasswordChangeForm, FormPageQuery, LoginForm, LogoutForm};
use crate::error_pages;
use crate::handlers::{form_retry_error_key, forwarded_context, found, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, ConsoleAdmin, ConsoleHome, ConsoleLogin, ForcedPasswordChange, MessagePage,
    SwitchTenant,
};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAccountTenantsRequest, InternalAccountTenantsResponse,
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse, InternalLogoutRequest,
};
use axum::extract::rejection::FormRejection;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use uuid::Uuid;

/// Admin console home (`GET /{tenant_id}/admin`). Forwards SSO to the api to check authorization.
///
/// `?error=csrf` is the banner when returning from a logout (the header's "Log out") whose token did not match
/// (task #143).
pub async fn home(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(context) => context,
        AdminResolution::Reject(resp) => return resp,
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&ConsoleHome {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        error_key: match query.error.as_deref() {
            Some("csrf") => Some("admin-error-csrf"),
            _ => None,
        },
    }))
    .into_response()
}

/// Tenant switch screen (`GET /{tenant_id}/admin/switch-tenant`). Lists the tenants in which the signed-in user has an `ACTIVE`
/// membership and allows moving to the target tenant's admin console. SSO is shared per host,
/// so no re-login is needed (ADR-0009 §8).
pub async fn switch_tenant(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(context) => context,
        AdminResolution::Reject(resp) => return resp,
    };
    // Fetch the list of member tenants from the api (forwarding the SSO cookie). Even if it fails, render the screen with a notice.
    let sso = cookies::get(&headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let (tenants, load_failed) = match state
        .api
        .account_tenants(&InternalAccountTenantsRequest {
            sso_session_id: sso,
        })
        .await
    {
        Ok(InternalAccountTenantsResponse::Ok { tenants }) => (tenants, false),
        Ok(_) => (Vec::new(), false),
        Err(e) => {
            tracing::error!(error = %e, "account tenants list call to api failed");
            (Vec::new(), true)
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&SwitchTenant {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        tenants: &tenants,
        current_tenant_id: &tenant.0,
        load_failed,
    }))
    .into_response()
}

/// Admin login form (`GET /{tenant_id}/admin/login`). If already signed in, 302 to the home.
/// `?error=csrf` shows the error banner when coming back via PRG from a POST with a CSRF mismatch.
pub async fn login_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<FormPageQuery>,
    headers: HeaderMap,
) -> Response {
    // If there is already a valid SSO + permissions, go home.
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        if let AdminSession::Authenticated(_) = state
            .api
            .admin_whoami(&correlation.0, &tenant.0, &sso)
            .await
        {
            return found(&admin_home_path(&tenant));
        }
    }

    let messages = Messages::new(locale(&headers));
    // Pass the CSRF seed (an unguessable random value) to both the cookie and the form. If a valid seed cookie exists,
    // reuse it and extend its TTL (rotating on every GET would make old forms opened in multiple tabs always
    // mismatch CSRF. The seed is a session-independent random value, so reusing it does not weaken protection).
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    )
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let csrf = admin_csrf_token(&csrf_id, state.config.csrf_secret());
    let set_cookies = state.set_cookies().set_local(
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
        &csrf_id,
        3600,
    );
    (
        set_cookies.into_headers(),
        Html(render_login_form(
            &messages,
            &tenant.prefix(),
            &csrf,
            form_retry_error_key(query.error.as_deref()),
        )),
    )
        .into_response()
}

/// Admin login processing (`POST /{tenant_id}/admin/login`). CSRF is verified in web; credentials are delegated to the api.
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // CSRF verification (recompute the token from the cookie seed and compare). FluentBundle is not Send, so create it per branch.
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    );
    let csrf_ok = admin_csrf_valid(
        csrf_id.as_deref(),
        &form.csrf_token,
        state.config.csrf_secret(),
    );
    if !csrf_ok {
        // PRG: switch to GET with 303 and automatically re-show the form with a new seed cookie and token
        //(previously it re-rendered a form with an empty CSRF, so resubmitting could not recover).
        tracing::warn!(
            correlation_id = %correlation.0,
            "admin login failed: csrf token mismatch or seed cookie expired; redirecting to fresh form"
        );
        return see_other(&format!("{}/admin/login?error=csrf", tenant.prefix()));
    }
    let csrf = admin_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAdminAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username,
        password: form.password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_admin(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin internal authenticate call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAdminAuthenticateResponse::Success {
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
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (set_cookies.into_headers(), found(&admin_home_path(&tenant))).into_response()
        }
        InternalAdminAuthenticateResponse::PasswordChangeRequired { username } => {
            // Forced password change (ADR-0009 §5). SSO is not issued yet. Keep the CSRF cookie and
            // embed the same csrf in the change form (it can be verified with the cookie left in the browser).
            Html(render_password_change_form(
                &messages,
                &tenant.prefix(),
                &csrf,
                &username,
                None,
            ))
            .into_response()
        }
        InternalAdminAuthenticateResponse::RateLimited => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        InternalAdminAuthenticateResponse::InvalidCredentials => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        InternalAdminAuthenticateResponse::Locked => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        InternalAdminAuthenticateResponse::Forbidden => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-forbidden",
        ),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalAdminAuthenticateResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &admin_home_path(&tenant),
            )
        }
        // Authentication policy (AP2). The credentials are already verified, so show wording different from a credential error.
        InternalAdminAuthenticateResponse::PolicyDenied => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-policy-denied",
        ),
        InternalAdminAuthenticateResponse::MfaEnrollmentRequired => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-mfa-enrollment-required",
        ),
        InternalAdminAuthenticateResponse::MfaRequired => reshow_login(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-mfa-required",
        ),
        InternalAdminAuthenticateResponse::Internal => api_internal_error("admin_authenticate"),
    }
}

/// Forced password change page (`GET /{tenant_id}/admin/password-change`). Against bookmarks/reloads,
/// direct access is led to the login screen (identity requires the username (login identifier) confirmed via
/// the form transition from `POST /admin/login`, so a GET alone cannot start a change).
pub async fn password_change_page(Extension(tenant): Extension<WebTenant>) -> Response {
    found(&format!("{}/admin/login", tenant.prefix()))
}

/// Performs the forced password change (`POST /{tenant_id}/admin/password-change`, ADR-0009 §5).
pub async fn password_change(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForcedPasswordChangeForm>,
) -> Response {
    let csrf_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE),
    );
    let csrf_ok = admin_csrf_valid(
        csrf_id.as_deref(),
        &form.csrf_token,
        state.config.csrf_secret(),
    );
    if !csrf_ok {
        // PRG: the forced change form can only be started via the form transition from `POST /admin/login`
        //(it carries the username), so 303 back to the login screen to start over.
        tracing::warn!(
            correlation_id = %correlation.0,
            "admin forced password change failed: csrf token mismatch or seed cookie expired; redirecting to login"
        );
        return see_other(&format!("{}/admin/login?error=csrf", tenant.prefix()));
    }
    let csrf = admin_csrf_token(&csrf_id.unwrap_or_default(), state.config.csrf_secret());

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
    let request = InternalAdminChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        username: form.username.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .admin_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin change-password call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAdminChangePasswordResponse::Success {
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
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (set_cookies.into_headers(), found(&admin_home_path(&tenant))).into_response()
        }
        InternalAdminChangePasswordResponse::RateLimited => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            &form.username,
            "login-error-rate-limited",
        ),
        InternalAdminChangePasswordResponse::InvalidCredentials => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            &csrf,
            &form.username,
            "password-change-error-invalid-current",
        ),
        InternalAdminChangePasswordResponse::Locked => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-locked",
        ),
        InternalAdminChangePasswordResponse::Forbidden => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "admin-login-error-forbidden",
        ),
        InternalAdminChangePasswordResponse::WeakPassword { reason } => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::UNPROCESSABLE_ENTITY,
            &csrf,
            &form.username,
            super::password_rejection_key(reason, "password-change-error-weak"),
        ),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalAdminChangePasswordResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &admin_home_path(&tenant),
            )
        }
        InternalAdminChangePasswordResponse::PolicyDenied => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-policy-denied",
        ),
        InternalAdminChangePasswordResponse::MfaEnrollmentRequired => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "login-error-mfa-enrollment-required",
        ),
        InternalAdminChangePasswordResponse::MfaRequired => reshow_password_change(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            &csrf,
            &form.username,
            "admin-login-error-mfa-required",
        ),
        InternalAdminChangePasswordResponse::Internal => {
            api_internal_error("admin_change_password")
        }
    }
}

/// Logout (`POST /{tenant_id}/admin/logout`, from the form in the shared layout's header). Revokes SSO in the api,
/// expires the cookies and 302s to login.
///
/// When signed in (SSO cookie present), the form's CSRF token (`console_csrf_token`) is verified; if it does not match,
/// nothing is done (SSO and cookies unchanged) and it returns home with `?error=csrf` — preventing forced logout from
/// external pages (task #143; previously protected only by SameSite=Lax). Without an SSO cookie there is nothing
/// to revoke, so it goes to login without checking the token. When the form cannot be read (no Content-Type etc.),
/// it is not a 422 but falls into verification as an empty token.
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
        let submitted = form.map(|Form(f)| f.csrf_token).unwrap_or_default();
        if !console_csrf_valid(&sso, &submitted, state.config.csrf_secret()) {
            tracing::warn!(
                correlation_id = %correlation.0,
                "admin logout rejected: csrf token mismatch"
            );
            return found(&format!("{}?error=csrf", admin_home_path(&tenant)));
        }
        let _ = state
            .api
            .logout(
                &ctx.correlation_id,
                &InternalLogoutRequest {
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
    (set_cookies.into_headers(), redirect_to_login(&tenant)).into_response()
}

/// Result of resolving an authorized admin. `Reject` holds a finished redirect/error Response.
pub(crate) enum AdminResolution {
    Ok(AdminContext),
    Reject(Response),
}

/// Context of the authorized admin and the tenant being operated. Each console screen carries it for rendering the header
/// (the owned version of `ConsoleAdmin`; passed to templates as a borrow via [`Self::chrome`]).
pub(crate) struct AdminContext {
    identity: AdminIdentity,
    /// CSRF token for post-login state-changing forms (`console_csrf_token`, derived from the SSO session id).
    /// Used by the shared layout's header (saving the language. task #79).
    csrf_token: String,
}

impl AdminContext {
    /// Context for screen rendering tests. At runtime it is always built from the api's whoami response.
    #[cfg(test)]
    pub(crate) fn for_test(label: &str, tenant_name: Option<&str>) -> Self {
        Self {
            identity: AdminIdentity::for_test(label, tenant_name),
            csrf_token: "test-console-csrf".to_string(),
        }
    }

    /// Context passed to the shared layout's header (admin label + tenant display name).
    pub(crate) fn chrome(&self) -> ConsoleAdmin<'_> {
        ConsoleAdmin {
            label: &self.identity.label,
            tenant_name: self.identity.tenant_name.as_deref(),
            permissions: self.identity.permissions(),
            csrf_token: &self.csrf_token,
        }
    }
}

/// Forwards the SSO cookie to the api to resolve the admin (unauthenticated → lead to login, insufficient permissions → 403 HTML).
/// Each admin console screen is protected by this (equivalent to the api's `AdminHtmlSession`).
pub(crate) async fn resolve_admin(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
) -> AdminResolution {
    let sso = cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let session = state
        .api
        .admin_whoami(&correlation.0, &tenant.0, &sso)
        .await;
    let csrf_token = console_csrf_token(&sso, state.config.csrf_secret());
    admin_resolution(session, csrf_token, tenant, headers)
}

/// Mapping whoami results → screen responses (separated from the api call for testability).
///
/// When the tenant cannot be resolved (`NotFound`), returns the 404 page. Mapping it to 502 like `Error` would make
/// a nonexistent tenant's URL look like a gateway failure (misleading diagnosis).
fn admin_resolution(
    session: AdminSession,
    csrf_token: String,
    tenant: &WebTenant,
    headers: &HeaderMap,
) -> AdminResolution {
    match session {
        AdminSession::Authenticated(identity) => AdminResolution::Ok(AdminContext {
            identity,
            csrf_token,
        }),
        AdminSession::Unauthenticated => AdminResolution::Reject(redirect_to_login(tenant)),
        AdminSession::Forbidden => AdminResolution::Reject(forbidden_response(headers)),
        AdminSession::NotFound => {
            AdminResolution::Reject(error_pages::page(StatusCode::NOT_FOUND, headers, None))
        }
        AdminSession::Error => {
            AdminResolution::Reject((StatusCode::BAD_GATEWAY, Html(String::new())).into_response())
        }
    }
}

/// Admin console home path (`/{tenant_id}/admin`).
pub(crate) fn admin_home_path(tenant: &WebTenant) -> String {
    format!("{}/admin", tenant.prefix())
}

/// 302 redirect to the login screen.
pub(crate) fn redirect_to_login(tenant: &WebTenant) -> Response {
    found(&format!("{}/admin/login", tenant.prefix()))
}

/// Minimal HTML page (403) conveying insufficient permissions. Reused by each admin console screen.
pub(crate) fn forbidden_response(headers: &HeaderMap) -> Response {
    let messages = Messages::new(locale(headers));
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("admin-forbidden-title"),
        message: messages.get("admin-forbidden-message"),
    });
    (StatusCode::FORBIDDEN, Html(body)).into_response()
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

/// Renders the admin login form HTML from the template (embedded values are auto-escaped).
fn render_login_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&ConsoleLogin {
        messages,
        tenant_prefix,
        csrf,
        error_key,
    })
}

/// Renders the forced password change form HTML from the shared template ([`ForcedPasswordChange`]).
/// Submits to the admin console's `POST /{tenant_id}/admin/password-change` (the portal has a separate handler and action).
fn render_password_change_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    username: &str,
    error_key: Option<&str>,
) -> String {
    render(&ForcedPasswordChange {
        messages,
        action: &format!("{tenant_prefix}/admin/password-change"),
        csrf,
        username,
        error_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    #[test]
    fn login_form_has_csrf_and_credential_fields() {
        let messages = Messages::new(Locale::Ja);
        let tenant_prefix = "/00000000-0000-7000-8000-000000000000";
        let html = render_login_form(&messages, tenant_prefix, "deadbeef", None);
        assert!(html.contains("name=\"csrf_token\" value=\"deadbeef\""));
        assert!(html.contains("name=\"username\""));
        assert!(html.contains("name=\"password\""));
        // No error, so no banner. Do not look at `role="alert"` alone — the passkey error field
        // is always in the DOM while hidden (same construction as the user login screen).
        assert!(!html.contains("alert alert-warning"));
        // Self-recovery path for admins who forgot their password (same path as the user login screen).
        assert!(html.contains(&format!("href=\"{tenant_prefix}/forgot-password\"")));
    }

    #[test]
    fn home_lists_sections_and_logout_for_signed_in_admin() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000000",
            error_key: None,
            admin: Some(crate::templates::ConsoleAdmin {
                label: "user-123",
                tenant_name: Some("ROOT"),
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
        });
        assert!(html.contains("user-123"));
        assert!(html.contains("ROOT"));
        assert!(html.contains("action=\"/00000000-0000-7000-8000-000000000000/admin/logout\""));
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin/clients"));
    }

    /// The header's language dropdown **POSTs to the save endpoint with a CSRF token when signed in**,
    /// and stays a temporary-switch GET when not signed in (task #79). As a GET it would not be saved, and while signed in
    /// the user setting beats the cookie, so the next screen would revert to the original language.
    #[test]
    fn the_header_language_switch_posts_with_a_token_only_when_signed_in() {
        let messages = Messages::new(Locale::Ja);
        let tenant = "/00000000-0000-7000-8000-000000000000";
        let signed_in = render(&ConsoleHome {
            messages: &messages,
            tenant,
            error_key: None,
            admin: Some(crate::templates::ConsoleAdmin {
                label: "user-123",
                tenant_name: Some("ROOT"),
                permissions: &[],
                csrf_token: "header-csrf-token",
            }),
        });
        assert!(
            signed_in.contains(&format!(
                r#"<form method="post" action="{tenant}/settings/display" class="dropdown">"#
            )),
            "{signed_in}"
        );
        assert!(
            signed_in
                .contains(r#"<input type="hidden" name="csrf_token" value="header-csrf-token">"#),
            "{signed_in}"
        );
        assert!(signed_in.contains("data-return-to-current"), "{signed_in}");
        assert!(!signed_in.contains(r#"<form method="get""#), "{signed_in}");

        let signed_out = render(&ConsoleHome {
            messages: &messages,
            tenant,
            error_key: None,
            admin: None,
        });
        assert!(
            signed_out.contains(r#"<form method="get" class="dropdown">"#),
            "{signed_out}"
        );
        assert!(!signed_out.contains("/settings/display"), "{signed_out}");
    }

    fn reject_status(session: AdminSession) -> StatusCode {
        let tenant = WebTenant("019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string());
        match admin_resolution(session, String::new(), &tenant, &HeaderMap::new()) {
            AdminResolution::Ok(_) => panic!("expected a rejection"),
            AdminResolution::Reject(response) => response.status(),
        }
    }

    /// When the api cannot resolve the tenant (404), the 404 page is returned. Regression test because mapping it to 502
    /// (gateway failure) makes a nonexistent tenant's URL look like a failure and misleads diagnosis.
    #[test]
    fn unknown_tenant_is_rejected_as_not_found_not_bad_gateway() {
        assert_eq!(reject_status(AdminSession::NotFound), StatusCode::NOT_FOUND);
    }

    /// Other branches are as before (unauthenticated → 302 to login, insufficient permissions → 403, api failure → 502).
    #[test]
    fn other_sessions_keep_their_responses() {
        assert_eq!(
            reject_status(AdminSession::Unauthenticated),
            StatusCode::FOUND
        );
        assert_eq!(
            reject_status(AdminSession::Forbidden),
            StatusCode::FORBIDDEN
        );
        assert_eq!(reject_status(AdminSession::Error), StatusCode::BAD_GATEWAY);
    }
}
