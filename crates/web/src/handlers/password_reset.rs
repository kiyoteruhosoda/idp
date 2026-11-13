//! Self-service password reset screens (web. MT18).
//!
//! - `GET/POST /{tenant_id}/forgot-password`: enter an email address to request a reset.
//!   The response is the same completion view whether or not the account exists (preventing enumeration
//!   is the api / Application layer's job; web just mirrors its response).
//! - `GET/POST /{tenant_id}/password-reset?token=...`: opened from the reset email link to
//!   set a new password. On success it leads to the login screen.
//!
//! Both are unauthenticated paths (no SSO). The forms have no session, so no CSRF token is
//! attached (the request only sends an email, and execution relies on token possession as identity; a third
//! party forcing it gains no state change). The actual work is delegated to the api's `/internal/password-reset/*`.

use super::internal_call_status;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ForgotPassword, PasswordReset};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
    InternalPasswordResetRequestRequest, InternalPasswordResetRequestResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ForgotForm {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetForm {
    pub token: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// Reset request form (`GET /{tenant_id}/forgot-password`).
pub async fn forgot_page(headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    Html(render(&ForgotPassword {
        messages: &messages,
        accepted: false,
        error_key: None,
    }))
    .into_response()
}

/// Submits a reset request (`POST /{tenant_id}/forgot-password`).
pub async fn forgot_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForgotForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPasswordResetRequestRequest {
        tenant_id: Some(tenant.0.clone()),
        email: form.email,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let result = state
        .api
        .password_reset_request(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(InternalPasswordResetRequestResponse::Accepted) => Html(render(&ForgotPassword {
            messages: &messages,
            accepted: true,
            error_key: None,
        }))
        .into_response(),
        Ok(InternalPasswordResetRequestResponse::Unavailable) => forgot_error(
            &messages,
            "forgot-password-error-unavailable",
            StatusCode::OK,
        ),
        Ok(InternalPasswordResetRequestResponse::RateLimited) => forgot_error(
            &messages,
            "forgot-password-error-rate-limited",
            StatusCode::TOO_MANY_REQUESTS,
        ),
        Err(e) => {
            tracing::error!(error = %e, "password reset request call to api failed");
            match internal_call_status(&e) {
                // If the tenant cannot be resolved, this screen itself does not exist. Instead of re-rendering
                // the form, fall back to the shared 404 page (MT28).
                StatusCode::NOT_FOUND => StatusCode::NOT_FOUND.into_response(),
                status => forgot_error(&messages, "admin-error-internal", status),
            }
        }
    }
}

/// New password form (`GET /{tenant_id}/password-reset?token=...`).
pub async fn reset_page(
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ResetQuery>,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return reset_view(
            &messages,
            &tenant,
            false,
            "",
            false,
            Some("password-reset-error-missing-token"),
            StatusCode::BAD_REQUEST,
        );
    }
    reset_view(
        &messages,
        &tenant,
        true,
        &token,
        false,
        None,
        StatusCode::OK,
    )
}

/// Performs the reset (`POST /{tenant_id}/password-reset`).
pub async fn reset_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some("password-reset-error-mismatch"),
            StatusCode::BAD_REQUEST,
        );
    }
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPasswordResetCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: form.token.clone(),
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let result = state
        .api
        .password_reset_complete(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(InternalPasswordResetCompleteResponse::Ok) => {
            reset_view(&messages, &tenant, false, "", true, None, StatusCode::OK)
        }
        Ok(InternalPasswordResetCompleteResponse::InvalidOrExpired) => reset_view(
            &messages,
            &tenant,
            false,
            "",
            false,
            Some("password-reset-error-invalid"),
            StatusCode::BAD_REQUEST,
        ),
        Ok(InternalPasswordResetCompleteResponse::WeakPassword { reason }) => reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some(super::password_rejection_key(
                reason,
                "password-reset-error-weak",
            )),
            StatusCode::BAD_REQUEST,
        ),
        Ok(InternalPasswordResetCompleteResponse::Internal) => reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some("admin-error-internal"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        Err(e) => {
            tracing::error!(error = %e, "password reset complete call to api failed");
            match internal_call_status(&e) {
                // Same as above (MT28).
                StatusCode::NOT_FOUND => StatusCode::NOT_FOUND.into_response(),
                status => reset_view(
                    &messages,
                    &tenant,
                    true,
                    &form.token,
                    false,
                    Some("admin-error-internal"),
                    status,
                ),
            }
        }
    }
}

fn forgot_error(messages: &Messages, error_key: &str, status: StatusCode) -> Response {
    (
        status,
        Html(render(&ForgotPassword {
            messages,
            accepted: false,
            error_key: Some(error_key),
        })),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
fn reset_view(
    messages: &Messages,
    tenant: &WebTenant,
    show_form: bool,
    token: &str,
    success: bool,
    error_key: Option<&str>,
    status: StatusCode,
) -> Response {
    (
        status,
        Html(render(&PasswordReset {
            messages,
            tenant_prefix: &tenant.prefix(),
            show_form,
            token,
            success,
            error_key,
        })),
    )
        .into_response()
}

fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = cookies::get(headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Locale::resolve(None, None, cookie_lang.as_deref(), accept)
}
