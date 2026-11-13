//! Handlers for each endpoint.

pub mod account_setup;
pub mod admin;
pub mod admin_accounts;
pub mod admin_application_logs;
pub mod admin_applications;
pub mod admin_audit;
pub mod admin_authentication_policies;
pub mod admin_client_permissions;
pub mod admin_clients;
pub mod admin_external_idps;
pub mod admin_invitations;
pub mod admin_login_identifiers;
pub mod admin_members;
pub mod admin_permissions;
pub mod admin_resources;
pub mod admin_restart;
pub mod admin_saml_service_providers;
pub mod admin_signing_keys;
pub mod admin_ssh_keys;
pub mod admin_system_settings;
pub mod admin_tenant_settings;
pub mod admin_tenant_smtp;
pub mod admin_tenants;
pub mod admin_users;
pub mod app_approver;
pub mod authorize;
pub mod consent;
pub mod discovery;
pub mod health;
pub mod internal_admin_token;
pub mod internal_app_approval;
pub mod internal_auth;
pub mod internal_device_enrollment;
pub mod internal_devices;
pub mod internal_runtime_settings;
pub mod internal_security_status;
pub mod internal_session_keys;
pub mod internal_sign_in_history;
pub mod internal_ssh_keys;
pub mod introspect;
pub mod invitations;
pub mod logout;
pub mod mfa;
pub mod passkey;
pub mod register;
pub mod revoke;
pub mod saml_sso;
pub mod token;
pub mod userinfo;

use crate::application::admin_account_guard::AdminAccountGuardError;
use crate::application::audit::RequestContext;
use crate::application::permission_management::PermissionManagementError;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use axum::http::header::{HeaderValue, LOCATION, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// `302 Found` redirect (design spec §4.2; axum's `Redirect::to` is 303, so it is not used).
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Builds the audit context from request headers.
///
/// Only when `trust_forwarded` is `true` is `X-Forwarded-For` trusted to take the real IP.
/// When `false`, forwarded headers are ignored (against header spoofing; S1).
/// Getting the peer socket IP directly needs the `ConnectInfo` extractor, so here
/// `ip_address = None` when trust is disabled (no IP is recorded in the audit log).
pub(crate) fn request_context(
    headers: &HeaderMap,
    correlation: &CorrelationId,
    trust_forwarded: bool,
) -> RequestContext {
    let ip_address = if trust_forwarded {
        // Take the **rightmost** value (the peer appended by the trusted proxy). The first may be what the client
        // claimed, so looking there lets spoofing straight through (SEC1; the derivation is shared with web).
        assay_contracts::forwarded::client_ip(
            headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok()),
        )
    } else {
        None
    };
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    RequestContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}

/// Converts `AdminAccountGuardError` to `ApiError` (shared by the account operation and permission grant endpoints, task #579).
pub(crate) fn map_admin_account_guard_error(
    e: AdminAccountGuardError,
    locale: ApiLocale,
) -> ApiError {
    match e {
        AdminAccountGuardError::Forbidden => {
            ApiError::Forbidden(ApiMessages::new(locale).get("api-admin-account-protected"))
        }
        AdminAccountGuardError::Internal(m) => ApiError::Internal(m),
    }
}

/// Converts `PermissionManagementError` to `ApiError` (shared by `admin_permissions` and `admin_users`).
pub(crate) fn map_permission_management_error(
    e: PermissionManagementError,
    locale: ApiLocale,
) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        PermissionManagementError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        PermissionManagementError::NotFound => ApiError::NotFound(msgs.get("api-user-not-found")),
        PermissionManagementError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        PermissionManagementError::Internal(m) => ApiError::Internal(m),
    }
}
