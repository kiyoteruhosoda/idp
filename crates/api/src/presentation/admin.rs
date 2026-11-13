//! Authorization extractors for admin features (ADR-0006 §5 / ADR-0037, CLAUDE.md "権限管理").
//!
//! Placing `RequirePerms<P>` in handler arguments validates the **admin access token** (`Authorization: Bearer`)
//! and checks that it satisfies the **permission code** represented by the type parameter `P`. The decision itself is made by
//! the application layer ([`ManagementTokenService`]); this extractor only maps the result to HTTP (Presentation only
//! receives allow/deny).
//!
//! Permission codes are specified as types (markers), not strings. Following CLAUDE.md "動的呼び出しの制限",
//! passing permissions as strings resolved at runtime is avoided and they are fixed at compile time. The mapping between
//! markers and strings is written once by this module's [`permission_markers!`].
//!
//! ## Credentials are tokens only (ADR-0037)
//!
//! Previously the SSO session cookie forwarded by web was the credential. Cookies are ambient (the browser
//! attaches them automatically), so the api also needed origin validation (CSRF protection), but Bearer is not ambient,
//! so **the CSRF concern disappears from the admin surface altogether**. The admin console (web) exchanges the SSO session
//! for an admin token via `POST /internal/admin/token` before calling the api. CSRF on the browser path is
//! handled and closed by web with synchronizer tokens (`assay_web::csrf`).
//!
//! Flows that require no permission, only "being signed in" (accepting an invitation, ADR-0009 §3), use
//! the [`AuthenticatedUser`] extractor. It reads the browser cookie directly, so
//! origin validation is kept as before.
//!
//! ```ignore
//! async fn admin_api(RequirePerms(admin, _): RequirePerms<UsersRead>) -> impl IntoResponse { ... }
//! ```

use crate::application::management_token::{AuthorizedPrincipal, ManagementAccess};
use crate::domain::permission;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::origin;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::marker::PhantomData;

/// Marker representing, as a type, the permission code required by a protected target.
///
/// To protect with a new permission, add a marker type (the single source of allowed values is the `permissions`
/// master table, and of implications `domain::permission`. Here the codes "used for protection"
/// among them are bundled as types).
pub trait RequiredPermission {
    const CODE: &'static str;
}

/// Defines the permission code marker types together.
///
/// It is a macro so that the mapping between marker types and permission code strings is listed **one per line**.
/// Hand-writing a `struct` and `impl` per type would scatter the table over 20+ declarations,
/// losing the overview of "which type is which code".
macro_rules! permission_markers {
    ($($(#[$doc:meta])* $name:ident => $code:path;)*) => {
        $(
            $(#[$doc])*
            pub struct $name;
            impl RequiredPermission for $name {
                const CODE: &'static str = $code;
            }
        )*
    };
}

permission_markers! {
    /// The whole admin console (tenant admin, ADR-0009 §4). Implies all fine-grained tenant management codes
    /// (`TENANT_MANAGEMENT_CODES`). ⚠ Does not imply `idp.smtp:*`.
    IdpAdmin => permission::TENANT_ADMIN;
    /// System administration (scope = root only). Creating/deleting tenants, system settings, restart,
    /// cross-tenant log viewing. **Not split into fine-grained codes** (ADR-0037).
    IdpSystemAdmin => permission::SYSTEM_ADMIN;

    /// Viewing and searching users.
    UsersRead => permission::USERS_READ;
    /// Creating/updating/deleting users, reissuing passwords, resetting MFA, unlocking, login identifiers.
    UsersWrite => permission::USERS_WRITE;
    /// Viewing apps (ADR-0054), including binding and assignment lists.
    ApplicationsRead => permission::APPLICATIONS_READ;
    /// Registering/updating/deleting apps, adding and removing bindings, assigning and unassigning users.
    ApplicationsWrite => permission::APPLICATIONS_WRITE;
    /// Viewing clients (RPs).
    ClientsRead => permission::CLIENTS_READ;
    /// Creating/updating/deleting clients (RPs), reissuing secrets, granting permissions.
    ClientsWrite => permission::CLIENTS_WRITE;
    /// Viewing tenant members.
    MembersRead => permission::MEMBERS_READ;
    /// Inviting, suspending and removing members.
    MembersWrite => permission::MEMBERS_WRITE;
    /// Viewing protected resources (audience names put in `aud`) and who they are lent to (ADR-0042).
    ResourcesRead => permission::RESOURCES_READ;
    /// Registering, disabling and deleting audiences, and lending them to / revoking them from clients (ADR-0042).
    ResourcesWrite => permission::RESOURCES_WRITE;
    /// Viewing permission grants.
    PermissionsRead => permission::PERMISSIONS_READ;
    /// Granting and revoking permissions.
    PermissionsWrite => permission::PERMISSIONS_WRITE;
    /// Viewing audit logs.
    AuditRead => permission::AUDIT_READ;
    /// Viewing signing keys.
    KeysRead => permission::KEYS_READ;
    /// Generating, retiring and deleting signing keys.
    KeysWrite => permission::KEYS_WRITE;
    /// Viewing the requesting tenant's own settings.
    TenantSettingsRead => permission::TENANT_SETTINGS_READ;
    /// Changing the requesting tenant's own settings.
    TenantSettingsWrite => permission::TENANT_SETTINGS_WRITE;
    /// Viewing authentication policies.
    AuthenticationPoliciesRead => permission::AUTHENTICATION_POLICIES_READ;
    /// Creating/updating/deleting authentication policies.
    AuthenticationPoliciesWrite => permission::AUTHENTICATION_POLICIES_WRITE;
    /// Viewing external IdP settings.
    ExternalIdpsRead => permission::EXTERNAL_IDPS_READ;
    /// Registering/updating/deleting external IdP settings.
    ExternalIdpsWrite => permission::EXTERNAL_IDPS_WRITE;
    /// Viewing SAML SPs.
    SamlServiceProvidersRead => permission::SAML_SERVICE_PROVIDERS_READ;
    /// Registering/updating/deleting SAML SPs.
    SamlServiceProvidersWrite => permission::SAML_SERVICE_PROVIDERS_WRITE;
    /// List of the organization's SSH keys (task #885). ⚠ The endpoint only lets machine clients through (`admin_ssh_keys`).
    SshKeysRead => permission::SSH_KEYS_READ;
    /// Viewing mail sending (SMTP) settings (ADR-0051, ADR-0058 §8). Grantable in any tenant; reaches only
    /// the route of the scope's tenant (the global route's endpoint imposes root on the using side). ⚠ Not implied by `idp.tenant.admin`.
    SmtpRead => permission::SMTP_READ;
    /// Changing mail sending (SMTP) settings (ADR-0051, ADR-0058 §8). Same range as `SmtpRead`.
    SmtpWrite => permission::SMTP_WRITE;
}

/// Extractor representing an authorized admin principal satisfying permission `P`.
///
/// Once extraction succeeds, "presented a valid admin token, the principal is still active, satisfies `P::CODE`" is
/// guaranteed. On rejection it returns JSON 401/403 (redirecting screens to login is web's job, ADR-0007).
pub struct RequirePerms<P: RequiredPermission>(pub AuthorizedPrincipal, pub PhantomData<P>);

impl<P> FromRequestParts<AppState> for RequirePerms<P>
where
    P: RequiredPermission,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // The requested tenant is the path-derived `ResolvedTenant` (injected by the `resolve_tenant` middleware, ADR-0009 §7).
        // The token's `iss` and `aud` must exactly match this tenant's values (rejects other tenants' tokens).
        // Not having passed the middleware is a wiring bug.
        let Some(resolved) = parts.extensions.get::<ResolvedTenant>() else {
            tracing::error!("RequirePerms used on a route without the tenant resolver middleware");
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "tenant context missing",
            ));
        };
        let token = bearer_token(parts);
        match state
            .management_tokens
            .authorize(resolved.context(), token.as_deref(), P::CODE)
            .await
        {
            ManagementAccess::Granted(principal)
                if opens_in_tenant(P::CODE, resolved.tenant().is_root()) =>
            {
                Ok(RequirePerms(principal, PhantomData))
            }
            ManagementAccess::Unauthenticated => Err(unauthorized(parts)),
            ManagementAccess::Granted(_) | ManagementAccess::Forbidden => Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                &messages(parts).get("api-permission-insufficient"),
            )),
        }
    }
}

/// `idp.system.admin` endpoints open only in the root tenant.
///
/// That holders exist only in root is also enforced by a DB constraint (`user_permissions_system_admin_scope_chk`),
/// but we don't rely on that alone (task #762).
fn opens_in_tenant(code: &str, tenant_is_root: bool) -> bool {
    code != permission::SYSTEM_ADMIN || tenant_is_root
}

/// Extractor representing a principal that presented a valid admin token (**regardless of permission codes**) (ADR-0059).
///
/// Placed on endpoints whose authorization depends on the principal itself rather than permission codes (the roster's self: which
/// app the calling service account claims to be). ⚠ **Extraction alone permits nothing** -- the handler (and the
/// application layer behind it) looks at the principal and decides 403. The only rejection is 401 for an invalid token.
pub struct ManagementPrincipal(pub AuthorizedPrincipal);

impl FromRequestParts<AppState> for ManagementPrincipal {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(resolved) = parts.extensions.get::<ResolvedTenant>() else {
            tracing::error!(
                "ManagementPrincipal used on a route without the tenant resolver middleware"
            );
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "tenant context missing",
            ));
        };
        let token = bearer_token(parts);
        match state
            .management_tokens
            .authenticate(resolved.context(), token.as_deref())
            .await
        {
            ManagementAccess::Granted(principal) => Ok(ManagementPrincipal(principal)),
            ManagementAccess::Unauthenticated | ManagementAccess::Forbidden => {
                Err(unauthorized(parts))
            }
        }
    }
}

/// Extracts `Authorization: Bearer <token>` (scheme name is case-insensitive, RFC 6750 §2.1).
fn bearer_token(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("Bearer")
        .then(|| value.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Extractor representing a signed-in user (regardless of permissions).
///
/// Once the user is resolved from the SSO session cookie, "has a valid SSO session, account is active" is
/// guaranteed. Used in flows that require no tenant permission (accepting an invitation, ADR-0009 §3). 401 if extraction fails.
///
/// Unlike the admin API, the cookie is used directly as the credential, so origin validation (SEC4) is kept.
pub struct AuthenticatedUser(pub uuid::Uuid);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if !origin::is_allowed(parts, &state.config) {
            return Err(forbidden_origin(parts));
        }
        let sso_session_id = crate::presentation::cookies::get(
            &parts.headers,
            crate::presentation::cookies::SSO_SESSION_COOKIE,
        );
        match state
            .admin_access
            .authenticated_user(sso_session_id.as_deref())
            .await
        {
            Some(user_id) => Ok(AuthenticatedUser(user_id)),
            None => Err(unauthorized(parts)),
        }
    }
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({ "error": code, "message": message }))).into_response()
}

/// 401 (with `WWW-Authenticate` per RFC 6750 §3; the admin API's only credential is Bearer).
fn unauthorized(parts: &Parts) -> Response {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        &messages(parts).get("api-authentication-required"),
    );
    response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer"),
    );
    response
}

/// Cookie-authenticated state-changing request from a disallowed origin (SEC4). Rejected with 403 without revealing authorization.
fn forbidden_origin(parts: &Parts) -> Response {
    tracing::warn!(
        method = %parts.method,
        path = %parts.uri.path(),
        "rejected cookie-authenticated request from a disallowed origin"
    );
    error_response(
        StatusCode::FORBIDDEN,
        "forbidden",
        &messages(parts).get("api-origin-not-allowed"),
    )
}

/// Translation dictionary following the request's `Accept-Language` (MT19). The extractor's rejection responses (401 / 403)
/// are also messages users see, so they are returned in the same language as errors inside handlers.
fn messages(parts: &Parts) -> ApiMessages {
    let header = parts
        .headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    ApiMessages::new(ApiLocale::from_accept_language(header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts_with(header: Option<&str>) -> Parts {
        let mut builder = Request::builder().uri("/t/admin/users");
        if let Some(value) = header {
            builder = builder.header(AUTHORIZATION, value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn reads_the_bearer_scheme_case_insensitively() {
        assert_eq!(
            bearer_token(&parts_with(Some("Bearer abc.def.ghi"))).as_deref(),
            Some("abc.def.ghi")
        );
        // The scheme in RFC 6750 §2.1 is case-insensitive.
        assert_eq!(
            bearer_token(&parts_with(Some("bearer abc"))).as_deref(),
            Some("abc")
        );
        assert_eq!(
            bearer_token(&parts_with(Some("BEARER abc"))).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_bearer_token() {
        // Other schemes are not read (accepting Basic here would mix client authentication with admin authorization).
        assert_eq!(bearer_token(&parts_with(Some("Basic abc"))), None);
        assert_eq!(bearer_token(&parts_with(None)), None);
        // A scheme alone or an empty value is not treated as a credential (`Some("")` does not take the 401 branch).
        assert_eq!(bearer_token(&parts_with(Some("Bearer"))), None);
        assert_eq!(bearer_token(&parts_with(Some("Bearer "))), None);
        assert_eq!(bearer_token(&parts_with(Some("Bearer    "))), None);
    }

    /// The mapping between marker types and permission codes matches the constants in `domain::permission`.
    #[test]
    fn markers_map_to_the_permission_codes_they_are_named_after() {
        assert_eq!(IdpAdmin::CODE, "idp.tenant.admin");
        assert_eq!(IdpSystemAdmin::CODE, "idp.system.admin");
        assert!(opens_in_tenant(IdpSystemAdmin::CODE, true));
        assert!(!opens_in_tenant(IdpSystemAdmin::CODE, false));
        assert!(opens_in_tenant(permission::USERS_READ, false));
        assert_eq!(UsersRead::CODE, "idp.users:read");
        assert_eq!(UsersWrite::CODE, "idp.users:write");
        assert_eq!(AuditRead::CODE, "idp.audit:read");
        assert_eq!(
            SamlServiceProvidersWrite::CODE,
            "idp.saml-service-providers:write"
        );
    }
}
