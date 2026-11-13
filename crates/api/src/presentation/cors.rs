//! CORS middleware (G1).
//!
//! The default topology is `domain-split` (api and web on separate host names), so an SPA (public client)
//! calling `identity.example.com/{tenant}/token` is always cross-origin.
//! A POST of `application/x-www-form-urlencoded` is CORS-safelisted so the request itself goes out, but
//! without `Access-Control-Allow-Origin` the browser **cannot read the response** -- that is G1's symptom.
//!
//! # How routes are split
//!
//! | Route | Decision |
//! |---|---|
//! | `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/{tenant}/saml/metadata` | Public metadata anyone can fetch without auth, so `Access-Control-Allow-Origin: *` |
//! | `/{tenant}/token`, `/revoke`, `/introspect`, `/userinfo` | Reflect the origin only on an exact match with the tenant's allowed origin set ([`assay_core::application::cors_policy`]) |
//! | Everything else (admin API, `/internal/*`, `/authorize` redirects) | No CORS headers (not routes called from browser JS) |
//!
//! **`Access-Control-Allow-Credentials` is never set on any route.** The api does not read browser cookies
//! (ADR-0018), so there is no reason to. Not setting it also structurally guarantees that the public metadata's `*`
//! cannot lead to session exfiltration.
//!
//! # Why not `tower_http::CorsLayer`
//!
//! Allowed origins are decided dynamically per tenant and per registered client. `CorsLayer`'s
//! `AllowOrigin::predicate` could express it, but the decision needs a DB lookup (async).

use crate::presentation::state::AppState;
use assay_core::domain::tenant::TenantId;
use axum::extract::{Request, State};
use axum::http::header::{
    HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS, ORIGIN,
    VARY,
};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

/// Preflight result cache time (seconds). Kept short since the allowed set can change from the admin screen.
const PREFLIGHT_MAX_AGE_SECS: u64 = 600;

/// Methods allowed in preflight (assay's protocol surface only uses GET and POST).
const ALLOWED_METHODS: &str = "GET, POST, OPTIONS";

/// How a request is treated for CORS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorsScope {
    /// Public metadata anyone can fetch (`*`).
    PublicMetadata,
    /// Protected protocol surface that needs matching against the tenant's allowed origins.
    TenantScoped(TenantId),
    /// Routes where CORS is not enabled.
    None,
}

pub async fn apply_cors(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // A request without `Origin` is not a browser cross-origin access (curl, server-to-server). Do nothing.
    let Some(origin) = request
        .headers()
        .get(ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return next.run(request).await;
    };
    let scope = classify(request.uri().path());
    if scope == CorsScope::None {
        return next.run(request).await;
    }

    let allow_origin = match scope {
        CorsScope::PublicMetadata => Some("*".to_string()),
        CorsScope::TenantScoped(tenant_id) => state
            .cors_policy
            .allows(tenant_id, &origin)
            .await
            .then_some(origin),
        CorsScope::None => None,
    };

    // Preflight (OPTIONS) is completed here without reaching handlers. The router has no
    // OPTIONS, so passing it through would give 405 with no CORS headers.
    if request.method() == Method::OPTIONS {
        let requested_headers = request
            .headers()
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned();
        return preflight_response(allow_origin.as_deref(), requested_headers);
    }

    let mut response = next.run(request).await;
    // No headers for disallowed origins (reading fails in the browser = as intended).
    if let Some(value) = allow_origin
        .as_deref()
        .and_then(|o| HeaderValue::try_from(o).ok())
    {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    // Tell caches the response varies per origin (prevents mix-ups in shared caches).
    append_vary_origin(&mut response);
    response
}

fn preflight_response(
    allow_origin: Option<&str>,
    requested_headers: Option<HeaderValue>,
) -> Response {
    let Some(origin) = allow_origin.and_then(|o| HeaderValue::try_from(o).ok()) else {
        // A preflight from a disallowed origin is returned without CORS headers (the browser won't send the actual
        // request). No reason is given -- don't let outsiders enumerate the allowed set.
        let mut response = StatusCode::NO_CONTENT.into_response();
        append_vary_origin(&mut response);
        return response;
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOWED_METHODS),
    );
    // Allow the requested headers as is. Since `Allow-Credentials` is not set, what is allowed here is only
    // "values the caller attaches itself" (`Authorization`, `Content-Type`); credentials the browser
    // attaches automatically (cookies) are out of scope.
    if let Some(requested) = requested_headers {
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, requested);
    }
    if let Ok(max_age) = HeaderValue::try_from(PREFLIGHT_MAX_AGE_SECS.to_string()) {
        headers.insert(ACCESS_CONTROL_MAX_AGE, max_age);
    }
    append_vary_origin(&mut response);
    response
}

fn append_vary_origin(response: &mut Response) {
    response
        .headers_mut()
        .append(VARY, HeaderValue::from_name(ORIGIN));
}

/// Decides the CORS treatment from the path.
///
/// Tenant-scoped paths are `/{tenant_id}/...` (ADR-0009 §6). The existence of `tenant_id` is not
/// checked (an unknown tenant has an empty allowed set, so no CORS headers end up attached).
fn classify(path: &str) -> CorsScope {
    let mut segments = path.trim_start_matches('/').split('/');
    let Some(first) = segments.next() else {
        return CorsScope::None;
    };
    // There is no public metadata outside tenants (Discovery is per tenant). Anything but `/{tenant}` is out of scope.
    let Ok(tenant_id) = Uuid::parse_str(first) else {
        return CorsScope::None;
    };
    let rest: Vec<&str> = segments.collect();
    match rest.as_slice() {
        [".well-known", "openid-configuration"] | [".well-known", "jwks.json"] => {
            CorsScope::PublicMetadata
        }
        ["saml", "metadata"] => CorsScope::PublicMetadata,
        ["token"] | ["revoke"] | ["introspect"] | ["userinfo"] => {
            CorsScope::TenantScoped(tenant_id.into())
        }
        _ => CorsScope::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "00000000-0000-7000-8000-000000000001";

    #[test]
    fn public_metadata_is_open_to_everyone() {
        assert_eq!(
            classify(&format!("/{TENANT}/.well-known/openid-configuration")),
            CorsScope::PublicMetadata
        );
        assert_eq!(
            classify(&format!("/{TENANT}/.well-known/jwks.json")),
            CorsScope::PublicMetadata
        );
        assert_eq!(
            classify(&format!("/{TENANT}/saml/metadata")),
            CorsScope::PublicMetadata
        );
    }

    #[test]
    fn protocol_endpoints_are_checked_against_the_tenant_allowlist() {
        for path in ["token", "revoke", "introspect", "userinfo"] {
            assert!(
                matches!(
                    classify(&format!("/{TENANT}/{path}")),
                    CorsScope::TenantScoped(_)
                ),
                "{path} must be tenant scoped"
            );
        }
    }

    /// CORS is not opened for the admin API, internal API or browser redirect routes. The admin API is only called from web,
    /// which holds the SSO cookie, and `/internal/*` is never exposed externally to begin with.
    #[test]
    fn everything_else_stays_closed() {
        assert_eq!(
            classify(&format!("/{TENANT}/admin/clients")),
            CorsScope::None
        );
        assert_eq!(classify(&format!("/{TENANT}/authorize")), CorsScope::None);
        assert_eq!(classify("/internal/authenticate"), CorsScope::None);
        assert_eq!(classify("/healthz"), CorsScope::None);
        assert_eq!(classify("/api/openapi.json"), CorsScope::None);
    }

    /// If the tenant part is not a UUID, it is not treated as tenant-scoped (prevents misfires on `/api/docs` etc.).
    #[test]
    fn a_non_uuid_first_segment_is_not_a_tenant() {
        assert_eq!(classify("/not-a-uuid/token"), CorsScope::None);
    }

    /// `Vary: Origin` is appended, not overwritten (does not erase values set by other middleware).
    #[test]
    fn vary_origin_is_appended() {
        let mut response = StatusCode::OK.into_response();
        response
            .headers_mut()
            .insert(VARY, HeaderValue::from_static("accept-language"));
        append_vary_origin(&mut response);
        let values: Vec<&str> = response
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(values, vec!["accept-language", "origin"]);
    }
}
