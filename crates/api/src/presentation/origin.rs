//! Origin / Referer check for state-changing requests authenticated by cookie (SEC4).
//!
//! In the default `domain-split` topology the SSO cookie is host-only and attached only to the web host,
//! so it never reaches the api admin API from a browser. With `PUBLISH_TOPOLOGY=single-origin`, however,
//! nginx routes `/{tenant}/admin/*` by the `Accept` header, so a same-site script sending
//! `Accept: application/json` can reach the api admin API with the cookie.
//!
//! **A JSON content-type is no defence.** Some state-changing endpoints take no body (`restart_service`,
//! `rotate_client_secret`, `reset_user_password` / `reset_user_mfa`) and fire on a POST + `Accept`
//! **simple request** (no preflight). A `SameSite=Lax` cookie is sent because the request is same-site.
//!
//! So extractors that authenticate by cookie require, for state-changing methods, that **`Origin`
//! (or `Referer` if absent) matches an allowed origin**.
//!
//! Only two allowed origins, determined by the deployment:
//!
//! * the origin of `PUBLIC_WEB_BASE_URL` (the same host as the api under single-origin)
//! * the origin of `ISSUER` (the api itself; meant for trying calls from the `/api/docs` Swagger UI)
//!
//! **Requests with neither header pass.** Browsers always send `Origin` on state-changing methods, so
//! they are outside the CSRF threat model, and this keeps the runbooks (`curl` examples in `docs/OPERATIONS.md`) working.

use crate::config::Config;
use axum::http::header::{ORIGIN, REFERER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};

/// Whether a cookie-authenticated state-changing request comes from an acceptable origin.
pub fn is_allowed(parts: &Parts, config: &Config) -> bool {
    is_allowed_from(&parts.method, &parts.headers, &allowed_origins(config))
}

fn is_allowed_from(method: &Method, headers: &HeaderMap, allowed: &[String]) -> bool {
    // Safe (non-state-changing) methods are out of scope. Browser navigations carry no Origin.
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    let Some(origin) = request_origin(headers) else {
        // Not a browser (server-to-server, CLI). The CSRF premise (the browser attaching the cookie) does not hold.
        return true;
    };
    allowed.contains(&origin)
}

/// The origin the request claims. Prefers `Origin`, otherwise derived from `Referer`.
/// `Origin: null` (sandboxed iframe, `data:`) is an "opaque origin" and never matches.
fn request_origin(headers: &HeaderMap) -> Option<String> {
    if let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        return Some(normalize(origin).unwrap_or_else(|| origin.to_string()));
    }
    let referer = headers.get(REFERER).and_then(|v| v.to_str().ok())?;
    normalize(referer)
}

/// Allowed origin (ascii-serialized, `scheme://host[:port]`).
fn allowed_origins(config: &Config) -> Vec<String> {
    [config.public_web_base_url(), config.issuer()]
        .into_iter()
        .filter_map(normalize)
        .collect()
}

fn normalize(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts(method: Method, headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder().method(method).uri("/t/admin/clients");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn allowed() -> Vec<String> {
        vec!["https://id.example.com".to_string()]
    }

    fn check(method: Method, headers: &[(&str, &str)]) -> bool {
        let p = parts(method, headers);
        is_allowed_from(&p.method, &p.headers, &allowed())
    }

    #[test]
    fn safe_methods_are_never_blocked() {
        // Does not change state, so out of CSRF scope. Navigations carry no Origin.
        assert!(check(
            Method::GET,
            &[("origin", "https://evil.example.com")]
        ));
        assert!(check(
            Method::HEAD,
            &[("origin", "https://evil.example.com")]
        ));
    }

    #[test]
    fn same_site_subdomain_cannot_post_to_the_admin_api() {
        // The SEC4 attack shape: a body-less simple request from another subdomain of the same eTLD+1.
        assert!(!check(
            Method::POST,
            &[
                ("origin", "https://evil.id.example.com"),
                ("accept", "application/json")
            ]
        ));
        assert!(!check(
            Method::POST,
            &[("origin", "https://id.example.com.evil.test")]
        ));
        assert!(!check(
            Method::DELETE,
            &[("origin", "https://evil.example.com")]
        ));
    }

    #[test]
    fn the_configured_origin_is_accepted() {
        assert!(check(Method::POST, &[("origin", "https://id.example.com")]));
        assert!(check(
            Method::POST,
            &[("referer", "https://id.example.com/t/admin/clients")]
        ));
    }

    #[test]
    fn requests_without_browser_headers_still_work() {
        // Does not break the runbook curl (which attaches the cookie explicitly).
        assert!(check(Method::POST, &[]));
    }

    #[test]
    fn opaque_origin_is_rejected() {
        assert!(!check(Method::POST, &[("origin", "null")]));
    }

    #[test]
    fn normalizes_to_scheme_host_port() {
        assert_eq!(
            normalize("https://id.example.com/tenant/login?x=1").as_deref(),
            Some("https://id.example.com")
        );
        assert_eq!(
            normalize("http://id.example.com:8080/").as_deref(),
            Some("http://id.example.com:8080")
        );
        // An opaque origin (not a tuple) is never matched.
        assert_eq!(normalize("null"), None);
        assert_eq!(normalize("data:text/html,x"), None);
    }

    #[test]
    fn referer_is_used_when_origin_is_absent() {
        let p = parts(
            Method::POST,
            &[("referer", "https://id.example.com/tenant/admin/clients")],
        );
        assert_eq!(
            request_origin(&p.headers).as_deref(),
            Some("https://id.example.com")
        );
    }

    #[test]
    fn opaque_origin_never_matches_an_allowed_origin() {
        let p = parts(Method::POST, &[("origin", "null")]);
        // Cannot be normalized, so it comes back raw and never matches an allowed origin (derived from a URL).
        assert_eq!(request_origin(&p.headers).as_deref(), Some("null"));
    }

    #[test]
    fn missing_headers_mean_a_non_browser_client() {
        let p = parts(Method::POST, &[]);
        assert_eq!(request_origin(&p.headers), None);
    }
}
