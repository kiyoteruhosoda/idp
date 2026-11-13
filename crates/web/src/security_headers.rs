//! Security header middleware (SEC3. Same policy as the api's `security_headers`).
//!
//! web serves HTML (login screen, admin console), so the following are added to every response:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY` (clickjacking protection. Only the 302 of the round trip tried without showing a screen allows the configured parent frame.
//!   `allow_silent_auth_framing`, task #888)
//! - `Content-Security-Policy` (`frame-ancestors 'none'`, no loading from external origins)
//!
//! Additionally, when `hsts_max_age > 0`, `Strict-Transport-Security` is added.
//!
//! For HTML, `no-transform` is added to `Cache-Control`. ⚠ This is **to keep the front (Cloudflare) from rewriting HTML**:
//! Cloudflare's "email address obfuscation" replaces emails in the body with `[email protected]` and
//! restores them with its own script on load. On screens that replace a list without reloading the page
//! (`assets/live-search.js`) the restore did not run, and the replaced text showed (2026-09-25).
//! Admin and login screens may suffer from being rewritten in transit, but never want to be rewritten.
//!
//! `'unsafe-inline'` is removed from `script-src` (SEC12). While inline is allowed, a single
//! reflected XSS would make the CSP useless as a defense. All screen-specific scripts were split out into same-origin
//! assets (`handlers::page_scripts`), and values the templates used to pass are handed over via `data-*`
//! attributes.
//!
//! `'unsafe-inline'` in `style-src` is kept. Current templates use many attributes like `style="display:none"`,
//! and these **do not lead to script execution** (`style-src` cannot bring in
//! `javascript:`), so the priority differs. If removed, it goes together with converting them to classes.

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use axum::middleware::Next;
use axum::response::Response;

/// Same-origin-only CSP. Inline scripts are not allowed (SEC12).
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// CSP for pages whose form submission navigates to an external origin (adds one `form-action` allowance to the default).
///
/// **Chrome applies `form-action` to redirect targets after form submission too** (differs from the CSP3
/// spec, but has been this way for years). The login and consent screens end with a 302 to the RP's `redirect_uri`
/// after submission, so with the default `form-action 'self'`, **the server records consent and issues the code,
/// yet the browser cannot return to the RP**. It fails with the cause showing neither on screen nor in logs.
///
/// Only **the single origin of that authorization request's `redirect_uri`** is allowed (a value exactly matching
/// the registered one is passed in). Pages POSTing to a SAML ACS take the same form for the same reason
/// (`handlers::saml_sso`). If `origin` is empty, the default CSP is returned as is.
pub fn csp_allowing_form_action(origin: &str) -> String {
    if origin.is_empty() {
        return CONTENT_SECURITY_POLICY.to_string();
    }
    CONTENT_SECURITY_POLICY.replace(
        "form-action 'self'",
        &format!("form-action 'self' {origin}"),
    )
}

/// Extracts scheme + host (+ port) from a URL, since CSP sources cannot have a path.
/// Unparseable URLs give an empty string (= no allowance added. fail-closed).
pub fn origin_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| {
            let host = parsed.host_str()?.to_string();
            Some(match parsed.port() {
                Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
                None => format!("{}://{host}", parsed.scheme()),
            })
        })
        .unwrap_or_default()
}

/// Builds a CSP allowing only the origin of the form submission's target URL in `form-action`.
///
/// Callers holding the target as a URL (the RP's `redirect_uri`, the SAML ACS URL) use this.
/// Unparseable URLs keep the default CSP (no allowance added. fail-closed).
pub fn form_action_csp_for(url: &str) -> String {
    csp_allowing_form_action(&origin_of(url))
}

/// Returns an HTML response whose form submission navigates to an external origin, with a CSP adding that allowance.
///
/// The middleware respects a CSP already set by the handler, so what is set here is output as is.
/// If `redirect_uri` cannot be parsed, the default CSP is returned (no allowance added. fail-closed).
pub fn html_with_form_action_csp(redirect_uri: &str, body: String) -> Response {
    use axum::response::{Html, IntoResponse};
    let csp = form_action_csp_for(redirect_uri);
    match HeaderValue::from_str(&csp) {
        Ok(value) => (
            [(axum::http::header::CONTENT_SECURITY_POLICY, value)],
            Html(body),
        )
            .into_response(),
        // If building fails, return the default CSP. Safer than sending a broken header.
        Err(_) => Html(body).into_response(),
    }
}

/// Lets the 302 of the round trip tried without showing a screen (`prompt=none`) go into the configured parent frame (task #888, ADR-0076).
///
/// ⚠ **Do not use for rendered screens.** A 302 is not rendered, so framing it offers nothing to click, but allowing screens
/// makes them a clickjacking target. If the parent is empty, nothing is done (the default `frame-ancestors 'none'` stays).
pub fn allow_silent_auth_framing(
    response: &mut Response,
    ancestors: &assay_contracts::frame_ancestors::FrameAncestors,
) {
    let Some(policy) = ancestors.content_security_policy() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_SECURITY_POLICY, value);
    }
}

/// Whether the response's CSP allows framing (has `frame-ancestors` and it is not `'none'`). If so,
/// `X-Frame-Options: DENY` is not added (with both present, old browsers take DENY).
fn csp_allows_framing(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|csp| {
            csp.contains("frame-ancestors") && !csp.contains("frame-ancestors 'none'")
        })
}

/// Factory for the middleware adding security headers. HSTS is not added when `hsts_max_age` is `0`.
pub async fn add_security_headers(request: Request, next: Next, hsts_max_age: u64) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    // Only the 302 of the round trip tried without showing a screen allows framing (`allow_silent_auth_framing`. task #888)
    if !csp_allows_framing(headers) {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }
    // If the handler has already set a CSP on the response, respect it (the RP-initiated logout front-channel page
    // uses a CSP allowing only the notification target origins in `frame-src`. `handlers::rp_logout`).
    let csp = HeaderName::from_static("content-security-policy");
    if !headers.contains_key(&csp) {
        headers.insert(csp, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    }

    if hsts_max_age > 0 {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={hsts_max_age}")) {
            headers.insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    if is_html(headers) {
        forbid_store_and_transform(headers);
    }

    response
}

fn is_html(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("text/html"))
}

/// Adds `no-store` and `no-transform` to HTML `Cache-Control`. Directives set by the handler are
/// kept; only additions are made.
///
/// - `no-store` (task #589): every HTML web returns is a screen rendered per user, and some carry client secrets,
///   recovery codes, setup links, TOTP secrets or SAML responses. Do not let "back" on a shared device
///   or the disk cache read them. Static assets (CSS, JS, fonts) are not HTML and are excluded
/// - `no-transform`: keep the front from rewriting the body
fn forbid_store_and_transform(headers: &mut axum::http::HeaderMap) {
    let current = headers
        .get(CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let has = |directive: &str| {
        current
            .split(',')
            .any(|d| d.trim().eq_ignore_ascii_case(directive))
    };
    let mut directives: Vec<&str> = Vec::new();
    if !current.is_empty() {
        directives.push(&current);
    }
    if !has("no-store") {
        directives.push("no-store");
    }
    if !has("no-transform") {
        directives.push("no-transform");
    }
    if let Ok(value) = HeaderValue::from_str(&directives.join(", ")) {
        headers.insert(CACHE_CONTROL, value);
    }
    // For HTTP/1.0 intermediaries (that do not understand `Cache-Control`).
    headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Chrome applies `form-action` to redirect targets after form submission too.** The login and
    /// consent screen submissions end with a 302 to the RP's `redirect_uri`, so without allowing that origin
    /// it fails as "consent and code issuance succeeded but the browser does not return to the RP", showing neither
    /// on screen nor in logs (hit on blobshare's production login on 2026-08-27).
    #[test]
    fn the_relying_party_origin_is_allowed_for_form_action() {
        let csp = csp_allowing_form_action("https://share.example.com");
        assert!(
            csp.contains("form-action 'self' https://share.example.com;"),
            "{csp}"
        );
        // Other directives stay at the defaults (not loosened).
        assert!(csp.contains("script-src 'self';"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }

    /// When the origin cannot be extracted, the default is returned (no allowance added. fail-closed).
    #[test]
    fn an_unusable_redirect_uri_leaves_the_policy_untouched() {
        assert_eq!(csp_allowing_form_action(""), CONTENT_SECURITY_POLICY);
        assert_eq!(origin_of("not a url"), "");
        assert_eq!(origin_of(""), "");
    }

    /// CSP sources cannot have a path, so it is cut down to scheme + host (+ port).
    #[test]
    fn only_the_origin_of_the_redirect_uri_is_used() {
        assert_eq!(
            origin_of("https://share.example.com/api/auth/oidc/callback"),
            "https://share.example.com"
        );
        assert_eq!(
            origin_of("http://localhost:8080/cb?x=1#f"),
            "http://localhost:8080"
        );
    }
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn respond(app: Router, uri: &str) -> Response {
        app.oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn app(hsts_max_age: u64) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route(
                "/page",
                get(|| async { axum::response::Html("<p>a@example.com</p>") }),
            )
            .route(
                "/no-store",
                get(|| async {
                    (
                        [(CACHE_CONTROL, "no-store")],
                        axum::response::Html("<p>x</p>"),
                    )
                }),
            )
            .route(
                "/silent",
                get(|| async {
                    let mut response =
                        crate::handlers::found("https://app.example.com/api/auth/sso/callback");
                    let ancestors = assay_contracts::frame_ancestors::parse_frame_ancestors(
                        "https://*.example.com",
                    )
                    .unwrap();
                    allow_silent_auth_framing(&mut response, &ancestors);
                    response
                }),
            )
            .route(
                "/silent-unset",
                get(|| async {
                    let mut response =
                        crate::handlers::found("https://app.example.com/api/auth/sso/callback");
                    allow_silent_auth_framing(
                        &mut response,
                        &assay_contracts::frame_ancestors::FrameAncestors::none(),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn(move |req, next| {
                add_security_headers(req, next, hsts_max_age)
            }))
    }

    /// Only the 302 of the round trip tried without showing a screen allows the configured parent frame (task #888, ADR-0076).
    #[tokio::test]
    async fn a_silent_redirect_may_be_framed_by_the_configured_parents_only() {
        let res = respond(app(0), "/silent").await;
        assert_eq!(
            res.headers()["content-security-policy"],
            "frame-ancestors https://*.example.com"
        );
        assert!(res.headers().get("x-frame-options").is_none());
    }

    /// If no parent is configured, framing is not allowed, as before.
    #[tokio::test]
    async fn without_parents_a_silent_redirect_is_not_framed() {
        let res = respond(app(0), "/silent-unset").await;
        assert_eq!(res.headers()["x-frame-options"], "DENY");
        let csp = res.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }

    /// HTML is not rewritten by the front (Cloudflare's email obfuscation was showing `[email protected]`).
    /// Handler directives are kept and only added to. Non-HTML responses (assets, JSON) are untouched.
    #[tokio::test]
    async fn html_is_marked_no_transform_without_dropping_the_handler_directives() {
        // HTML is not stored (some screens carry secrets. task #589).
        let res = respond(app(0), "/page").await;
        assert_eq!(res.headers()[CACHE_CONTROL], "no-store, no-transform");
        assert_eq!(res.headers()["pragma"], "no-cache");
        let res = respond(app(0), "/no-store").await;
        assert_eq!(res.headers()[CACHE_CONTROL], "no-store, no-transform");
        // Not added to non-HTML responses (static assets etc.).
        let res = respond(app(0), "/").await;
        assert!(res.headers().get(CACHE_CONTROL).is_none());
        assert!(res.headers().get("pragma").is_none());
    }

    #[tokio::test]
    async fn adds_security_headers_to_every_response() {
        let res = respond(app(0), "/").await;
        let headers = res.headers();
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(
            headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("default-src 'self'"));
        // Inline scripts are not allowed (SEC12). Allowing them makes the CSP powerless against a single XSS.
        assert!(
            !csp.contains("script-src 'self' 'unsafe-inline'"),
            "script-src must not allow inline: {csp}"
        );
        // HSTS is not added when hsts_max_age = 0.
        assert!(!headers.contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn adds_hsts_when_max_age_is_positive() {
        let res = respond(app(31_536_000), "/").await;
        assert_eq!(
            res.headers()["strict-transport-security"],
            "max-age=31536000"
        );
    }
}
