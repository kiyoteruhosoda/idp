//! Security header middleware (S1).
//!
//! Adds the following to every response:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY` (only the 302 of the silent round trip allows the configured parent frame; task #888)
//!
//! Additionally adds `Strict-Transport-Security` when `hsts_max_age > 0`.

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// Lets the 302 of the silent round trip (`prompt=none`) be framed by the configured parent (task #888, ADR-0076).
/// Does nothing when the parent list is empty. ⚠ Not for rendered responses (302 only).
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

/// Whether the response CSP allows framing. If it does, `X-Frame-Options: DENY` is not added.
fn csp_allows_framing(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|csp| {
            csp.contains("frame-ancestors") && !csp.contains("frame-ancestors 'none'")
        })
}

/// Middleware factory that adds the security headers.
///
/// HSTS is not added when `hsts_max_age` is `0`.
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
    // Only the 302 of the silent round trip allows framing (`allow_silent_auth_framing`; task #888).
    if !csp_allows_framing(headers) {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }

    if hsts_max_age > 0 {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={hsts_max_age}")) {
            headers.insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}
