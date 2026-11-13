//! Cookie reading (axum adapter).
//!
//! The api issues no cookies to browsers (ADR-0018 decision 2). Reading is likewise limited to the
//! `Cookie: sso_session_id=...` header that web's `api_client` explicitly attaches on server-to-server calls (the admin JSON API's
//! auth extractor, `presentation::admin`). The name is a contract shared with web, so it is
//! defined once in [`assay_contracts::cookies`].

use axum::http::header::COOKIE;
use axum::http::HeaderMap;

pub use assay_contracts::cookies::{AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// Extracts the value of `name` from the request's `Cookie` header.
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    assay_contracts::cookies::read(
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
        name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn reads_a_cookie_from_the_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("a=1; auth_session_id=abc123; b=2"),
        );
        assert_eq!(
            get(&headers, AUTH_SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
        assert_eq!(get(&headers, "missing"), None);
    }

    #[test]
    fn reads_a_cookie_split_across_several_cookie_headers() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("a=1"));
        headers.append(COOKIE, HeaderValue::from_static("sso_session_id=xyz"));
        assert_eq!(get(&headers, SSO_SESSION_COOKIE).as_deref(), Some("xyz"));
    }
}
