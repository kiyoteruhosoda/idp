//! Cookie の読み書き（axum アダプタ）。
//!
//! 名前と `Set-Cookie` 値の組み立ては web と共有する必要があるため
//! [`idp_contracts::cookies`] に単一定義してある。本モジュールは `HeaderMap` からの読み出しと
//! `Set-Cookie` ヘッダ化という axum 依存の部分だけを担う。

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName};

pub use idp_contracts::cookies::{CookiePolicy, AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// リクエストの `Cookie` ヘッダから `name` の値を取り出す。
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    idp_contracts::cookies::read(
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
        name,
    )
}

/// `Set-Cookie` 値一式を `AppendHeaders` へ渡せるヘッダの組に変換する。
pub fn headers(cookies: impl IntoIterator<Item = String>) -> Vec<(HeaderName, String)> {
    cookies
        .into_iter()
        .map(|cookie| (SET_COOKIE, cookie))
        .collect()
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

    #[test]
    fn converts_cookies_into_set_cookie_headers() {
        let policy = CookiePolicy::new(true, Some("example.com"));
        let out = headers(policy.expire_shared(SSO_SESSION_COOKIE));
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|(name, _)| name == SET_COOKIE));
        assert!(out[0].1.contains("Domain=example.com"));
    }
}
