//! Cookie の読み出し（axum アダプタ）。
//!
//! api はブラウザに対して Cookie を発行しない（ADR-0018 決定 2）。読み出しも、web の `api_client`
//! がサーバ間呼び出しで明示的に付与した `Cookie: sso_session_id=...` ヘッダ（管理 JSON API の
//! 認証 extractor。`presentation::admin`）に限る。名前は web と共有する契約のため
//! [`assay_contracts::cookies`] に単一定義してある。

use axum::http::header::COOKIE;
use axum::http::HeaderMap;

pub use assay_contracts::cookies::{AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// リクエストの `Cookie` ヘッダから `name` の値を取り出す。
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
