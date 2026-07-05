//! Cookie の読み書きヘルパー。
//!
//! 属性は設計仕様 §2.4 に従い `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/` を付与する
//! （`Secure` は `Config::cookie_secure()`。開発時の http issuer では無効化できる）。

use axum::http::header::COOKIE;
use axum::http::HeaderMap;

/// `auth_session_id` Cookie（`/authorize` 〜 `/login` の短命 Cookie）。
pub const AUTH_SESSION_COOKIE: &str = "auth_session_id";
/// SSO セッション Cookie（値は session_id 平文。DB にはハッシュのみ保存）。
pub const SSO_SESSION_COOKIE: &str = "sso_session_id";

/// リクエストの `Cookie` ヘッダから `name` の値を取り出す。
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(COOKIE).iter().find_map(|value| {
        value.to_str().ok().and_then(|raw| {
            raw.split(';').find_map(|pair| {
                let (k, v) = pair.trim().split_once('=')?;
                (k == name).then(|| v.to_string())
            })
        })
    })
}

/// `Set-Cookie` の値を構築する。
pub fn build(name: &str, value: &str, max_age_secs: u64, secure: bool) -> String {
    let mut cookie =
        format!("{name}={value}; Max-Age={max_age_secs}; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Cookie を失効させる `Set-Cookie` の値を構築する。
pub fn expire(name: &str, secure: bool) -> String {
    build(name, "", 0, secure)
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
        assert_eq!(get(&headers, "auth_session_id").as_deref(), Some("abc123"));
        assert_eq!(get(&headers, "missing"), None);
    }

    #[test]
    fn builds_cookie_with_required_attributes() {
        let c = build("sso_session_id", "v", 600, true);
        assert_eq!(
            c,
            "sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        let c = expire("sso_session_id", false);
        assert_eq!(
            c,
            "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        );
    }
}
