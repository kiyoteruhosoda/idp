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
/// 管理ログインフォームの CSRF 用 Cookie（GET で発行する推測不能な乱数。同期トークンの種）。
pub const ADMIN_CSRF_COOKIE: &str = "admin_csrf_id";

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
    build_with_domain(name, value, max_age_secs, secure, None)
}

/// Cookie を失効させる `Set-Cookie` の値を構築する。
pub fn expire(name: &str, secure: bool) -> String {
    build(name, "", 0, secure)
}

fn build_with_domain(
    name: &str,
    value: &str,
    max_age_secs: u64,
    secure: bool,
    domain: Option<&str>,
) -> String {
    let mut cookie = format!("{name}={value}; Max-Age={max_age_secs}");
    if let Some(domain) = domain {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie.push_str("; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// サービス横断 Cookie（`sso_session_id`・`auth_session_id`）の `Set-Cookie` 値一式を構築する
/// （ADR-0012 §3）。
///
/// - `domain` が `None`（単一オリジン構成）: 従来どおり host-only の 1 本のみ。
/// - `domain` が `Some`（別ドメイン構成）: `Domain` 属性付き Cookie に加えて、`Domain` 属性なしの
///   同名削除 Cookie（`Max-Age=0`）を併送する。Cookie の識別子は名前だけでなく `Domain` を含むため、
///   単一オリジン構成から移行した既存ブラウザに残る host-only Cookie を能動的に掃除しないと、
///   同名 Cookie の二重送信で古いセッションが新しいセッションを覆い隠す（ログインループ）。
pub fn build_shared(
    name: &str,
    value: &str,
    max_age_secs: u64,
    secure: bool,
    domain: Option<&str>,
) -> Vec<String> {
    match domain {
        None => vec![build(name, value, max_age_secs, secure)],
        Some(d) => vec![
            build_with_domain(name, value, max_age_secs, secure, Some(d)),
            build(name, "", 0, secure),
        ],
    }
}

/// サービス横断 Cookie を失効させる `Set-Cookie` 値一式を構築する。削除 Cookie も発行時と同じ
/// `Domain` で出さないと消えないため、`domain` 設定時はドメイン付き削除 + host-only 削除を併送する。
pub fn expire_shared(name: &str, secure: bool, domain: Option<&str>) -> Vec<String> {
    build_shared(name, "", 0, secure, domain)
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

    #[test]
    fn shared_cookie_without_domain_keeps_host_only_behavior() {
        // COOKIE_DOMAIN 未設定（単一オリジン構成）は従来と同一の 1 本のみ（ADR-0012 の回帰条件）。
        assert_eq!(
            build_shared("sso_session_id", "v", 600, true, None),
            vec!["sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"]
        );
        assert_eq!(
            expire_shared("sso_session_id", false, None),
            vec!["sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"]
        );
    }

    #[test]
    fn shared_cookie_with_domain_adds_host_only_cleanup() {
        // Domain 付き発行と同時に host-only の同名削除 Cookie を併送する（移行時の残留掃除）。
        assert_eq!(
            build_shared("sso_session_id", "v", 600, true, Some("example.com")),
            vec![
                "sso_session_id=v; Max-Age=600; Domain=example.com; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
        // 削除もドメイン付き + host-only の両方で出す（Domain が違う Cookie は消えないため）。
        assert_eq!(
            expire_shared("auth_session_id", false, Some("example.com")),
            vec![
                "auth_session_id=; Max-Age=0; Domain=example.com; Path=/; HttpOnly; SameSite=Lax",
                "auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            ]
        );
    }
}
