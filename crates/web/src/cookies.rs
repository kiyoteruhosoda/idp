//! Cookie の読み書き（axum アダプタ）。
//!
//! 名前と `Set-Cookie` 値の組み立ては api と共有する必要があるため
//! [`idp_contracts::cookies`] に単一定義してある。本モジュールは `HeaderMap` からの読み出しと、
//! 応答へ載せる `Set-Cookie` ヘッダの組み立て（[`SetCookies`]）という axum 依存の部分を担う。
//!
//! web が発行する Cookie は 2 種類ある。取り違えると SSO が壊れる（別ドメイン構成で api が
//! セッションを読めない／CSRF Cookie が不必要に親ドメインへ広がる）ため、[`SetCookies`] では
//! メソッド名で区別する。
//!
//! - **サービス横断**（`sso_session_id`・`auth_session_id`）: api も読む。`set_shared` / `expire_shared`
//! - **web ローカル**（`lang`・CSRF・MFA チケット）: web だけが読む。`set_local` / `expire_local`

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName};
use axum::response::AppendHeaders;

pub use idp_contracts::cookies::{CookiePolicy, AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// 管理ログインフォームの CSRF 用 Cookie（GET で発行する推測不能な乱数。同期トークンの種）。
pub const ADMIN_CSRF_COOKIE: &str = "admin_csrf_id";
/// エンドユーザー・ポータルのログインフォーム CSRF 用 Cookie（`admin_csrf_id` と同じ仕組み・別名前空間）。
pub const PORTAL_CSRF_COOKIE: &str = "portal_csrf_id";
/// ポータルの TOTP 入力ステップで `mfa_ticket`（署名付き短命チケット）を保持する Cookie。
pub const PORTAL_MFA_COOKIE: &str = "portal_mfa_ticket";
/// 表示言語の選択を保持する Cookie（`ja` / `en`。MT15。決定チェーンの優先度3）。
pub const LANG_COOKIE: &str = "lang";
/// 言語 Cookie の保持期間（既定 1 年）。UI 設定のため長命にする。
pub const LANG_COOKIE_MAX_AGE_SECS: u64 = 31_536_000;

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

/// 応答へ載せる `Set-Cookie` ヘッダの集合。`WebState::set_cookies()` から作り、メソッドを繋いで
/// 組み立てて `AppendHeaders` として返す（`IntoResponse` のタプルへそのまま渡せる）。
///
/// ```ignore
/// (state.set_cookies()
///     .set_shared(cookies::SSO_SESSION_COOKIE, &sso_session_id, ttl)
///     .expire_shared(cookies::AUTH_SESSION_COOKIE)
///     .into_headers(),
///  found(&redirect_to)).into_response()
/// ```
#[derive(Debug, Clone)]
pub struct SetCookies {
    policy: CookiePolicy,
    headers: Vec<(HeaderName, String)>,
}

impl SetCookies {
    pub fn new(policy: CookiePolicy) -> Self {
        Self {
            policy,
            headers: Vec::new(),
        }
    }

    /// サービス横断 Cookie を発行する（`COOKIE_DOMAIN` 設定時は `Domain` 付き + host-only 削除の併送）。
    #[must_use]
    pub fn set_shared(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.push_all(self.policy.set_shared(name, value, max_age_secs));
        self
    }

    /// サービス横断 Cookie を失効させる。
    #[must_use]
    pub fn expire_shared(mut self, name: &str) -> Self {
        self.push_all(self.policy.expire_shared(name));
        self
    }

    /// web ローカル Cookie を発行する（host-only。`Domain` は付けない）。
    #[must_use]
    pub fn set_local(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.set_local(name, value, max_age_secs)));
        self
    }

    /// web ローカル Cookie を失効させる。
    #[must_use]
    pub fn expire_local(mut self, name: &str) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.expire_local(name)));
        self
    }

    /// 応答へ付与する `Set-Cookie` ヘッダ。
    pub fn into_headers(self) -> AppendHeaders<Vec<(HeaderName, String)>> {
        AppendHeaders(self.headers)
    }

    fn push_all(&mut self, cookies: Vec<String>) {
        self.headers
            .extend(cookies.into_iter().map(|cookie| (SET_COOKIE, cookie)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn values(set_cookies: SetCookies) -> Vec<String> {
        set_cookies.headers.into_iter().map(|(_, v)| v).collect()
    }

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
    fn login_success_cookies_are_accumulated_in_order() {
        // ログイン成功の代表形: SSO 発行 + auth_session 失効 + 言語同期（ADR-0012 §3 / MT20）。
        let set_cookies = SetCookies::new(CookiePolicy::new(true, None))
            .set_shared(SSO_SESSION_COOKIE, "sess", 600)
            .expire_shared(AUTH_SESSION_COOKIE)
            .set_local(LANG_COOKIE, "ja", LANG_COOKIE_MAX_AGE_SECS);
        assert_eq!(
            values(set_cookies),
            vec![
                "sso_session_id=sess; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure",
                "auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
                "lang=ja; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
    }

    #[test]
    fn shared_cookies_carry_the_domain_and_local_cookies_do_not() {
        // 別ドメイン構成: セッションだけが親ドメインへ広がり、CSRF・言語は host-only のまま。
        let set_cookies = SetCookies::new(CookiePolicy::new(false, Some("example.com")))
            .set_shared(SSO_SESSION_COOKIE, "sess", 600)
            .expire_local(ADMIN_CSRF_COOKIE);
        let values = values(set_cookies);
        assert_eq!(values.len(), 3, "domain cookie + host-only cleanup + csrf");
        assert!(values[0].contains("Domain=example.com"), "{values:?}");
        assert!(
            !values[1].contains("Domain=") && values[1].contains("Max-Age=0"),
            "{values:?}"
        );
        assert!(
            values[2].starts_with("admin_csrf_id=") && !values[2].contains("Domain="),
            "{values:?}"
        );
    }
}
