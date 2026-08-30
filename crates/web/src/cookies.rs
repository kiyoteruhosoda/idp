//! Cookie の読み書き（axum アダプタ）。
//!
//! 名前と `Set-Cookie` 値の組み立ては api との契約のため [`assay_contracts::cookies`] に単一定義
//! してある。本モジュールは `HeaderMap` からの読み出しと、応答へ載せる `Set-Cookie` ヘッダの
//! 組み立て（[`SetCookies`]）という axum 依存の部分を担う。
//!
//! ブラウザ Cookie はすべて web だけが発行・読取する host-only Cookie である（ADR-0018 決定 2。
//! api はブラウザ Cookie を読まない）。[`SetCookies`] のメソッドは 2 種類に分かれる。
//!
//! - **セッション**（`sso_session_id`・`auth_session_id`）: `set_session` / `expire_session`。
//!   旧 ADR-0012 構成でブラウザに残った `Domain` 付き Cookie の掃除（削除併送）を伴う。
//! - **web ローカル**（`lang`・CSRF・MFA チケット）: `set_local` / `expire_local`。
//!
//! web ローカルのうち **CSRF の種・MFA チケット・SAML 進行状態**は名前を `__Host-` 前置にして
//! オリジンへ束縛する（SEC5）。Cookie はサブドメイン間で分離されないため、同一親ドメインの別
//! サブドメインを奪った攻撃者が `Domain=親` の同名 Cookie を強制でき、種を固定して CSRF トークンを
//! 偽造できてしまう。名前の解決は `WebState::origin_bound_cookie` に集約してあり、読み出し
//! （[`get`]）と発行（[`SetCookies::set_local`]）は必ず同じ実名を使う。

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName};
use axum::response::AppendHeaders;

pub use assay_contracts::cookies::{CookiePolicy, AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// 管理ログインフォームの CSRF 用 Cookie（GET で発行する推測不能な乱数。同期トークンの種）。
/// **オリジン束縛**（`WebState::origin_bound_cookie` 経由で `__Host-` 前置。SEC5）。
pub const ADMIN_CSRF_COOKIE: &str = "admin_csrf_id";
/// エンドユーザー・ポータルのログインフォーム CSRF 用 Cookie（`admin_csrf_id` と同じ仕組み・別名前空間）。
/// **オリジン束縛**（SEC5）。
pub const PORTAL_CSRF_COOKIE: &str = "portal_csrf_id";
/// ポータルの TOTP 入力ステップで `mfa_ticket`（署名付き短命チケット）を保持する Cookie。
/// **オリジン束縛**（SEC5）。
pub const PORTAL_MFA_COOKIE: &str = "portal_mfa_ticket";
/// SAML SSO の進行状態 id を保持する Cookie。SSO 未確立で `/saml/continue` から
/// ログインへ誘導したあと、ログイン成功時にフローへ復帰するために使う（web ローカル）。
/// **オリジン束縛**（SEC5）。
pub const SAML_REQUEST_COOKIE: &str = "saml_request_id";
/// 表示言語の選択を保持する Cookie（`ja` / `en`。MT15。決定チェーンの優先度3）。
pub const LANG_COOKIE: &str = "lang";
/// 表示設定 Cookie（言語・配色）の保持期間（既定 1 年）。UI 設定のため長命にする。
pub const PREFERENCE_COOKIE_MAX_AGE_SECS: u64 = 31_536_000;
/// 配色の選択を保持する Cookie（`light` / `dark` / `system`）。**`HttpOnly` を付けない**
/// （`assets/theme.js` が最初の描画より前に読む。理由は `assay_contracts::cookies::set_preference`）。
pub const THEME_COOKIE: &str = "theme";

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

/// 応答へ載せる `Set-Cookie` ヘッダの集合。`WebState::set_cookies()` から作り、メソッドを繋いで
/// 組み立てて `AppendHeaders` として返す（`IntoResponse` のタプルへそのまま渡せる）。
///
/// ```ignore
/// (state.set_cookies()
///     .set_session(cookies::SSO_SESSION_COOKIE, &sso_session_id, ttl)
///     .expire_session(cookies::AUTH_SESSION_COOKIE)
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

    /// セッション Cookie を host-only で発行する（`COOKIE_DOMAIN` 設定時は旧 `Domain` 付き
    /// Cookie の削除を併送する。ADR-0018 決定 2・4）。
    #[must_use]
    pub fn set_session(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.push_all(self.policy.set_session(name, value, max_age_secs));
        self
    }

    /// セッション Cookie を失効させる。
    #[must_use]
    pub fn expire_session(mut self, name: &str) -> Self {
        self.push_all(self.policy.expire_session(name));
        self
    }

    /// web ローカル Cookie を発行する（host-only。`Domain` は付けない）。
    #[must_use]
    pub fn set_local(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.set_local(name, value, max_age_secs)));
        self
    }

    /// 画面のスクリプトから読める表示設定 Cookie を発行する（配色。`HttpOnly` 無し）。
    #[must_use]
    pub fn set_preference(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers.push((
            SET_COOKIE,
            self.policy.set_preference(name, value, max_age_secs),
        ));
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
        // ログイン成功の代表形: SSO 発行 + auth_session 失効 + 言語同期（ADR-0018 決定 2 / MT20）。
        let set_cookies = SetCookies::new(CookiePolicy::new(true, None))
            .set_session(SSO_SESSION_COOKIE, "sess", 600)
            .expire_session(AUTH_SESSION_COOKIE)
            .set_local(LANG_COOKIE, "ja", PREFERENCE_COOKIE_MAX_AGE_SECS);
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
    fn session_cookies_stay_host_only_and_clean_up_the_legacy_domain() {
        // ADR-0018 決定 2・4: セッション Cookie 本体は常に host-only。COOKIE_DOMAIN が設定されて
        // いる移行期間は旧 `Domain` 付き Cookie の削除を併送する。CSRF 等のローカル Cookie は対象外。
        let set_cookies = SetCookies::new(CookiePolicy::new(false, Some("example.com")))
            .set_session(SSO_SESSION_COOKIE, "sess", 600)
            .expire_local(ADMIN_CSRF_COOKIE);
        let values = values(set_cookies);
        assert_eq!(values.len(), 3, "host-only cookie + legacy cleanup + csrf");
        assert!(
            values[0].starts_with("sso_session_id=sess") && !values[0].contains("Domain="),
            "{values:?}"
        );
        assert!(
            values[1].contains("Domain=example.com") && values[1].contains("Max-Age=0"),
            "{values:?}"
        );
        assert!(
            values[2].starts_with("admin_csrf_id=") && !values[2].contains("Domain="),
            "{values:?}"
        );
    }
}
