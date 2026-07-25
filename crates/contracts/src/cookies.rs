//! Cookie の名前と `Set-Cookie` 値の組み立て（api ↔ web 共通）。
//!
//! `sso_session_id` / `auth_session_id` は **api と web の双方が読み書きするサービス横断 Cookie**
//! であり、名前・属性がずれると SSO が静かに壊れる（ログインループ）。名前も属性の組み立ても
//! csrf・cookie_domain と同様に契約として本 crate に単一定義し、両サービスはこれを使う。
//!
//! 属性は設計仕様 §2.4 に従い `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/` を付与する
//! （`Secure` は各サービスが自身の公開オリジンのスキームから決める。ADR-0012 §2）。
//! `Domain` の扱いは [`CookiePolicy`] を参照。
//!
//! axum には依存しない（本 crate の制約）。`HeaderMap` からの読み出し・`Set-Cookie` ヘッダ化は
//! 各サービスの `cookies` モジュールが薄いアダプタとして担う。

/// SSO セッション Cookie（値は session_id 平文。DB にはハッシュのみ保存）。api・web 双方が読む。
pub const SSO_SESSION_COOKIE: &str = "sso_session_id";
/// `auth_session_id` Cookie（`/authorize` 〜 `/login` の短命 Cookie）。api・web 双方が読む。
pub const AUTH_SESSION_COOKIE: &str = "auth_session_id";

/// `Cookie` ヘッダの生文字列（複数ヘッダ可）から `name` の値を取り出す。
///
/// 名前は完全一致で比較する（`sso_session_id` が `x_sso_session_id` に一致しない）。値に `=` を
/// 含む Cookie（base64 等）は最初の `=` だけを区切りとして扱う。
pub fn read<'a>(raw_headers: impl IntoIterator<Item = &'a str>, name: &str) -> Option<String> {
    raw_headers.into_iter().find_map(|raw| {
        raw.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

/// サービス横断 Cookie に付与する属性の方針（`Secure` と `Domain`）。設定から一度組み立てて使い回す。
///
/// `Secure` と `Domain` は必ず対で決まるため、呼び出し側が両方を引数で持ち回る形にはしない
/// （新しい発行箇所で `Domain` を渡し忘れると、その Cookie だけが host-only になって
/// 別ドメイン構成の SSO が壊れる。ADR-0012 §3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    secure: bool,
    domain: Option<String>,
}

impl CookiePolicy {
    /// `secure` は自サービスの公開オリジンのスキーム由来、`domain` は `COOKIE_DOMAIN`
    /// （検証済みの値。[`crate::cookie_domain::validate_cookie_domain`]）。
    pub fn new(secure: bool, domain: Option<&str>) -> Self {
        Self {
            secure,
            domain: domain.map(str::to_string),
        }
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    /// サービス横断 Cookie の `Domain` 属性。`None` = host-only（単一オリジン構成の従来挙動）。
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// サービス横断 Cookie（`sso_session_id`・`auth_session_id`）を発行する `Set-Cookie` 値一式
    /// （ADR-0012 §3）。
    ///
    /// - `Domain` 未設定（単一オリジン構成）: 従来どおり host-only の 1 本のみ。
    /// - `Domain` 設定時（別ドメイン構成）: `Domain` 属性付き Cookie に加えて、`Domain` 属性なしの
    ///   同名削除 Cookie（`Max-Age=0`）を併送する。Cookie の識別子は名前だけでなく `Domain` を
    ///   含むため、単一オリジン構成から移行した既存ブラウザに残る host-only Cookie を能動的に
    ///   掃除しないと、同名 Cookie の二重送信で古いセッションが新しいセッションを覆い隠す。
    pub fn set_shared(&self, name: &str, value: &str, max_age_secs: u64) -> Vec<String> {
        match self.domain.as_deref() {
            None => vec![build(name, value, max_age_secs, self.secure, None)],
            Some(domain) => vec![
                build(name, value, max_age_secs, self.secure, Some(domain)),
                build(name, "", 0, self.secure, None),
            ],
        }
    }

    /// サービス横断 Cookie を失効させる `Set-Cookie` 値一式。削除 Cookie も発行時と同じ `Domain` で
    /// 出さないと消えないため、`Domain` 設定時はドメイン付き削除 + host-only 削除を併送する。
    pub fn expire_shared(&self, name: &str) -> Vec<String> {
        self.set_shared(name, "", 0)
    }

    /// サービスローカル Cookie（発行元サービスだけが読むもの。CSRF・言語・MFA チケット等）を
    /// 発行する `Set-Cookie` 値。`Domain` は付けず host-only に保つ。
    pub fn set_local(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        build(name, value, max_age_secs, self.secure, None)
    }

    /// サービスローカル Cookie を失効させる `Set-Cookie` 値。
    pub fn expire_local(&self, name: &str) -> String {
        self.set_local(name, "", 0)
    }
}

fn build(name: &str, value: &str, max_age_secs: u64, secure: bool, domain: Option<&str>) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_cookie_by_exact_name() {
        let header = "a=1; auth_session_id=abc123; b=2";
        assert_eq!(read([header], "auth_session_id").as_deref(), Some("abc123"));
        assert_eq!(read([header], "missing"), None);
        // 部分一致では拾わない（`sso_session_id` が `x_sso_session_id` に一致しない）。
        assert_eq!(read(["x_sso_session_id=other"], "sso_session_id"), None);
        assert_eq!(read(["sso_session_id_2=other"], "sso_session_id"), None);
    }

    #[test]
    fn reads_a_cookie_across_multiple_headers() {
        // ブラウザ・プロキシは `Cookie` ヘッダを複数本に分けて送ることがある。
        assert_eq!(
            read(["a=1", "sso_session_id=xyz"], "sso_session_id").as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn keeps_values_containing_equals_signs() {
        // base64 値の末尾パディング（`=`）が切り落とされない。
        assert_eq!(read(["t=YWJj=="], "t").as_deref(), Some("YWJj=="));
    }

    #[test]
    fn local_cookie_has_the_required_attributes() {
        let policy = CookiePolicy::new(true, None);
        assert_eq!(
            policy.set_local("lang", "ja", 600),
            "lang=ja; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        assert_eq!(
            CookiePolicy::new(false, None).expire_local("lang"),
            "lang=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn local_cookie_never_gets_the_domain_attribute() {
        // CSRF・言語・MFA チケットは発行元サービスだけが読む。別ドメイン構成でも host-only に保つ。
        let policy = CookiePolicy::new(true, Some("example.com"));
        assert_eq!(
            policy.set_local("portal_csrf_id", "v", 600),
            "portal_csrf_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!policy.expire_local("portal_csrf_id").contains("Domain="));
    }

    #[test]
    fn shared_cookie_without_domain_keeps_host_only_behavior() {
        // COOKIE_DOMAIN 未設定（単一オリジン構成）は従来と同一の 1 本のみ（ADR-0012 の回帰条件）。
        let policy = CookiePolicy::new(true, None);
        assert_eq!(
            policy.set_shared(SSO_SESSION_COOKIE, "v", 600),
            vec!["sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"]
        );
        assert_eq!(
            CookiePolicy::new(false, None).expire_shared(SSO_SESSION_COOKIE),
            vec!["sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"]
        );
    }

    #[test]
    fn shared_cookie_with_domain_adds_host_only_cleanup() {
        // Domain 付き発行と同時に host-only の同名削除 Cookie を併送する（移行時の残留掃除）。
        assert_eq!(
            CookiePolicy::new(true, Some("example.com")).set_shared(SSO_SESSION_COOKIE, "v", 600),
            vec![
                "sso_session_id=v; Max-Age=600; Domain=example.com; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
        // 削除もドメイン付き + host-only の両方で出す（Domain が違う Cookie は消えないため）。
        assert_eq!(
            CookiePolicy::new(false, Some("example.com")).expire_shared(AUTH_SESSION_COOKIE),
            vec![
                "auth_session_id=; Max-Age=0; Domain=example.com; Path=/; HttpOnly; SameSite=Lax",
                "auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            ]
        );
    }

    #[test]
    fn domain_cookie_is_readable_back_by_the_same_name() {
        // 発行 → ブラウザ → 読み出しの往復で名前が一致する（api/web の名前ずれ防止）。
        let issued = CookiePolicy::new(false, Some("example.com")).set_shared(
            SSO_SESSION_COOKIE,
            "session-value",
            600,
        );
        let sent_back = issued[0].split(';').next().unwrap();
        assert_eq!(
            read([sent_back], SSO_SESSION_COOKIE).as_deref(),
            Some("session-value")
        );
    }
}
