//! Cookie の名前と `Set-Cookie` 値の組み立て（api ↔ web 契約）。
//!
//! ADR-0018 決定 2 により **api はブラウザ Cookie を読み書きしない**。`sso_session_id` /
//! `auth_session_id` はブラウザに対しては web だけが発行・読取する host-only Cookie になったが、
//! 名前は引き続き契約である（web の `api_client` が管理 JSON API へのサーバ間呼び出しで
//! `Cookie: sso_session_id=...` を明示付与し、api の admin extractor が同じ名前で読むため）。
//! 名前と属性の組み立ては csrf・cookie_domain と同様に本 crate に単一定義し、web はこれを使う。
//!
//! 属性は設計仕様 §2.4 に従い `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/` を付与する
//! （`Secure` は web が自身の公開オリジンのスキームから決める。ADR-0012 §2）。
//! `Domain` は付与しない（host-only が既定。ADR-0018 決定 4）。`COOKIE_DOMAIN` は
//! ADR-0012 §3 の旧構成でブラウザに残った `Domain` 付き Cookie を掃除するためだけに残る
//! （[`CookiePolicy`] 参照）。
//!
//! axum には依存しない（本 crate の制約）。`HeaderMap` からの読み出し・`Set-Cookie` ヘッダ化は
//! 各サービスの `cookies` モジュールが薄いアダプタとして担う。

/// SSO セッション Cookie（値は session_id 平文。DB にはハッシュのみ保存）。ブラウザへは web だけが
/// 発行・読取し、api へはサーバ間呼び出しのヘッダ（admin API）またはボディ（`/internal/*`）で渡す。
pub const SSO_SESSION_COOKIE: &str = "sso_session_id";
/// `auth_session_id` Cookie（`/authorize` ハンドオフ〜 `/login` 完了の短命 Cookie）。web だけが読む。
pub const AUTH_SESSION_COOKIE: &str = "auth_session_id";

/// `__Host-` プレフィックス（RFC 6265bis §4.1.3.2）。この名前で送られた Cookie をブラウザは
/// 「`Secure` かつ `Domain` 無しかつ `Path=/`」でしか受け付けない。結果として **発行元オリジンに
/// 束縛**され、同一親ドメインの別サブドメイン（`Domain=親` を付けられる位置）から上書き・強制できない。
pub const HOST_PREFIX: &str = "__Host-";

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

/// Cookie に付与する属性の方針（`Secure` と旧 `Domain` Cookie の掃除）。設定から一度組み立てて使い回す。
///
/// ADR-0018 決定 2・4: セッション Cookie（`sso_session_id`・`auth_session_id`）は **常に host-only**
/// で発行する。`legacy_cleanup_domain`（`COOKIE_DOMAIN`）が設定されている場合は、ADR-0012 §3 の
/// 旧構成でブラウザに残った `Domain` 付き同名 Cookie を削除する Cookie を併送する（Cookie の識別子は
/// 名前だけでなく `Domain` を含むため、能動的に消さないと二重送信で古いセッションが新しいセッションを
/// 覆い隠す）。掃除が完了した環境では `COOKIE_DOMAIN` を未設定にする（既定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    secure: bool,
    legacy_cleanup_domain: Option<String>,
}

impl CookiePolicy {
    /// `secure` は自サービスの公開オリジンのスキーム由来、`legacy_cleanup_domain` は `COOKIE_DOMAIN`
    /// （検証済みの値。[`crate::cookie_domain::validate_cookie_domain`]）。
    pub fn new(secure: bool, legacy_cleanup_domain: Option<&str>) -> Self {
        Self {
            secure,
            legacy_cleanup_domain: legacy_cleanup_domain.map(str::to_string),
        }
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    /// 掃除対象の旧 `Domain`（`COOKIE_DOMAIN`）。`None` = 掃除なし（既定）。
    pub fn legacy_cleanup_domain(&self) -> Option<&str> {
        self.legacy_cleanup_domain.as_deref()
    }

    /// セッション Cookie（`sso_session_id`・`auth_session_id`）を発行する `Set-Cookie` 値一式。
    ///
    /// - 常に host-only の 1 本を発行する（`Domain` は付けない。ADR-0018 決定 2・4）。
    /// - `COOKIE_DOMAIN` 設定時（旧 ADR-0012 構成からの移行期間）: 加えて `Domain` 属性付きの
    ///   同名削除 Cookie（`Max-Age=0`）を併送し、ブラウザに残った旧 Cookie を掃除する。
    pub fn set_session(&self, name: &str, value: &str, max_age_secs: u64) -> Vec<String> {
        let mut cookies = vec![build(name, value, max_age_secs, self.secure, None)];
        if let Some(domain) = self.legacy_cleanup_domain.as_deref() {
            cookies.push(build(name, "", 0, self.secure, Some(domain)));
        }
        cookies
    }

    /// セッション Cookie を失効させる `Set-Cookie` 値一式。削除 Cookie は発行時と同じ形（host-only）
    /// に加え、`COOKIE_DOMAIN` 設定時は旧 `Domain` 付き削除も併送する（`Domain` が違う Cookie は
    /// 消えないため）。
    pub fn expire_session(&self, name: &str) -> Vec<String> {
        self.set_session(name, "", 0)
    }

    /// サービスローカル Cookie（CSRF・言語・MFA チケット等）を発行する `Set-Cookie` 値。
    /// セッション Cookie と同じく host-only だが、旧 `Domain` 掃除の対象ではない。
    pub fn set_local(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        build(name, value, max_age_secs, self.secure, None)
    }

    /// 画面のスクリプトから読める表示設定 Cookie を発行する `Set-Cookie` 値（`HttpOnly` を付けない）。
    ///
    /// **`HttpOnly` を外すのはこの用途に限る。** 配色は最初の描画より前に確定していないと画面が
    /// 白から黒へちらつくため、`<head>` の同期スクリプトが自分で読む必要がある。運べるのは
    /// `light` / `dark` / `system` のいずれかで、盗まれて困る値も、書き換えられて権限が動く値も
    /// 含まない（配色が変わるだけで、サーバは何の判断にも使わない）。資格情報・セッション識別子を
    /// この関数で発行しないこと。
    pub fn set_preference(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        build_preference(name, value, max_age_secs, self.secure)
    }

    /// サービスローカル Cookie を失効させる `Set-Cookie` 値。
    pub fn expire_local(&self, name: &str) -> String {
        self.set_local(name, "", 0)
    }

    /// オリジン束縛が要るローカル Cookie（CSRF の種・MFA チケット・SAML 進行状態）の実名を返す
    /// （SEC5）。`set_local` / `expire_local` が付ける属性は `__Host-` の要件（`Secure` /
    /// `Domain` 無し / `Path=/`）をすでに満たすため、前置するのは名前だけでよい。
    ///
    /// **平文 HTTP（`secure == false`）では前置しない。** `__Host-` 付きの Cookie はブラウザが
    /// `Secure` 無しでは保存を拒否するため、前置すると開発環境（`http://localhost`）で CSRF の種が
    /// 一切保存されずログインできなくなる。本番は必ず HTTPS（`COOKIE_SECURE`）なので保護は効く。
    pub fn origin_bound_name(&self, base_name: &str) -> String {
        if self.secure {
            format!("{HOST_PREFIX}{base_name}")
        } else {
            base_name.to_string()
        }
    }
}

/// スクリプトから読める Cookie（`HttpOnly` 無し）。属性は [`build`] と揃える。
fn build_preference(name: &str, value: &str, max_age_secs: u64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; Max-Age={max_age_secs}; Path=/; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
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
    fn origin_bound_names_carry_the_host_prefix_over_https() {
        // SEC5: HTTPS では `__Host-` 前置でオリジン束縛する。
        let policy = CookiePolicy::new(true, Some("example.com"));
        assert_eq!(
            policy.origin_bound_name("portal_csrf_id"),
            "__Host-portal_csrf_id"
        );
        // 前置した名前で発行しても、属性は `__Host-` の要件（Secure / Domain 無し / Path=/）を満たす。
        let issued = policy.set_local(&policy.origin_bound_name("portal_csrf_id"), "seed", 900);
        assert_eq!(
            issued,
            "__Host-portal_csrf_id=seed; Max-Age=900; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        // 平文 HTTP ではブラウザが `__Host-` を拒否するため前置しない（開発環境）。
        assert_eq!(
            CookiePolicy::new(false, None).origin_bound_name("portal_csrf_id"),
            "portal_csrf_id"
        );
    }

    #[test]
    fn local_cookie_never_gets_the_domain_attribute() {
        // CSRF・言語・MFA チケットは host-only。旧 Domain 掃除の対象でもない。
        let policy = CookiePolicy::new(true, Some("example.com"));
        assert_eq!(
            policy.set_local("portal_csrf_id", "v", 600),
            "portal_csrf_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!policy.expire_local("portal_csrf_id").contains("Domain="));
    }

    #[test]
    fn session_cookie_is_host_only_by_default() {
        // COOKIE_DOMAIN 未設定（既定。ADR-0018 決定 4）: host-only の 1 本のみ。
        let policy = CookiePolicy::new(true, None);
        assert_eq!(
            policy.set_session(SSO_SESSION_COOKIE, "v", 600),
            vec!["sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"]
        );
        assert_eq!(
            CookiePolicy::new(false, None).expire_session(SSO_SESSION_COOKIE),
            vec!["sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"]
        );
    }

    #[test]
    fn session_cookie_never_carries_the_domain_attribute() {
        // ADR-0018 決定 2: COOKIE_DOMAIN が設定されていても、発行する Cookie 本体は host-only。
        // Domain は旧 Cookie の削除（Max-Age=0）にだけ現れる。
        let issued =
            CookiePolicy::new(true, Some("example.com")).set_session(SSO_SESSION_COOKIE, "v", 600);
        assert_eq!(
            issued,
            vec![
                "sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Domain=example.com; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
        // 失効も host-only 削除 + 旧 Domain 削除の併送。
        assert_eq!(
            CookiePolicy::new(false, Some("example.com")).expire_session(AUTH_SESSION_COOKIE),
            vec![
                "auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
                "auth_session_id=; Max-Age=0; Domain=example.com; Path=/; HttpOnly; SameSite=Lax",
            ]
        );
    }

    #[test]
    fn session_cookie_is_readable_back_by_the_same_name() {
        // 発行 → ブラウザ → 読み出しの往復で名前が一致する（発行と読取の名前ずれ防止）。
        let issued =
            CookiePolicy::new(false, None).set_session(SSO_SESSION_COOKIE, "session-value", 600);
        let sent_back = issued[0].split(';').next().unwrap();
        assert_eq!(
            read([sent_back], SSO_SESSION_COOKIE).as_deref(),
            Some("session-value")
        );
    }
}
