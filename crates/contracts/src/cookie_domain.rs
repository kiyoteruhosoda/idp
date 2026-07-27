//! `COOKIE_DOMAIN` の起動時検証（ADR-0012 で導入、ADR-0018 決定 4 で用途変更）。
//!
//! セッション Cookie は常に host-only で発行されるため、本値は旧 ADR-0012 構成でブラウザに残った
//! `Domain` 付き Cookie を掃除する削除 Cookie にだけ使う。検証条件（親ドメイン整合・public suffix
//! 拒否）は削除 Cookie がブラウザに受理されるための条件として同じに保つ。
//!
//! api と web が同一の検証を行う必要があるため、csrf と同様に contracts で共有する。
//! 検証内容は ADR-0012 §Consequences の 2 点:
//!
//! 1. `COOKIE_DOMAIN` が `ISSUER`・`PUBLIC_WEB_BASE_URL` 双方のホストの親ドメイン（または同一）で
//!    あること。そうでない構成はブラウザが `Domain` Cookie を拒否し、ログインループになる。
//! 2. `COOKIE_DOMAIN` が public suffix（eTLD。例 `com`・`co.uk`）そのものでないこと。public suffix は
//!    検証 1 を通過しうるが、ブラウザは public suffix への `Domain` Cookie を拒否するため、
//!    起動は成功するのに Cookie が一切共有されない障害になる（Public Suffix List で判定）。

use url::Url;

/// `COOKIE_DOMAIN` を検証し、正規化した値（先頭 `.` 除去・小文字）を返す。
///
/// `origins` には Cookie を共有するサービスの公開オリジン（`ISSUER`・`PUBLIC_WEB_BASE_URL`）を
/// 渡す。検証失敗時は構成エラーとして起動を中止する想定のメッセージを返す（fail-fast）。
///
/// 検証 1・2 に加え、**全オリジンのスキーム一致**も要求する。各サービスは Cookie の `Secure` 属性を
/// 自身の公開オリジンのスキームから独立に導出するため、https/http が混在すると片側だけが
/// `Secure` Cookie を発行し、もう片側（http）へブラウザが Cookie を送信せずログインループになる。
pub fn validate_cookie_domain(raw: &str, origins: &[&str]) -> Result<String, String> {
    // RFC 6265 に従い先頭のドットは無視する（`.example.com` と `example.com` は同義）。
    let domain = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err("COOKIE_DOMAIN must not be empty".to_string());
    }
    if domain.contains(['/', ':', '?', '#', '@', ' ']) {
        return Err(format!(
            "COOKIE_DOMAIN must be a bare domain name (e.g. `example.com`), got `{raw}`"
        ));
    }

    // 検証 1: 各公開オリジンのホストの**真の親ドメイン**であること。
    //
    // 同一ホストは不可: RFC 6265 §5.3 の Cookie 同一性は (name, domain, path) で決まり host-only
    // フラグを含まないため、`COOKIE_DOMAIN` がホスト名そのものだと、掃除用の `Domain` 付き削除
    // Cookie（Max-Age=0）が**同時に発行した host-only セッション Cookie を上書き削除**してしまう
    // （毎回セッションが消えるログインループ。ADR-0018 決定 4）。
    // あわせてスキームを収集し、混在（https/http）を拒否する（`Secure` 属性の非対称化を防ぐ）。
    let mut schemes: Vec<String> = Vec::new();
    for origin in origins {
        let url = Url::parse(origin)
            .map_err(|_| format!("cannot parse origin `{origin}` to validate COOKIE_DOMAIN"))?;
        let host = url
            .host_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| format!("cannot parse origin `{origin}` to validate COOKIE_DOMAIN"))?;
        if host == domain {
            return Err(format!(
                "COOKIE_DOMAIN `{domain}` equals the host of `{origin}`; the legacy-cleanup \
                 deletion cookie would also delete the freshly issued host-only session cookie \
                 (RFC 6265 treats them as the same cookie) and every login would loop. \
                 Set the OLD parent domain being cleaned up, or unset COOKIE_DOMAIN (ADR-0018)"
            ));
        }
        if !host.ends_with(&format!(".{domain}")) {
            return Err(format!(
                "COOKIE_DOMAIN `{domain}` is not a parent domain of `{host}` (from `{origin}`); \
                 browsers reject such Domain cookies, so the legacy-cleanup deletion cookie \
                 would never be accepted. \
                 api and web must be subdomains of the same registrable domain (ADR-0018)"
            ));
        }
        schemes.push(url.scheme().to_ascii_lowercase());
    }
    if schemes.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(format!(
            "COOKIE_DOMAIN is set but the shared-cookie origins mix schemes ({origins:?}); \
             each service derives the cookie `Secure` attribute from its own origin, so a \
             Secure cookie issued by the https side is never sent to the http side and every \
             login would loop. Use the same scheme (https) for both ISSUER and \
             PUBLIC_WEB_BASE_URL (ADR-0012)"
        ));
    }

    // 検証 2: public suffix そのものではないこと。登録可能ドメイン（eTLD+1）が取れない値は
    // suffix そのもの（`com`・`co.uk` 等）であり、ブラウザが Domain Cookie を拒否する。
    if psl::domain(domain.as_bytes()).is_none() {
        return Err(format!(
            "COOKIE_DOMAIN `{domain}` is a public suffix (eTLD); browsers reject Domain cookies \
             on public suffixes, so cookies would never be shared. Use a registrable domain \
             like `example.com` (ADR-0012)"
        ));
    }

    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINS: &[&str] = &["https://api.example.com", "https://id.example.com"];

    #[test]
    fn accepts_parent_domain_of_both_origins() {
        assert_eq!(
            validate_cookie_domain("example.com", ORIGINS).unwrap(),
            "example.com"
        );
        // 先頭ドット・大文字は正規化する。
        assert_eq!(
            validate_cookie_domain(".Example.COM", ORIGINS).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn rejects_domain_equal_to_origin_host() {
        // ホスト名そのものは不可: RFC 6265 の Cookie 同一性は host-only フラグを含まないため、
        // 掃除用の Domain 付き削除 Cookie が host-only セッション Cookie を上書き削除してしまう
        // （ADR-0018 決定 4）。
        let err =
            validate_cookie_domain("idp.example.com", &["https://idp.example.com"]).unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
        // 入れ子ホスト構成（api が web の子）で web ホストを指定した場合も同様に拒否する。
        let err = validate_cookie_domain(
            "idp.example.com",
            &["https://api.idp.example.com", "https://idp.example.com"],
        )
        .unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
    }

    #[test]
    fn rejects_domain_not_parent_of_an_origin() {
        // 片方のオリジンだけの親では全ログインフローが壊れる。
        let err = validate_cookie_domain("other.com", ORIGINS).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
        // 部分文字列一致（`ample.com`）は親ドメインではない。
        let err = validate_cookie_domain("ample.com", ORIGINS).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
    }

    #[test]
    fn rejects_a_sibling_host_of_the_other_origin() {
        // 実際に起きやすい取り違え: 片方のホスト名（`api.example.com`）をそのまま COOKIE_DOMAIN に
        // 設定する構成。同一ホスト拒否（削除 Cookie の自壊防止）に掛かる。
        let err = validate_cookie_domain("api.example.com", ORIGINS).unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
        // オリジンの順序に依らず、もう片方の親でない値も拒否される。
        let err =
            validate_cookie_domain("id.example.com", &["https://api.example.com"]).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
    }

    #[test]
    fn rejects_public_suffix() {
        // `com` は両ホストの親として検証 1 を通るが、public suffix なので拒否する。
        let err = validate_cookie_domain("com", ORIGINS).unwrap_err();
        assert!(err.contains("public suffix"), "{err}");
        let err = validate_cookie_domain(
            "co.uk",
            &["https://api.example.co.uk", "https://id.example.co.uk"],
        )
        .unwrap_err();
        assert!(err.contains("public suffix"), "{err}");
    }

    #[test]
    fn rejects_empty_and_malformed_values() {
        assert!(validate_cookie_domain("", ORIGINS).is_err());
        assert!(validate_cookie_domain(".", ORIGINS).is_err());
        assert!(validate_cookie_domain("example.com/path", ORIGINS).is_err());
        assert!(validate_cookie_domain("example.com:8080", ORIGINS).is_err());
    }

    #[test]
    fn rejects_when_origin_is_unparsable() {
        assert!(validate_cookie_domain("example.com", &["not a url"]).is_err());
    }

    #[test]
    fn rejects_mixed_schemes_between_shared_cookie_origins() {
        // https 側だけが Secure Cookie を発行し、http 側へは送信されない（ログインループ）ため、
        // COOKIE_DOMAIN 設定時のスキーム混在は起動時に拒否する。
        let err = validate_cookie_domain(
            "example.com",
            &["https://api.example.com", "http://id.example.com"],
        )
        .unwrap_err();
        assert!(err.contains("mix schemes"), "{err}");
        // 同一スキームなら http 同士（ローカル・テスト構成）も https 同士も受理する。
        assert!(validate_cookie_domain(
            "example.com",
            &["http://api.example.com", "http://id.example.com"],
        )
        .is_ok());
    }
}
