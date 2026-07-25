//! `COOKIE_DOMAIN`（サービス横断 Cookie の `Domain` 属性）の起動時検証（ADR-0012）。
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

    // 検証 1: 各公開オリジンのホストの親ドメイン（または同一）であること。
    for origin in origins {
        let host = Url::parse(origin)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .ok_or_else(|| format!("cannot parse origin `{origin}` to validate COOKIE_DOMAIN"))?;
        let matches = host == domain || host.ends_with(&format!(".{domain}"));
        if !matches {
            return Err(format!(
                "COOKIE_DOMAIN `{domain}` is not a parent domain of `{host}` (from `{origin}`); \
                 browsers reject such Domain cookies and every login would loop. \
                 api and web must be subdomains of the same registrable domain (ADR-0012)"
            ));
        }
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
    fn accepts_domain_equal_to_origin_host() {
        // 単一オリジン相当（host-only と同じ到達範囲）でも設定自体は許容する。
        assert_eq!(
            validate_cookie_domain("idp.example.com", &["https://idp.example.com"]).unwrap(),
            "idp.example.com"
        );
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
}
