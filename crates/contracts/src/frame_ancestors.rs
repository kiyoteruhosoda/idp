//! 画面を出さずに試す往復（`prompt=none`）を、枠（iframe）に入れてよい親（task #888・ADR-0076）。
//!
//! 各アプリは切れたログインを、見えない枠で `/authorize?prompt=none` へ問い合わせて続ける。
//! その往復の応答（api の `/authorize` と web の `/login?auth_session=` の 302）にだけ、
//! `SILENT_AUTH_FRAME_ANCESTORS` に書いた親からの枠を許す CSP を付ける。ほかの画面は今までどおり
//! `frame-ancestors 'none'`・`X-Frame-Options: DENY`。
//!
//! api と web が同じ検査を通すため contracts に置く（`cookie_domain` と同じ）。
//!
//! 書けるのは `https://<名前>` と `https://*.<名前>`（ポート付きも可）を空白で区切ったものだけ。
//! `*`・`'self'` などのキーワード・パス・`http`（`localhost` だけは開発のため許す）は断る。
//! `*.` の後ろは 2 段以上（`*.com` は断る）。

use url::Url;

/// 検査を通った親の並び。空なら枠を許さない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameAncestors(Vec<String>);

impl FrameAncestors {
    /// 枠を許さない（既定）。
    pub fn none() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 応答に付ける CSP（`frame-ancestors …`）。空なら `None`（付けない）。
    pub fn content_security_policy(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(format!("frame-ancestors {}", self.0.join(" ")))
    }

    pub fn sources(&self) -> &[String] {
        &self.0
    }
}

/// `SILENT_AUTH_FRAME_ANCESTORS` を検査する。1 つでも書けないものがあれば全体を断る（起動を止める）。
pub fn parse_frame_ancestors(raw: &str) -> Result<FrameAncestors, String> {
    raw.split_whitespace()
        .map(parse_source)
        .collect::<Result<Vec<_>, _>>()
        .map(FrameAncestors)
}

fn parse_source(raw: &str) -> Result<String, String> {
    let refuse = |why: &str| {
        Err(format!(
            "SILENT_AUTH_FRAME_ANCESTORS: `{raw}` {why} (write `https://*.example.com` or `https://app.example.com`)"
        ))
    };
    let Some((scheme, rest)) = raw.split_once("://") else {
        return refuse("is not an origin");
    };
    let (wildcard, host_and_port) = match rest.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    // `*.` を外した残りをふつうの URL として読む（パス・クエリ・利用者情報が無いことも見る）
    let Ok(url) = Url::parse(&format!("{scheme}://{host_and_port}")) else {
        return refuse("is not an origin");
    };
    let Some(host) = url.host_str() else {
        return refuse("has no host");
    };
    // `*` は先頭の `*.` だけ（`https://*` や `https://a.*.com` は断る）
    if host.contains('*') {
        return refuse("is too broad");
    }
    if url.path() != "/"
        || host_and_port.ends_with('/')
        || url.query().is_some()
        || !url.username().is_empty()
    {
        return refuse("must not carry a path");
    }
    let local = host == "localhost" || host == "127.0.0.1";
    match url.scheme() {
        "https" => {}
        "http" if local && !wildcard => {}
        _ => return refuse("must be https"),
    }
    if wildcard && host.split('.').count() < 2 {
        return refuse("is too broad");
    }
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let star = if wildcard { "*." } else { "" };
    Ok(format!("{}://{star}{host}{port}", url.scheme()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomains_of_a_registered_name_are_accepted() {
        let parsed = parse_frame_ancestors("https://*.nolumia.com").unwrap();
        assert_eq!(
            parsed.content_security_policy().as_deref(),
            Some("frame-ancestors https://*.nolumia.com")
        );
    }

    #[test]
    fn several_origins_are_joined() {
        let parsed =
            parse_frame_ancestors(" https://*.nolumia.com  https://app.example.com:8443 ").unwrap();
        assert_eq!(
            parsed.sources(),
            ["https://*.nolumia.com", "https://app.example.com:8443"]
        );
    }

    #[test]
    fn empty_means_no_frame() {
        let parsed = parse_frame_ancestors("").unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.content_security_policy(), None);
    }

    #[test]
    fn plain_http_is_only_for_localhost() {
        assert!(parse_frame_ancestors("http://localhost:5173").is_ok());
        assert!(parse_frame_ancestors("http://app.example.com").is_err());
        assert!(parse_frame_ancestors("http://*.localhost").is_err());
    }

    #[test]
    fn broad_or_odd_sources_are_refused() {
        for raw in [
            "*",
            "'self'",
            "'none'",
            "https://*",
            "https://*.com",
            "nolumia.com",
            "https://app.example.com/path",
            "https://app.example.com/",
            "https://user@app.example.com",
            "https://app.example.com?x=1",
            "javascript://x",
        ] {
            assert!(parse_frame_ancestors(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn one_bad_source_refuses_the_whole_setting() {
        assert!(parse_frame_ancestors("https://*.nolumia.com *").is_err());
    }
}
