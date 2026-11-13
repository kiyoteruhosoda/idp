//! Parents allowed to frame (iframe) the no-screen round trip (`prompt=none`) (task #888, ADR-0076).
//!
//! Each app keeps an expired login going by querying `/authorize?prompt=none` in a hidden frame.
//! Only the responses of that round trip (the 302 of api's `/authorize` and of web's `/login?auth_session=`)
//! get a CSP allowing framing by the parents listed in `SILENT_AUTH_FRAME_ANCESTORS`. Every other screen
//! keeps `frame-ancestors 'none'` and `X-Frame-Options: DENY` as before.
//!
//! Lives in contracts so api and web run the same check (like `cookie_domain`).
//!
//! Only space-separated `https://<name>` and `https://*.<name>` (ports allowed) may be written.
//! Keywords like `*` and `'self'`, paths, and `http` (only `localhost` is allowed, for development) are rejected.
//! After `*.` there must be 2 or more labels (`*.com` is rejected).

use url::Url;

/// The list of parents that passed the check. Empty means framing is not allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameAncestors(Vec<String>);

impl FrameAncestors {
    /// Framing not allowed (default).
    pub fn none() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// CSP to put on the response (`frame-ancestors …`). `None` (not added) when empty.
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

/// Checks `SILENT_AUTH_FRAME_ANCESTORS`. If even one entry is invalid, rejects the whole value (stops startup).
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
    // Parse the rest after removing `*.` as a normal URL (also check there is no path, query or userinfo)
    let Ok(url) = Url::parse(&format!("{scheme}://{host_and_port}")) else {
        return refuse("is not an origin");
    };
    let Some(host) = url.host_str() else {
        return refuse("has no host");
    };
    // `*` only as the leading `*.` (`https://*` and `https://a.*.com` are rejected)
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
