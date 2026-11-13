//! Startup validation of `COOKIE_DOMAIN` (introduced in ADR-0012, repurposed by decision 4 of ADR-0018).
//!
//! Session cookies are always issued host-only, so this value is used only for deletion cookies that clean up
//! `Domain` cookies left in browsers by the old ADR-0012 setup. The validation conditions (parent domain
//! consistency, public suffix rejection) stay the same as the conditions for browsers to accept the deletion cookie.
//!
//! api and web must run the same validation, so like csrf it is shared in contracts.
//! The checks are the two points of ADR-0012 §Consequences:
//!
//! 1. `COOKIE_DOMAIN` is a parent domain of (or the same as) both the `ISSUER` and `PUBLIC_WEB_BASE_URL`
//!    hosts. Otherwise browsers reject the `Domain` cookie and you get a login loop.
//! 2. `COOKIE_DOMAIN` is not itself a public suffix (eTLD, e.g. `com`, `co.uk`). A public suffix can
//!    pass check 1, but browsers reject `Domain` cookies for public suffixes, so startup succeeds
//!    while no cookie is ever shared (decided with the Public Suffix List).

use url::Url;

/// Validates `COOKIE_DOMAIN` and returns the normalized value (leading `.` removed, lowercase).
///
/// `origins` are the public origins of the services sharing the cookie (`ISSUER`, `PUBLIC_WEB_BASE_URL`).
/// On validation failure, returns a message meant to abort startup as a configuration error (fail-fast).
///
/// Besides checks 1 and 2, **all origins must share the same scheme**. Each service derives the cookie's
/// `Secure` attribute independently from its own public origin scheme, so mixing https/http makes only one side
/// issue a `Secure` cookie, and the browser does not send it to the other (http) side: a login loop.
pub fn validate_cookie_domain(raw: &str, origins: &[&str]) -> Result<String, String> {
    // Per RFC 6265, a leading dot is ignored (`.example.com` and `example.com` are equivalent).
    let domain = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return Err("COOKIE_DOMAIN must not be empty".to_string());
    }
    if domain.contains(['/', ':', '?', '#', '@', ' ']) {
        return Err(format!(
            "COOKIE_DOMAIN must be a bare domain name (e.g. `example.com`), got `{raw}`"
        ));
    }

    // Check 1: it is a **proper parent domain** of every public origin's host.
    //
    // The same host is not allowed: RFC 6265 §5.3 cookie identity is (name, domain, path) and excludes the
    // host-only flag, so if `COOKIE_DOMAIN` is the host name itself, the cleanup `Domain` deletion
    // cookie (Max-Age=0) **overwrites and deletes the host-only session cookie issued at the same time**
    // (a login loop where the session vanishes every time; decision 4 of ADR-0018).
    // Also collect schemes and reject a mix (https/http) (prevents asymmetric `Secure` attributes).
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

    // Check 2: it is not itself a public suffix. A value with no registrable domain (eTLD+1) is
    // a suffix itself (`com`, `co.uk` etc.), and browsers reject the Domain cookie.
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
        // Leading dots and uppercase are normalized.
        assert_eq!(
            validate_cookie_domain(".Example.COM", ORIGINS).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn rejects_domain_equal_to_origin_host() {
        // The host name itself is not allowed: RFC 6265 cookie identity excludes the host-only flag, so
        // the cleanup Domain deletion cookie would overwrite and delete the host-only session cookie
        // (decision 4 of ADR-0018).
        let err =
            validate_cookie_domain("idp.example.com", &["https://idp.example.com"]).unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
        // Likewise rejected when the web host is given in a nested host setup (api is a child of web).
        let err = validate_cookie_domain(
            "idp.example.com",
            &["https://api.idp.example.com", "https://idp.example.com"],
        )
        .unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
    }

    #[test]
    fn rejects_domain_not_parent_of_an_origin() {
        // A parent of only one origin breaks every login flow.
        let err = validate_cookie_domain("other.com", ORIGINS).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
        // A substring match (`ample.com`) is not a parent domain.
        let err = validate_cookie_domain("ample.com", ORIGINS).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
    }

    #[test]
    fn rejects_a_sibling_host_of_the_other_origin() {
        // A likely mix-up in practice: setting one host name (`api.example.com`) as COOKIE_DOMAIN as is.
        // Caught by the same-host rejection (preventing the deletion cookie from destroying itself).
        let err = validate_cookie_domain("api.example.com", ORIGINS).unwrap_err();
        assert!(err.contains("equals the host"), "{err}");
        // Regardless of origin order, a value that is not a parent of the other one is also rejected.
        let err =
            validate_cookie_domain("id.example.com", &["https://api.example.com"]).unwrap_err();
        assert!(err.contains("not a parent domain"), "{err}");
    }

    #[test]
    fn rejects_public_suffix() {
        // `com` passes check 1 as a parent of both hosts, but is rejected as a public suffix.
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
        // Only the https side issues a Secure cookie and it is not sent to the http side (login loop),
        // so a scheme mix with COOKIE_DOMAIN set is rejected at startup.
        let err = validate_cookie_domain(
            "example.com",
            &["https://api.example.com", "http://id.example.com"],
        )
        .unwrap_err();
        assert!(err.contains("mix schemes"), "{err}");
        // With the same scheme, both http pairs (local/test setups) and https pairs are accepted.
        assert!(validate_cookie_domain(
            "example.com",
            &["http://api.example.com", "http://id.example.com"],
        )
        .is_ok());
    }
}
