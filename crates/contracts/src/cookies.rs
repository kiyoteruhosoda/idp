//! Cookie names and building `Set-Cookie` values (api <-> web contract).
//!
//! Per decision 2 of ADR-0018, **api does not read or write browser cookies**. `sso_session_id` /
//! `auth_session_id` became host-only cookies issued and read only by web toward the browser, but the
//! names remain a contract (web's `api_client` explicitly sends `Cookie: sso_session_id=...` in server-to-server
//! calls to the admin JSON API, and api's admin extractor reads the same name).
//! Building names and attributes is defined once in this crate, like csrf and cookie_domain, and web uses it.
//!
//! Per design spec §2.4, the attributes are `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/`
//! (`Secure` is decided by web from its own public origin scheme; ADR-0012 §2).
//! No `Domain` is set (host-only is the default; decision 4 of ADR-0018). `COOKIE_DOMAIN` remains only
//! to clean up `Domain` cookies left in browsers by the old setup of ADR-0012 §3
//! (see [`CookiePolicy`]).
//!
//! No dependency on axum (a constraint of this crate). Reading from `HeaderMap` and turning into `Set-Cookie` headers
//! are done by each service's `cookies` module as a thin adapter.

/// SSO session cookie (the value is the plain session_id; only the hash is stored in the DB). Only web issues and reads
/// it toward the browser; it is passed to api in a server-to-server header (admin API) or body (`/internal/*`).
pub const SSO_SESSION_COOKIE: &str = "sso_session_id";
/// `auth_session_id` cookie (short-lived, from the `/authorize` handoff to `/login` completion). Read only by web.
pub const AUTH_SESSION_COOKIE: &str = "auth_session_id";

/// Session cookies prefixed with `__Host-` when `Secure` (task #583; medium-3 of the 2026-10-20 vulnerability review).
///
/// Without the prefix, an attacker holding another subdomain of the same parent (any of `*.nolumia.com`) could
/// inject a same-name cookie with `Domain=nolumia.com; Path=/<tenant>`, and since longer-Path cookies are sent first,
/// the attacker's session would win (logging the victim into the attacker's account, disrupting the session).
/// ⚠ **The names stay the contract** (server-to-server calls to api pass the unprefixed name). The prefix applies
/// only toward the browser, and the receiver maps it with [`CookiePolicy::bind_session_cookie_names`].
pub const ORIGIN_BOUND_SESSION_COOKIES: &[&str] = &[SSO_SESSION_COOKIE, AUTH_SESSION_COOKIE];

/// The `__Host-` prefix (RFC 6265bis §4.1.3.2). Browsers accept a cookie sent with this name only if it is
/// "`Secure`, without `Domain`, and `Path=/`". As a result it is **bound to the issuing origin**,
/// and cannot be overwritten or forced from another subdomain of the same parent (where `Domain=parent` could be set).
pub const HOST_PREFIX: &str = "__Host-";

/// Extracts the value of `name` from raw `Cookie` header strings (multiple headers allowed).
///
/// Names are compared exactly (`sso_session_id` does not match `x_sso_session_id`). For cookies whose value contains
/// `=` (base64 etc.), only the first `=` is treated as the separator.
pub fn read<'a>(raw_headers: impl IntoIterator<Item = &'a str>, name: &str) -> Option<String> {
    raw_headers.into_iter().find_map(|raw| {
        raw.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

/// Policy for cookie attributes (`Secure` and cleanup of old `Domain` cookies). Built once from settings and reused.
///
/// Decisions 2 and 4 of ADR-0018: session cookies (`sso_session_id`, `auth_session_id`) are **always issued
/// host-only**. If `legacy_cleanup_domain` (`COOKIE_DOMAIN`) is set, a cookie deleting the same-name `Domain` cookie
/// left in browsers by the old setup of ADR-0012 §3 is sent along (a cookie's identity includes `Domain`, not just
/// the name, so unless actively deleted, the old session hides the new one through double sending). Once cleanup
/// is done in an environment, leave `COOKIE_DOMAIN` unset (the default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePolicy {
    secure: bool,
    legacy_cleanup_domain: Option<String>,
}

impl CookiePolicy {
    /// `secure` derives from this service's public origin scheme; `legacy_cleanup_domain` is `COOKIE_DOMAIN`
    /// (a validated value; [`crate::cookie_domain::validate_cookie_domain`]).
    pub fn new(secure: bool, legacy_cleanup_domain: Option<&str>) -> Self {
        Self {
            secure,
            legacy_cleanup_domain: legacy_cleanup_domain.map(str::to_string),
        }
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    /// The old `Domain` to clean up (`COOKIE_DOMAIN`). `None` = no cleanup (default).
    pub fn legacy_cleanup_domain(&self) -> Option<&str> {
        self.legacy_cleanup_domain.as_deref()
    }

    /// The set of `Set-Cookie` values issuing a session cookie (`sso_session_id`, `auth_session_id`).
    ///
    /// - Always issues one host-only cookie (no `Domain`; decisions 2 and 4 of ADR-0018).
    /// - When `COOKIE_DOMAIN` is set (migration period from the old ADR-0012 setup): also sends a same-name
    ///   deletion cookie (`Max-Age=0`) with the `Domain` attribute to clean up the old cookie left in the browser.
    ///
    /// When `Secure`, [`ORIGIN_BOUND_SESSION_COOKIES`] are issued with the `__Host-` prefixed name, and a deletion
    /// cookie is sent along to remove the same-name unprefixed cookie (issued before prefixing).
    pub fn set_session(&self, name: &str, value: &str, max_age_secs: u64) -> Vec<String> {
        let bound = self.origin_bound_session_name(name);
        let mut cookies = vec![build(&bound, value, max_age_secs, self.secure, None)];
        if bound != name {
            cookies.push(build(name, "", 0, self.secure, None));
        }
        if let Some(domain) = self.legacy_cleanup_domain.as_deref() {
            cookies.push(build(name, "", 0, self.secure, Some(domain)));
        }
        cookies
    }

    /// The set of `Set-Cookie` values expiring the session cookie. Deletion cookies have the same shape as issuance
    /// (host-only), plus, when `COOKIE_DOMAIN` is set, an old `Domain` deletion (cookies with a different `Domain`
    /// are not removed otherwise).
    pub fn expire_session(&self, name: &str) -> Vec<String> {
        self.set_session(name, "", 0)
    }

    /// The session cookie's name in the browser (`__Host-` prefixed when `Secure`; task #583).
    fn origin_bound_session_name(&self, name: &str) -> String {
        if self.secure && ORIGIN_BOUND_SESSION_COOKIES.contains(&name) {
            format!("{HOST_PREFIX}{name}")
        } else {
            name.to_string()
        }
    }

    /// Returns the received `Cookie` header with session cookie names mapped (task #583).
    ///
    /// Works only when `Secure`: maps `__Host-sso_session_id` to `sso_session_id` and **drops an unprefixed
    /// `sso_session_id`** (an unprefixed name can be injected from another subdomain; cookies issued before
    /// prefixing are treated the same, and that person logs in once more). Readers can read by the contract name as is.
    /// `None` when there is nothing to change (not `Secure`, or no relevant cookie).
    pub fn bind_session_cookie_names<'a>(
        &self,
        raw_headers: impl IntoIterator<Item = &'a str>,
    ) -> Option<String> {
        if !self.secure {
            return None;
        }
        let mut changed = false;
        let mut pairs = Vec::new();
        for pair in raw_headers
            .into_iter()
            .flat_map(|raw| raw.split(';'))
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
        {
            let name = pair.split_once('=').map_or(pair, |(k, _)| k);
            if ORIGIN_BOUND_SESSION_COOKIES.contains(&name) {
                changed = true;
                continue;
            }
            match name.strip_prefix(HOST_PREFIX) {
                Some(base) if ORIGIN_BOUND_SESSION_COOKIES.contains(&base) => {
                    changed = true;
                    pairs.push(pair[HOST_PREFIX.len()..].to_string());
                }
                _ => pairs.push(pair.to_string()),
            }
        }
        changed.then(|| pairs.join("; "))
    }

    /// `Set-Cookie` value issuing a service-local cookie (CSRF, language, MFA ticket etc.).
    /// Host-only like session cookies, but not subject to the old `Domain` cleanup.
    pub fn set_local(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        build(name, value, max_age_secs, self.secure, None)
    }

    /// `Set-Cookie` value issuing a display setting cookie readable by page scripts (no `HttpOnly`).
    ///
    /// **Dropping `HttpOnly` is limited to this use.** Unless the color scheme is fixed before the first paint, the
    /// screen flickers from white to black, so a synchronous script in `<head>` must read it itself. It can carry
    /// only `light` / `dark` / `system`, neither a value harmful if stolen nor one that shifts permissions if
    /// rewritten (only the colors change; the server uses it for no decision). Never issue credentials or session
    /// identifiers with this function.
    pub fn set_preference(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        build_preference(name, value, max_age_secs, self.secure)
    }

    /// `Set-Cookie` value expiring a service-local cookie.
    pub fn expire_local(&self, name: &str) -> String {
        self.set_local(name, "", 0)
    }

    /// A local cookie that must arrive even with a POST from another site (`SameSite=None`).
    ///
    /// **Used only for an external SAML IdP's ACS** (task #581). The other IdP carries the assertion with a
    /// **cross-site POST** through the browser, so a `SameSite=Lax` cookie is not
    /// sent. The value is a one-time random showing "started in this browser" and carries no permission.
    /// ⚠ Browsers do not accept `SameSite=None` without `Secure`, so over plain HTTP (development) it
    /// falls back to `Lax` (SAML ACS does not work there, but the OIDC return does).
    pub fn set_cross_site_local(&self, name: &str, value: &str, max_age_secs: u64) -> String {
        if !self.secure {
            return self.set_local(name, value, max_age_secs);
        }
        format!("{name}={value}; Max-Age={max_age_secs}; Path=/; HttpOnly; SameSite=None; Secure")
    }

    /// Expires the cookie set with [`Self::set_cross_site_local`].
    pub fn expire_cross_site_local(&self, name: &str) -> String {
        self.set_cross_site_local(name, "", 0)
    }

    /// Returns the real name of a local cookie needing origin binding (CSRF seed, MFA ticket, SAML progress state)
    /// (SEC5). The attributes `set_local` / `expire_local` add already meet the `__Host-` requirements (`Secure` /
    /// no `Domain` / `Path=/`), so only the name needs the prefix.
    ///
    /// **No prefix over plain HTTP (`secure == false`).** Browsers refuse to store `__Host-` cookies
    /// without `Secure`, so prefixing would mean no CSRF seed is ever stored in development (`http://localhost`)
    /// and login becomes impossible. Production is always HTTPS (`COOKIE_SECURE`), so the protection applies.
    pub fn origin_bound_name(&self, base_name: &str) -> String {
        if self.secure {
            format!("{HOST_PREFIX}{base_name}")
        } else {
            base_name.to_string()
        }
    }
}

/// A cookie readable by scripts (no `HttpOnly`). Attributes match [`build`].
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
        // Partial matches are not picked up (`sso_session_id` does not match `x_sso_session_id`).
        assert_eq!(read(["x_sso_session_id=other"], "sso_session_id"), None);
        assert_eq!(read(["sso_session_id_2=other"], "sso_session_id"), None);
    }

    #[test]
    fn reads_a_cookie_across_multiple_headers() {
        // Browsers and proxies may split the `Cookie` header into several.
        assert_eq!(
            read(["a=1", "sso_session_id=xyz"], "sso_session_id").as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn keeps_values_containing_equals_signs() {
        // Trailing padding (`=`) of base64 values is not cut off.
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

    /// Over HTTPS, only the prefixed name is read as the contract name. An unprefixed same name (injectable
    /// from another subdomain) is dropped (task #583).
    #[test]
    fn session_cookie_names_are_bound_to_the_origin_over_https() {
        let policy = CookiePolicy::new(true, None);
        assert_eq!(
            policy.bind_session_cookie_names([
                "sso_session_id=planted; lang=ja",
                "__Host-sso_session_id=mine; __Host-auth_session_id=a",
            ]),
            Some("lang=ja; sso_session_id=mine; auth_session_id=a".to_string())
        );
        // If only an injected cookie exists, it is the same as not being logged in.
        assert_eq!(
            policy.bind_session_cookie_names(["sso_session_id=planted"]),
            Some(String::new())
        );
        // Without a session cookie, nothing is touched.
        assert_eq!(policy.bind_session_cookie_names(["lang=ja"]), None);
        // Plain HTTP (development) has no prefix, so nothing is mapped.
        assert_eq!(
            CookiePolicy::new(false, None).bind_session_cookie_names(["sso_session_id=v"]),
            None
        );
    }

    #[test]
    fn cross_site_local_cookie_is_same_site_none_only_over_https() {
        assert_eq!(
            CookiePolicy::new(true, None).set_cross_site_local("__Host-b", "v", 600),
            "__Host-b=v; Max-Age=600; Path=/; HttpOnly; SameSite=None; Secure"
        );
        // Over plain HTTP, None cannot be set (browsers drop it), so it falls back to Lax.
        assert_eq!(
            CookiePolicy::new(false, None).expire_cross_site_local("b"),
            "b=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn origin_bound_names_carry_the_host_prefix_over_https() {
        // SEC5: over HTTPS, origin-bind with the `__Host-` prefix.
        let policy = CookiePolicy::new(true, Some("example.com"));
        assert_eq!(
            policy.origin_bound_name("portal_csrf_id"),
            "__Host-portal_csrf_id"
        );
        // Even issued with the prefixed name, the attributes meet the `__Host-` requirements (Secure / no Domain / Path=/).
        let issued = policy.set_local(&policy.origin_bound_name("portal_csrf_id"), "seed", 900);
        assert_eq!(
            issued,
            "__Host-portal_csrf_id=seed; Max-Age=900; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        // Over plain HTTP browsers reject `__Host-`, so no prefix (development).
        assert_eq!(
            CookiePolicy::new(false, None).origin_bound_name("portal_csrf_id"),
            "portal_csrf_id"
        );
    }

    #[test]
    fn local_cookie_never_gets_the_domain_attribute() {
        // CSRF, language and MFA ticket are host-only, and not subject to the old Domain cleanup.
        let policy = CookiePolicy::new(true, Some("example.com"));
        assert_eq!(
            policy.set_local("portal_csrf_id", "v", 600),
            "portal_csrf_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure"
        );
        assert!(!policy.expire_local("portal_csrf_id").contains("Domain="));
    }

    #[test]
    fn session_cookie_is_host_only_by_default() {
        // COOKIE_DOMAIN unset (default; decision 4 of ADR-0018): host-only. Over HTTPS, prefix with `__Host-` and
        // delete old cookies with the unprefixed name (task #583).
        let policy = CookiePolicy::new(true, None);
        assert_eq!(
            policy.set_session(SSO_SESSION_COOKIE, "v", 600),
            vec![
                "__Host-sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
        assert_eq!(
            CookiePolicy::new(false, None).expire_session(SSO_SESSION_COOKIE),
            vec!["sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"]
        );
    }

    #[test]
    fn session_cookie_never_carries_the_domain_attribute() {
        // Decision 2 of ADR-0018: even with COOKIE_DOMAIN set, the issued cookie itself is host-only.
        // Domain appears only in deleting the old cookie (Max-Age=0).
        let issued =
            CookiePolicy::new(true, Some("example.com")).set_session(SSO_SESSION_COOKIE, "v", 600);
        assert_eq!(
            issued,
            vec![
                "__Host-sso_session_id=v; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Domain=example.com; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
        // Expiry also sends host-only deletion + old Domain deletion together.
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
        // Names match in the issue -> browser -> read round trip (prevents name drift between issuing and reading).
        let issued =
            CookiePolicy::new(false, None).set_session(SSO_SESSION_COOKIE, "session-value", 600);
        let sent_back = issued[0].split(';').next().unwrap();
        assert_eq!(
            read([sent_back], SSO_SESSION_COOKIE).as_deref(),
            Some("session-value")
        );
    }
}
