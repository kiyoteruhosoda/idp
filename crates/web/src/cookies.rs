//! Reading and writing cookies (axum adapter).
//!
//! Names and building `Set-Cookie` values are a contract with the api, so they are defined once in [`assay_contracts::cookies`].
//! This module handles the axum-dependent parts: reading from `HeaderMap` and building the `Set-Cookie` headers
//! for responses ([`SetCookies`]).
//!
//! All browser cookies are host-only cookies issued and read only by web (ADR-0018 decision 2;
//! the api does not read browser cookies). [`SetCookies`] methods come in two kinds.
//!
//! - **Session** (`sso_session_id`, `auth_session_id`): `set_session` / `expire_session`.
//!   Includes cleaning up `Domain`-scoped cookies left in browsers by the old ADR-0012 setup (sending deletions alongside).
//! - **web-local** (`lang`, CSRF, MFA ticket): `set_local` / `expire_local`.
//!
//! Among web-local cookies, **the CSRF seed, MFA ticket and SAML progress state** get a `__Host-` prefixed name to
//! bind them to the origin (SEC5). Cookies are not isolated between subdomains, so an attacker who took over another
//! subdomain of the same parent domain could force a same-name cookie with `Domain=parent`, fixing the seed and forging
//! CSRF tokens. Name resolution is centralized in `WebState::origin_bound_cookie`, and reading
//! ([`get`]) and issuing ([`SetCookies::set_local`]) always use the same actual name.

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName};
use axum::response::AppendHeaders;

pub use assay_contracts::cookies::{CookiePolicy, AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};

/// CSRF cookie for the admin login form (an unguessable random value issued on GET; the synchronizer token's seed).
/// **Origin-bound** (`__Host-` prefixed via `WebState::origin_bound_cookie`. SEC5).
pub const ADMIN_CSRF_COOKIE: &str = "admin_csrf_id";
/// CSRF cookie for the end-user portal login form (same mechanism as `admin_csrf_id`, separate namespace).
/// **Origin-bound** (SEC5).
pub const PORTAL_CSRF_COOKIE: &str = "portal_csrf_id";
/// Cookie holding the `mfa_ticket` (signed short-lived ticket) during the portal's TOTP input step.
/// **Origin-bound** (SEC5).
pub const PORTAL_MFA_COOKIE: &str = "portal_mfa_ticket";
/// The "enrollment ticket" when signing in correctly from an unregistered device (task #916. 10 minutes. Set with an origin-bound name).
pub const DEVICE_ENROLLMENT_COOKIE: &str = "device_enrollment";
/// Cookie holding the SAML SSO progress state id. Used to return to the flow on successful login after
/// `/saml/continue` led to login because SSO was not established (web-local).
/// **Origin-bound** (SEC5).
pub const SAML_REQUEST_COOKIE: &str = "saml_request_id";
/// One-time value placed in the browser that started an external IdP login (task #581). Passed to the api at the
/// return endpoint (OIDC callback, SAML ACS) to confirm it is the starting browser. **Origin-bound** (`__Host-`),
/// `SameSite=None` so it also arrives at the SAML ACS (a cross-site POST).
pub const EXTERNAL_LOGIN_BINDING_COOKIE: &str = "external_login_binding";
/// Lifetime of [`EXTERNAL_LOGIN_BINDING_COOKIE`]. Aligned with the api's progress state lifetime (600 s).
pub const EXTERNAL_LOGIN_BINDING_MAX_AGE_SECS: u64 = 600;
/// One-time mark placed in the browser that started "Continue in the app" (task #892. ADR-0077). Passed to the api
/// with the code in the browser opened by the authenticator app to confirm it is the requesting browser. **Origin-bound** (`__Host-`),
/// `SameSite=Lax` (the navigation the app opens is a top-level GET, so it arrives).
pub const APP_APPROVAL_BINDING_COOKIE: &str = "app_approval_binding";
/// Lifetime of [`APP_APPROVAL_BINDING_COOKIE`]. Aligned with the api's request lifetime (300 s).
pub const APP_APPROVAL_BINDING_MAX_AGE_SECS: u64 = 300;
/// Reception identifier for returning to the authenticator app registration confirmation after login (task #892). **Origin-bound**.
pub const APP_APPROVER_ENROLLMENT_COOKIE: &str = "app_approver_enrollment";
/// Lifetime of [`APP_APPROVER_ENROLLMENT_COOKIE`]. Aligned with the api's reception lifetime (600 s).
pub const APP_APPROVER_ENROLLMENT_MAX_AGE_SECS: u64 = 600;
/// Cookie holding the display language choice (`ja` / `en`. MT15. Priority 3 in the decision chain).
pub const LANG_COOKIE: &str = "lang";
/// Retention of display setting cookies (language, color scheme) (default 1 year). Long-lived since they are UI settings.
pub const PREFERENCE_COOKIE_MAX_AGE_SECS: u64 = 31_536_000;
/// Cookie holding the color scheme choice (`light` / `dark` / `system`). **No `HttpOnly`**
/// (`assets/theme.js` reads it before the first paint; see `assay_contracts::cookies::set_preference` for why).
pub const THEME_COOKIE: &str = "theme";

/// Extracts the value of `name` from the request's `Cookie` header.
pub fn get(headers: &HeaderMap, name: &str) -> Option<String> {
    assay_contracts::cookies::read(
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
        name,
    )
}

/// Set of `Set-Cookie` headers for a response. Created from `WebState::set_cookies()`, built by chaining methods,
/// and returned as `AppendHeaders` (can be passed directly in an `IntoResponse` tuple).
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

    /// Issues a session cookie as host-only (when `COOKIE_DOMAIN` is set, also sends deletion of the old `Domain`-scoped
    /// cookie. ADR-0018 decision 2, 4).
    #[must_use]
    pub fn set_session(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.push_all(self.policy.set_session(name, value, max_age_secs));
        self
    }

    /// Expires a session cookie.
    #[must_use]
    pub fn expire_session(mut self, name: &str) -> Self {
        self.push_all(self.policy.expire_session(name));
        self
    }

    /// Issues a web-local cookie (host-only; no `Domain`).
    #[must_use]
    pub fn set_local(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.set_local(name, value, max_age_secs)));
        self
    }

    /// Issues a display setting cookie readable by screen scripts (color scheme; no `HttpOnly`).
    #[must_use]
    pub fn set_preference(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers.push((
            SET_COOKIE,
            self.policy.set_preference(name, value, max_age_secs),
        ));
        self
    }

    /// Issues a local cookie that also arrives on POSTs from other sites (for the external SAML IdP's ACS.
    /// `assay_contracts::cookies::CookiePolicy::set_cross_site_local`).
    #[must_use]
    pub fn set_cross_site_local(mut self, name: &str, value: &str, max_age_secs: u64) -> Self {
        self.headers.push((
            SET_COOKIE,
            self.policy.set_cross_site_local(name, value, max_age_secs),
        ));
        self
    }

    /// Expires a cookie set with [`Self::set_cross_site_local`].
    #[must_use]
    pub fn expire_cross_site_local(mut self, name: &str) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.expire_cross_site_local(name)));
        self
    }

    /// Expires a web-local cookie.
    #[must_use]
    pub fn expire_local(mut self, name: &str) -> Self {
        self.headers
            .push((SET_COOKIE, self.policy.expire_local(name)));
        self
    }

    /// `Set-Cookie` headers to attach to the response.
    pub fn into_headers(self) -> AppendHeaders<Vec<(HeaderName, String)>> {
        AppendHeaders(self.headers)
    }

    fn push_all(&mut self, cookies: Vec<String>) {
        self.headers
            .extend(cookies.into_iter().map(|cookie| (SET_COOKIE, cookie)));
    }
}

/// Middleware that maps the session cookie names in the incoming request's `Cookie` header (task #583).
///
/// Over HTTPS, session cookies are exchanged with the browser only under `__Host-` prefixed names
/// ([`CookiePolicy::bind_session_cookie_names`]). They are mapped back to the contract names here, so handlers
/// can keep reading [`SSO_SESSION_COOKIE`] / [`AUTH_SESSION_COOKIE`]. ⚠ Unprefixed same names are dropped.
pub async fn bind_session_cookie_names(
    policy: CookiePolicy,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let rebuilt = policy.bind_session_cookie_names(
        request
            .headers()
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    if let Some(rebuilt) = rebuilt {
        let headers = request.headers_mut();
        headers.remove(COOKIE);
        if !rebuilt.is_empty() {
            match axum::http::HeaderValue::from_str(&rebuilt) {
                Ok(value) => {
                    headers.insert(COOKIE, value);
                }
                Err(_) => {
                    // The original cookie contains non-ASCII etc. Treat the session as unreadable
                    // (do not pass the unprefixed name through).
                    tracing::warn!("could not rebuild the cookie header for the session cookies");
                }
            }
        }
    }
    next.run(request).await
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
        // Typical successful login: SSO issued + auth_session expired + language synced (ADR-0018 decision 2 / MT20).
        let set_cookies = SetCookies::new(CookiePolicy::new(true, None))
            .set_session(SSO_SESSION_COOKIE, "sess", 600)
            .expire_session(AUTH_SESSION_COOKIE)
            .set_local(LANG_COOKIE, "ja", PREFERENCE_COOKIE_MAX_AGE_SECS);
        assert_eq!(
            values(set_cookies),
            vec![
                "__Host-sso_session_id=sess; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure",
                "sso_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
                "__Host-auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
                "auth_session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
                "lang=ja; Max-Age=31536000; Path=/; HttpOnly; SameSite=Lax; Secure",
            ]
        );
    }

    #[test]
    fn session_cookies_stay_host_only_and_clean_up_the_legacy_domain() {
        // ADR-0018 decision 2, 4: the session cookie itself is always host-only. During the migration period with COOKIE_DOMAIN
        // set, deletion of the old `Domain`-scoped cookie is sent alongside. Local cookies such as CSRF are excluded.
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
