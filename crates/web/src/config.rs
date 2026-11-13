//! Settings of the web service (ADR-0007).
//!
//! web has no DB, so it has its own (small) settings separate from the api's. They are always obtained through this module,
//! and raw environment variables are not read directly anywhere else. The precedence is
//! **"default < environment variable (ENV) < DB override via the api"** (MT26 / ADR-0013).
//! (An empty string is treated as "unset"; the countermeasure for Compose's `${VAR:-}` follows the api config.)
//!
//! Only shared keys **consumed by both** the api and web take DB overrides via the api
//! (`ISSUER`, `COOKIE_SECURE`, `HSTS_MAX_AGE`, `AUTH_SESSION_TTL_SECS`). web-specific keys
//! (`WEB_BIND_ADDR`, `API_BASE_URL`), bootstrap secrets (`INTERNAL_SERVICE_TOKEN`,
//! `CSRF_SECRET`), and `PUBLIC_WEB_BASE_URL` / `COOKIE_DOMAIN`, which must match between api and web, stay ENV > default.
#![allow(dead_code)]

use assay_contracts::cookies::CookiePolicy;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::env;

/// Development default for the internal service auth token (same value as the api; ADR-0007 §5).
/// In production always set `INTERNAL_SERVICE_TOKEN` to a value shared with the api.
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";
/// Development default for the CSRF secret (same value as the api's `DEV_CSRF_SECRET`; 32 bytes).
/// In production always set `CSRF_SECRET` to a base64 value shared with the api.
const DEV_CSRF_SECRET: &[u8; 32] = b"idp-dev-insecure-csrf-secret-xxx";
/// Default TTL (seconds) of the `auth_session_id` cookie. Matches the api (600 seconds = 10 minutes).
const DEFAULT_AUTH_SESSION_TTL_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Clone)]
pub struct Config {
    bind_addr: String,
    api_base_url: String,
    /// The api's public origin (= OIDC issuer). The base of absolute URLs the browser uses to reach api endpoints.
    /// Distinct from `api_base_url` (web->api server-to-server target; may be a Compose-internal address);
    /// **always use this one for URLs shown to the browser**.
    issuer: String,
    /// web's own public origin (ADR-0012 §2; used for the cookie `Secure` decision and building absolute URLs).
    /// Set to the same value as the api's `PUBLIC_WEB_BASE_URL`. If unset, the same origin as the issuer
    /// (single-origin setup).
    public_web_base_url: String,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    /// Cookie attribute policy (`Secure` + cleanup of legacy cookies with `Domain`; ADR-0018 decisions 2 and 4).
    /// Set `COOKIE_DOMAIN` to the same value as the api. `None` = no cleanup (default).
    cookie_policy: CookiePolicy,
    auth_session_ttl_secs: u64,
    /// HSTS `max-age` (seconds). 0 = no HSTS header (same key `HSTS_MAX_AGE` as the api).
    hsts_max_age: u64,
    /// Whether to trust the reverse proxy's `X-Forwarded-For` (same key `TRUST_FORWARDED_HEADERS` as the api;
    /// SEC1). Default `false` = ignore the header and use the TCP peer.
    trust_forwarded_headers: bool,
    /// Parents allowed to frame the round trip tried without showing a screen (`SILENT_AUTH_FRAME_ANCESTORS`; same key as the api, env var only;
    /// task #888, ADR-0076).
    silent_auth_frame_ancestors: assay_contracts::frame_ancestors::FrameAncestors,
    /// Whether to allow refreshing the short cookie of a bound login state for requests initiated from hosts other than assay
    /// (`DBSC_ALLOWED_REFRESH_INITIATORS`; env var only; task #934, ADR-0074). If empty, only from assay itself.
    dbsc_allowed_refresh_initiators: Vec<String>,
    /// Whether to show "Continue with the app" (`APP_APPROVER_PACKAGE_NAME` is non-empty; task #892).
    /// The decision itself belongs to the api (it refuses requests when the endpoint is closed). This only decides whether to show it.
    app_approver_enabled: bool,
    log_format: LogFormat,
    /// Shared keys whose DB override via the api was adopted (for the startup log; values not included).
    shared_settings_from_api: Vec<String>,
    /// Snapshot of the shared runtime settings received from the api at startup (MT27).
    ///
    /// Kept so the settings screen can show "shared keys not yet applied to web". Even when an api restart updates the snapshot,
    /// web keeps using the values from its startup, so unless the two are compared, **the state where only the api runs with the new
    /// value** is invisible to everyone (ADR-0013 §Consequences). Secrets don't travel this path
    /// (ADR-0013 §3), so keeping it is fine.
    shared_runtime_settings: HashMap<String, String>,
}

/// ⚠ Secrets (DB connection string, keys, service-to-service token, CSRF key) are not put in `Debug` (task #593).
/// Fields are chosen by hand so values don't leak even if `{:?}` ends up in logs (when adding, only non-secret ones).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("api_base_url", &self.api_base_url)
            .field("issuer", &self.issuer)
            .field("public_web_base_url", &self.public_web_base_url)
            .field("cookie_policy", &self.cookie_policy)
            .field("trust_forwarded_headers", &self.trust_forwarded_headers)
            .field("hsts_max_age", &self.hsts_max_age)
            .finish_non_exhaustive()
    }
}

/// Minimal settings needed to query the api (MT26 / ADR-0013).
///
/// **Shared keys (`COOKIE_SECURE`, `HSTS_MAX_AGE`, `AUTH_SESSION_TTL_SECS`) are not touched.**
/// Parsing ENV shared keys here would make startup fail before querying the api just because ENV has an invalid value
/// (even if the DB has a correct override), and recovery through the `ENV < DB` precedence would be impossible.
///
/// Bootstrap secrets, on the other hand, are `EnvLocked` and can't be fixed from the DB, so **this fails fast here**
/// (so that when the api is unreachable, the actual misconfiguration is shown first rather than "can't reach the api").
///
/// `ISSUER` takes DB overrides (ADR-0017), but the api hasn't been queried yet here, so the ENV value is
/// used. In a setup where the DB override is https and ENV is http, this stage lets it through, and after the shared settings are received
/// [`Config::from_env_and_shared_settings`] rejects it with the same check. The api also rejects the same combination on save
/// (`domain::system_setting::ensure_override_is_bootable`), so this path is normally not entered.
#[derive(Debug, Clone)]
pub struct Bootstrap {
    api_base_url: String,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    log_format: LogFormat,
}

impl Bootstrap {
    pub fn from_env() -> anyhow::Result<Self> {
        let issuer = normalize_base_url(env_or("ISSUER", "http://localhost:8080"));
        let public_web_base_url = normalize_base_url(env_or("PUBLIC_WEB_BASE_URL", &issuer));
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                // Minimum requirements (length, placeholder) are checked by the contract shared with the api (SEC11).
                Some(v) => (
                    assay_contracts::deployment::validate_internal_service_token(&v)
                        .map_err(|e| anyhow::anyhow!(e))?,
                    false,
                ),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // Also validates the base64 format (a value that can't be fixed in the DB, so fail early).
        let (_, csrf_secret_is_dev) = load_csrf_secret()?;
        ensure_production_secrets(
            &issuer,
            &public_web_base_url,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        Ok(Self {
            api_base_url: normalize_base_url(env_or("API_BASE_URL", "http://localhost:8080")),
            internal_service_token,
            internal_service_token_is_dev,
            log_format: parse_log_format(),
        })
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
}

impl Config {
    /// Builds from environment variables and defaults only (no api DB overrides). For tests that don't
    /// start the api. The actual startup path is
    /// [`from_env_and_shared_settings`](Self::from_env_and_shared_settings).
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_and_shared_settings(&HashMap::new())
    }

    /// Resolves settings giving top priority to the DB overrides of the shared runtime settings received from the api
    /// (MT26 / ADR-0013; precedence is default < ENV < `shared`).
    ///
    /// Keys absent from `shared` fall back to ENV -> default as before. In particular the default of `COOKIE_SECURE`
    /// is the scheme of **web's own public origin** (ADR-0012 §2) and does not inherit the api's default.
    pub fn from_env_and_shared_settings(shared: &HashMap<String, String>) -> anyhow::Result<Self> {
        let resolver = SharedSettingResolver::new(shared);
        // The api's public origin (= OIDC issuer; the base of redirects pointing the browser to the api).
        // Moved to DB management in ADR-0017, so the override received from the api takes top priority.
        let issuer = normalize_base_url(resolver.string("ISSUER", "http://localhost:8080"));
        // web's own public origin (ADR-0012 §2). Unset means the same origin as the issuer (single-origin setup).
        let public_web_base_url = normalize_base_url(env_or("PUBLIC_WEB_BASE_URL", &issuer));
        // Cookie Secure attribute. Defaults to the scheme of our own origin (PUBLIC_WEB_BASE_URL)
        // (ADR-0012 §2; decided by web's own public scheme, not the issuer).
        let cookie_secure =
            resolver.parse("COOKIE_SECURE", public_web_base_url.starts_with("https://"))?;
        // COOKIE_DOMAIN for cleaning up cookies with Domain from the old ADR-0012 setup (ADR-0018 decision 4).
        // The same validation as the api (parent-domain consistency, public suffix rejection) runs at startup (fail-fast).
        let cookie_domain = match env_lookup("COOKIE_DOMAIN") {
            Some(raw) => Some(
                assay_contracts::cookie_domain::validate_cookie_domain(
                    &raw,
                    &[issuer.as_str(), public_web_base_url.as_str()],
                )
                .map_err(|e| anyhow::anyhow!(e))?,
            ),
            None => None,
        };
        let cookie_policy = CookiePolicy::new(cookie_secure, cookie_domain.as_deref());
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                // Minimum requirements (length, placeholder) are checked by the contract shared with the api (SEC11).
                Some(v) => (
                    assay_contracts::deployment::validate_internal_service_token(&v)
                        .map_err(|e| anyhow::anyhow!(e))?,
                    false,
                ),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // In production (https issuer), don't start with the development default token (fail-fast; same policy as the api).
        ensure_production_secrets(
            &issuer,
            &public_web_base_url,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        Ok(Self {
            bind_addr: env_or("WEB_BIND_ADDR", "0.0.0.0:8081"),
            // Target for reaching the api. A proxy-internal address in single-origin setups; the api's direct address locally.
            api_base_url: normalize_base_url(env_or("API_BASE_URL", "http://localhost:8080")),
            issuer,
            public_web_base_url,
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            cookie_policy,
            auth_session_ttl_secs: resolver
                .parse("AUTH_SESSION_TTL_SECS", DEFAULT_AUTH_SESSION_TTL_SECS)?,
            hsts_max_age: resolver.parse("HSTS_MAX_AGE", 0u64)?,
            trust_forwarded_headers: resolver.parse("TRUST_FORWARDED_HEADERS", false)?,
            // Don't start with a value that can't be written (fail-fast; the api runs the same check)
            silent_auth_frame_ancestors: assay_contracts::frame_ancestors::parse_frame_ancestors(
                &env_or("SILENT_AUTH_FRAME_ANCESTORS", ""),
            )
            .map_err(|e| anyhow::anyhow!(e))?,
            dbsc_allowed_refresh_initiators:
                assay_contracts::session_key::parse_refresh_initiators(&env_or(
                    "DBSC_ALLOWED_REFRESH_INITIATORS",
                    "",
                ))
                .map_err(|e| anyhow::anyhow!(e))?,
            app_approver_enabled: !env_or("APP_APPROVER_PACKAGE_NAME", "").trim().is_empty(),
            log_format: parse_log_format(),
            shared_settings_from_api: resolver.applied_keys(),
            shared_runtime_settings: shared.clone(),
        })
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }
    /// The api's base URL (no trailing slash). The API client joins each endpoint to it.
    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }
    /// Service auth token attached to web->api `/internal/*` calls (ADR-0007 §5).
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    /// CSRF token signing key (for HMAC-SHA256). Shares the same `CSRF_SECRET` as the api.
    pub fn csrf_secret(&self) -> &[u8; 32] {
        &self.csrf_secret
    }
    pub fn csrf_secret_is_dev(&self) -> bool {
        self.csrf_secret_is_dev
    }
    /// The api's public origin (= OIDC issuer; no trailing slash). The base of absolute URLs pointing the browser to api
    /// endpoints. With separate-domain publishing (ADR-0015) web and api have different origins, so
    /// links to endpoints served by the api (`/{tenant_id}/saml/metadata` etc.) written relative to the web origin
    /// would 404.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// web's own public origin (no trailing slash; ADR-0012 §2).
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }
    /// Whether web adds `Secure` to the cookies it builds (used when turning api responses into cookies).
    pub fn cookie_secure(&self) -> bool {
        self.cookie_policy.secure()
    }
    /// `COOKIE_DOMAIN` for cleaning up cookies with `Domain` from the old ADR-0012 setup (ADR-0018 decision 4).
    /// `None` = no cleanup (default). Session cookies are always issued host-only.
    pub fn cookie_domain(&self) -> Option<&str> {
        self.cookie_policy.legacy_cleanup_domain()
    }
    /// Cookie attribute policy. Issuing and expiring cookies always goes through this (ADR-0012 §3; so that no
    /// issuing site forgets to pass `Domain`). Normally use `WebState::set_cookies()`.
    pub fn cookie_policy(&self) -> &CookiePolicy {
        &self.cookie_policy
    }
    /// TTL (seconds) of the `auth_session_id` cookie. Matches the api's `AUTH_SESSION_TTL_SECS`.
    pub fn auth_session_ttl_secs(&self) -> u64 {
        self.auth_session_ttl_secs
    }
    /// HSTS `max-age` (seconds). 0 = no HSTS header.
    pub fn hsts_max_age(&self) -> u64 {
        self.hsts_max_age
    }
    /// Parents allowed to frame the round trip tried without showing a screen (not allowed if empty; task #888, ADR-0076).
    pub fn silent_auth_frame_ancestors(&self) -> &assay_contracts::frame_ancestors::FrameAncestors {
        &self.silent_auth_frame_ancestors
    }
    /// Types of non-assay initiator hosts allowed to refresh the short cookie (`allowed_refresh_initiators` in registration/refresh responses).
    pub fn dbsc_allowed_refresh_initiators(&self) -> &[String] {
        &self.dbsc_allowed_refresh_initiators
    }
    /// Whether to trust `X-Forwarded-For` for the client IP (SEC1). If `false` (default),
    /// the header is ignored and the TCP peer address (`ConnectInfo`) is used. Same key and default as the api;
    /// set to `true` only behind a trusted reverse proxy.
    /// Whether to show "Continue with the app" on screen (task #892).
    pub fn app_approver_enabled(&self) -> bool {
        self.app_approver_enabled
    }

    pub fn trust_forwarded_headers(&self) -> bool {
        self.trust_forwarded_headers
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
    /// Names of shared keys whose DB override via the api was adopted (for the startup log; **values not included**).
    pub fn shared_settings_from_api(&self) -> &[String] {
        &self.shared_settings_from_api
    }

    /// Shared runtime settings received from the api at startup. The settings screen compares them with the api's current snapshot
    /// to detect what has not yet been applied to web (MT27).
    pub fn shared_runtime_settings(&self) -> &HashMap<String, String> {
        &self.shared_runtime_settings
    }
}

/// Compares the shared settings web applied at startup with those the api currently serves, and returns **keys not yet applied
/// to web** (MT27). Only key names are returned; values are not included.
///
/// An api restart is itself the publication of new values (ADR-0013 §1-a), so if the api restarted and web
/// did not, only the api runs with the new values. The reverse (only web has new values) structurally cannot happen
/// with the snapshot approach.
pub fn stale_shared_settings(
    applied: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> Vec<String> {
    let mut keys: Vec<String> = current
        .iter()
        .filter(|(key, value)| applied.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        // Keys whose override was removed (gone from the api side) are also not yet applied.
        .chain(
            applied
                .keys()
                .filter(|key| !current.contains_key(*key))
                .cloned(),
        )
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Resolves shared keys as "default < ENV < DB override via the api" (MT26 / ADR-0013).
///
/// Records which keys came from the DB and shows operators in the startup log (needed to isolate cases where the value on the
/// settings screen and the value actually in effect disagree).
struct SharedSettingResolver<'a> {
    shared: &'a HashMap<String, String>,
    applied: std::cell::RefCell<Vec<String>>,
}

impl<'a> SharedSettingResolver<'a> {
    fn new(shared: &'a HashMap<String, String>) -> Self {
        Self {
            shared,
            applied: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Resolves the effective value as a string (DB override > ENV; `None` if neither).
    fn optional_string(&self, key: &str) -> Option<String> {
        if let Some(v) = self.shared.get(key).filter(|v| !v.is_empty()) {
            self.applied.borrow_mut().push(key.to_string());
            return Some(v.clone());
        }
        env_lookup(key)
    }

    fn parse<T>(&self, key: &str, default: T) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.optional_string(key) {
            Some(v) => v
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
            None => Ok(default),
        }
    }

    /// Resolves the effective value as a string (DB override > ENV > default).
    fn string(&self, key: &str, default: &str) -> String {
        self.optional_string(key)
            .unwrap_or_else(|| default.to_string())
    }

    fn applied_keys(&self) -> Vec<String> {
        self.applied.borrow().clone()
    }
}

/// Fails startup if development default secrets are used in a production-like setup.
///
/// Production-likeness looks at **both the issuer and web's own public origin** (since ADR-0012 §2 web
/// has its own public origin). If either is `https://`, it is treated as a public deployment.
/// Looking only at the issuer would let through a setup where `PUBLIC_WEB_BASE_URL` is a public https deployment but `ISSUER` was
/// mistakenly set to an internal http URL, running with the `CSRF_SECRET` shared with the api still at the known development value
/// (anyone could forge CSRF tokens).
fn ensure_production_secrets(
    issuer: &str,
    public_web_base_url: &str,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    // The decision lives in the contract shared with the api (SEC11). Not only https, but also deployments that terminate TLS
    // upstream and expose a non-loopback http address are treated as production.
    use assay_contracts::deployment::requires_production_secrets;
    let public_origin = if requires_production_secrets(issuer) {
        issuer
    } else if requires_production_secrets(public_web_base_url) {
        public_web_base_url
    } else {
        return Ok(());
    };
    if internal_service_token_is_dev {
        anyhow::bail!(
            "the public origin ({public_origin}) is not a local loopback origin but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with api) in production."
        );
    }
    if csrf_secret_is_dev {
        anyhow::bail!(
            "the public origin ({public_origin}) is not a local loopback origin but CSRF_SECRET is not set; \
             refusing to start with the built-in development secret. \
             Set CSRF_SECRET (base64, 32 bytes, shared with api) in production."
        );
    }
    Ok(())
}

/// Reads `CSRF_SECRET` (base64, 32 bytes). Uses the development default if unset.
///
/// Starting with the `.env.*.example` placeholder `CHANGE-ME` left in place happens often in practice
/// (a bare base64 error doesn't lead to the cause), so placeholders are detected before base64 decoding
/// and the fix (`openssl rand -base64 32`) is suggested (same policy as the api's `decode_secret_32`).
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => {
            let v = v.trim();
            if v.contains("CHANGE-ME") {
                anyhow::bail!(
                    "CSRF_SECRET is still the .env template placeholder \"CHANGE-ME\"; \
                     replace it with a real value (generate with `openssl rand -base64 32`, \
                     shared with api)"
                );
            }
            let bytes = STANDARD.decode(v).map_err(|e| {
                anyhow::anyhow!(
                    "CSRF_SECRET must be base64 (generate with `openssl rand -base64 32`): {e}"
                )
            })?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("CSRF_SECRET must decode to exactly 32 bytes"))?;
            Ok((arr, false))
        }
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

/// Normalizes a public base URL: drops the trailing slash and **lower-cases the scheme**.
///
/// URI schemes are case-insensitive (RFC 3986 §3.1). If a notation like `HTTPS://id.example.com` couldn't be
/// judged https, the cookie `Secure` decision and the production-secret fail-fast (both look at
/// the scheme) would be bypassed. Host and path are left as is (the issuer must exactly match the ID Token's `iss`,
/// so we don't change it on our own).
fn normalize_base_url(raw: String) -> String {
    let trimmed = raw.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
        None => trimmed.to_string(),
    }
}

fn env_lookup(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn env_or(key: &str, default: &str) -> String {
    env_lookup(key).unwrap_or_else(|| default.to_string())
}

/// Reads `LOG_FORMAT` (`EnvLocked`). Unknown values fall back to the default JSON (log init must not fail).
fn parse_log_format() -> LogFormat {
    match env_or("LOG_FORMAT", "json").to_ascii_lowercase().as_str() {
        "pretty" => LogFormat::Pretty,
        _ => LogFormat::Json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Lock serializing tests that touch process-wide environment variables (`cargo test` runs threads in parallel).
    /// Tests calling `Config::from_env*` must always acquire it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Acquires `ENV_LOCK`. Even if another test panics while holding the lock and poisons it, mutual exclusion
    /// itself is preserved, so the inner value is taken and execution continues.
    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tests using non-loopback public origins are judged production-like (SEC11), so `Config` can't be built
    /// with the development default secrets. Injects test values.
    fn set_production_secrets() {
        std::env::set_var("INTERNAL_SERVICE_TOKEN", "t".repeat(32));
        std::env::set_var("CSRF_SECRET", STANDARD.encode([7u8; 32]));
    }

    fn clear_production_secrets() {
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
    }

    #[test]
    fn base_url_is_normalized_without_trailing_slash() {
        assert_eq!(
            normalize_base_url("http://api:8080/".to_string()),
            "http://api:8080"
        );
    }

    #[test]
    fn base_url_scheme_is_lowercased_but_host_is_left_alone() {
        // Schemes are case-insensitive (RFC 3986 §3.1). Normalized so https detection (cookie Secure, production
        // secret fail-fast) isn't bypassed by `HTTPS://` notation.
        assert_eq!(
            normalize_base_url("HTTPS://ID.Example.com/".to_string()),
            "https://ID.Example.com"
        );
        // Values without a scheme pass through untouched (not broken by mistake).
        assert_eq!(
            normalize_base_url("id.example.com".to_string()),
            "id.example.com"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        let issuer = "https://idp.example.com";
        assert!(ensure_production_secrets(issuer, issuer, true, false).is_err());
        assert!(ensure_production_secrets(issuer, issuer, false, true).is_err());
        assert!(ensure_production_secrets(issuer, issuer, false, false).is_ok());
        assert!(ensure_production_secrets(
            "http://localhost:8080",
            "http://localhost:8081",
            true,
            true
        )
        .is_ok());
    }

    #[test]
    fn production_secrets_are_required_when_only_the_web_origin_is_https() {
        // ADR-0012 §2: web has its own public origin. As long as it is published over https, whatever the ISSUER
        // scheme, it must not start with the development secret (the CSRF key shared with the api).
        // The issuer side is loopback (= not judged as production), pinning that the decision is made
        // by web's public origin alone.
        let err = ensure_production_secrets(
            "http://localhost:8080",
            "https://id.example.com",
            false,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("https://id.example.com"), "{err}");
        assert!(err.contains("CSRF_SECRET"), "{err}");
        assert!(ensure_production_secrets(
            "http://localhost:8080",
            "https://id.example.com",
            true,
            false
        )
        .is_err());
    }

    #[test]
    fn uppercase_https_scheme_is_still_treated_as_production() {
        // Fail-fast works with `HTTPS://` notation too (`from_env` goes through normalize_base_url, so
        // ensure_production_secrets receives the lower-cased value).
        let public_web_base_url = normalize_base_url("HTTPS://id.example.com".to_string());
        assert!(ensure_production_secrets(
            "http://localhost:8080",
            &public_web_base_url,
            false,
            true
        )
        .is_err());
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let key = "IDP_WEB_TEST_EMPTY";
        std::env::set_var(key, "");
        assert_eq!(env_or(key, "fallback"), "fallback");
        std::env::remove_var(key);
    }

    #[test]
    fn self_origin_and_cookie_domain_resolution() {
        let _env = env_guard();
        // Uses a non-loopback origin, so it is production-like (SEC11). Prepare secrets first.
        set_production_secrets();
        // Separate-domain setup: the Secure decision follows our own origin (PUBLIC_WEB_BASE_URL), not the issuer
        // (ADR-0012 §2). With an http own origin, no Secure.
        std::env::set_var("ISSUER", "http://api.example.com");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com/");
        std::env::set_var("COOKIE_DOMAIN", "example.com");
        let config = Config::from_env().unwrap();
        assert_eq!(config.public_web_base_url(), "http://id.example.com");
        assert!(!config.cookie_secure());
        assert_eq!(config.cookie_domain(), Some("example.com"));

        // A COOKIE_DOMAIN that is not a parent of both origins fails startup (fail-fast).
        std::env::set_var("COOKIE_DOMAIN", "other.com");
        assert!(Config::from_env().is_err());

        // Unset = host-only; own origin same as the issuer (traditional behavior of the single-origin setup).
        std::env::remove_var("COOKIE_DOMAIN");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        let config = Config::from_env().unwrap();
        assert_eq!(config.public_web_base_url(), "http://api.example.com");
        assert_eq!(config.cookie_domain(), None);

        // With an https own origin, Secure is added. Pins, combined with an http issuer, that the basis of the decision is the own origin
        // rather than the issuer (ADR-0012 §2).
        std::env::set_var("PUBLIC_WEB_BASE_URL", "https://id.example.com");
        let config = Config::from_env().unwrap();
        assert!(config.cookie_secure(), "Secure follows the web origin");

        // An explicit COOKIE_SECURE takes precedence over the own origin's scheme (escape hatch for proxy-terminated setups).
        std::env::set_var("COOKIE_SECURE", "false");
        assert!(!Config::from_env().unwrap().cookie_secure());
        std::env::set_var("COOKIE_SECURE", "true");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com");
        assert!(Config::from_env().unwrap().cookie_secure());

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        clear_production_secrets();
        std::env::remove_var("ISSUER");
    }

    /// MT26 / ADR-0013: DB overrides via the api take precedence over ENV and defaults.
    /// MT27: if the shared settings web applied at startup differ from the api's current values, "not yet applied to web".
    #[test]
    fn stale_shared_settings_reports_keys_the_web_has_not_picked_up() {
        let applied = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);

        // If they match exactly, nothing is pending.
        assert!(stale_shared_settings(&applied, &applied).is_empty());

        // Only keys whose values changed are listed.
        let changed = HashMap::from([
            ("COOKIE_SECURE".to_string(), "false".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);
        assert_eq!(
            stale_shared_settings(&applied, &changed),
            vec!["COOKIE_SECURE".to_string()]
        );

        // Keys newly added on the api side are also pending.
        let added = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "900".to_string()),
        ]);
        assert_eq!(
            stale_shared_settings(&applied, &added),
            vec!["AUTH_SESSION_TTL_SECS".to_string()]
        );

        // **Keys whose override was removed (gone from the api side) are also pending**. Dropping this would hide from the screen
        // the state where the override was removed but web keeps running with the old override.
        let removed = HashMap::from([("COOKIE_SECURE".to_string(), "true".to_string())]);
        assert_eq!(
            stale_shared_settings(&applied, &removed),
            vec!["HSTS_MAX_AGE".to_string()]
        );
    }

    /// ADR-0017: `ISSUER` also became a shared key taking DB overrides via the api. If web missed it,
    /// in a single-origin setup only web's own origin (= issuer when `PUBLIC_WEB_BASE_URL` is unset) would stay at the old
    /// `http://localhost:8080`, and the api and browser paths would diverge.
    #[test]
    fn issuer_from_api_overrides_env_for_the_web_origin() {
        let _env = env_guard();
        // The overridden issuer is non-loopback, so it is production-like (SEC11).
        set_production_secrets();
        std::env::set_var("ISSUER", "http://localhost:8080");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");

        let shared = HashMap::from([("ISSUER".to_string(), "http://idp.example.test".to_string())]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert_eq!(config.public_web_base_url(), "http://idp.example.test");
        assert_eq!(config.shared_settings_from_api(), ["ISSUER"]);

        // Without an override it goes back to ENV.
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert_eq!(config.public_web_base_url(), "http://localhost:8080");

        std::env::remove_var("ISSUER");
        clear_production_secrets();
    }

    #[test]
    fn shared_settings_from_api_take_precedence_over_env_and_defaults() {
        let _env = env_guard();
        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");
        // ENV deliberately has a value different from the DB, pinning that the DB wins.
        std::env::set_var("COOKIE_SECURE", "false");
        std::env::set_var("HSTS_MAX_AGE", "1");
        std::env::set_var("AUTH_SESSION_TTL_SECS", "60");

        let shared = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "1200".to_string()),
        ]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert!(config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 31_536_000);
        assert_eq!(config.auth_session_ttl_secs(), 1_200);
        let mut applied = config.shared_settings_from_api().to_vec();
        applied.sort();
        assert_eq!(
            applied,
            ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"]
        );

        // Without a DB override it falls to ENV, and without ENV to the default.
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert!(!config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 1);
        assert_eq!(config.auth_session_ttl_secs(), 60);
        assert!(config.shared_settings_from_api().is_empty());

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert!(
            !config.cookie_secure(),
            "http origin defaults to non-Secure"
        );
        assert_eq!(config.hsts_max_age(), 0);
        assert_eq!(
            config.auth_session_ttl_secs(),
            DEFAULT_AUTH_SESSION_TTL_SECS
        );
    }

    /// An empty-string DB override is treated as "unset" and falls to ENV (the api uses an empty string to remove an override;
    /// `system_settings.update_runtime_setting`).
    #[test]
    fn empty_shared_override_falls_back_to_env() {
        let _env = env_guard();
        std::env::set_var("HSTS_MAX_AGE", "42");
        let shared = HashMap::from([("HSTS_MAX_AGE".to_string(), String::new())]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert_eq!(config.hsts_max_age(), 42);
        assert!(config.shared_settings_from_api().is_empty());
        std::env::remove_var("HSTS_MAX_AGE");
    }

    /// An invalid DB override fails startup (silently discarding the value and falling to the default would keep running
    /// with the settings screen and actual behavior disagreeing).
    #[test]
    fn invalid_shared_override_fails_startup() {
        let _env = env_guard();
        std::env::remove_var("HSTS_MAX_AGE");
        let shared = HashMap::from([("HSTS_MAX_AGE".to_string(), "not-a-number".to_string())]);
        let err = Config::from_env_and_shared_settings(&shared)
            .unwrap_err()
            .to_string();
        assert!(err.contains("HSTS_MAX_AGE"), "{err}");
    }

    /// Even if ENV shared keys are broken, bootstrap passes and recovery via DB override is possible (MT26 / ADR-0013).
    /// If bootstrap parsed shared keys, it would fail before querying the api despite the `ENV < DB` precedence,
    /// and it could not be fixed from the DB.
    #[test]
    fn bootstrap_ignores_malformed_shared_env_values_so_db_can_recover_them() {
        let _env = env_guard();
        std::env::set_var("HSTS_MAX_AGE", "not-a-number");
        std::env::set_var("AUTH_SESSION_TTL_SECS", "soon");
        std::env::set_var("API_BASE_URL", "http://api:8080/");

        // Bootstrap reads only the values needed to reach the api -> broken shared keys are ignored.
        let bootstrap = Bootstrap::from_env().expect("bootstrap must not parse shared keys");
        assert_eq!(bootstrap.api_base_url(), "http://api:8080");

        // Broken ENV can be rescued by a DB override.
        let shared = HashMap::from([
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "900".to_string()),
        ]);
        let config = Config::from_env_and_shared_settings(&shared).expect("DB values recover ENV");
        assert_eq!(config.hsts_max_age(), 31_536_000);
        assert_eq!(config.auth_session_ttl_secs(), 900);

        // Without a DB override it is a configuration error as before (broken ENV is not silently ignored).
        assert!(Config::from_env_and_shared_settings(&HashMap::new()).is_err());

        std::env::remove_var("HSTS_MAX_AGE");
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        std::env::remove_var("API_BASE_URL");
    }

    /// The production-secret fail-fast works in bootstrap too (`EnvLocked` can't be fixed from the DB, so
    /// the actual misconfiguration is shown before api unreachability).
    #[test]
    fn bootstrap_still_rejects_development_secrets_on_a_public_origin() {
        let _env = env_guard();
        std::env::set_var("ISSUER", "https://api.example.com");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        let err = Bootstrap::from_env().unwrap_err().to_string();
        assert!(err.contains("INTERNAL_SERVICE_TOKEN"), "{err}");
        std::env::remove_var("ISSUER");
    }

    /// Secrets are not put in `Debug` (task #593). Values don't leak even if `{:?}` ends up in logs.
    #[test]
    fn debug_output_does_not_carry_the_secrets() {
        let _env = env_guard();
        set_production_secrets();
        let config = Config::from_env().unwrap();
        let shown = format!("{config:?}");
        clear_production_secrets();
        assert!(!shown.contains(&"t".repeat(32)), "{shown}");
        assert!(!shown.contains("csrf_secret"), "{shown}");
        assert!(!shown.contains("internal_service_token"), "{shown}");
        assert!(shown.contains("bind_addr"), "{shown}");
    }
}
