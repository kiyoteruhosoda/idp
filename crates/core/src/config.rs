//! Application settings.
//!
//! Settings must **always be read through this module**. Raw environment variables and DSNs are not referenced directly elsewhere.
//!
//! Precedence: **built-in default < environment variable (ENV) < DB (system_settings table)**.
//! Following the idea that "it can later be overridden in the DB", the layer closer to operations (DB) wins.
//! However, only `DbManaged` keys accept DB overrides. `EnvLocked` (bootstrap keys needed before reading the DB or to
//! decrypt secrets in the DB, and keys whose values must match between api/web) do not consult the DB and resolve as ENV > default
//! (ADR-0010). `Builtin` is always the default.
//!
//! ⚠ **Keys tenants can override (ADR-0058) are not held in `Config`.** Their values differ per tenant and
//! cannot be expressed by resolving one at startup and handing it out, so consumers look them up from
//! [`crate::application::tenant_settings::TenantSettingsService`] on every reference.
//! All that is done here is stopping at startup on values of the wrong type ([`Self::from_env_and_db_settings`]) and
//! providing the last layer of resolution (environment variable -> built-in default) ([`Self::value_without_db`]).
//!
//! Some getters (various TTLs, clock skew) are kept even though unused for now,
//! since they are used in later phases (T2 and on).
#![allow(dead_code)]

use crate::domain::authentication_policy::DefaultPolicyEffect;
use crate::domain::password_policy::DEFAULT_BREACH_API_BASE_URL;
use crate::domain::system_setting::{
    requires_production_secrets, runtime_setting_definition, tenant_overridable_setting_keys,
    validate_setting_value, DefaultRisk, DeploymentState, DevelopmentSecrets, SettingOwner,
    RUNTIME_SETTING_DEFINITIONS,
};
use crate::domain::values::AssignmentEnforcement;
use assay_contracts::cookies::CookiePolicy;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

/// Development default of the private-key encryption key (exactly 32 bytes). In production always set `KEY_ENCRYPTION_KEY`.
/// In operation, migrate to key management outside the DB (KMS, etc.).
///
/// Public like `DEV_CSRF_SECRET` (integration tests use it to explicitly inject "the same bytes as the default",
/// so that signing keys in the shared test DB stay mutually decryptable by all test binaries).
pub const DEV_KEY_ENCRYPTION_KEY: &[u8; 32] = b"idp-dev-insecure-key-0123456789!";

/// Development default of the inter-service internal auth token (ADR-0007 §5). In production always
/// set `INTERNAL_SERVICE_TOKEN`. A shared secret protecting web->api `/internal/*` calls.
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";

/// Development default of the CSRF token HMAC key (exactly 32 bytes). In production always
/// set `CSRF_SECRET` to the same value in web and api (SEC7).
pub const DEV_CSRF_SECRET: &[u8; 32] = b"idp-dev-insecure-csrf-secret-xxx";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    Builtin,
    Env,
    Db,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSetting {
    pub key: String,
    pub owner: SettingOwner,
    pub source: SettingSource,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    /// Safety assessment for screen display (does not include values or fingerprints).
    pub status: SettingSafetyStatus,
    /// The basis of the danger/safety assessment. Does not include secret plaintext or fingerprints.
    pub reason: String,
    /// The effective value resolved at startup (for display). Always `None` for secrets (plaintext is never exposed).
    pub value: Option<String>,
    /// The built-in default (for display). `None` for secrets.
    pub default_value: Option<String>,
    /// Description of what this setting is used for (for operators. Shown on the settings screen).
    pub description: String,
}

impl ResolvedSetting {
    /// Whether it is **saved but not yet applied to the running process** (MT27).
    ///
    /// `resolved_settings` is the startup snapshot, and `db_current` is the override value currently stored in
    /// `system_settings` (`None` if unset). If the two differ, the value saved on the settings screen
    /// has not taken effect yet.
    ///
    /// That saving does not change behavior is invisible on screen, and operators arrive at the wrong conclusion
    /// "I saved it but it is not fixed". The decision is placed here so the display side does not have to reproduce the comparison rules
    /// (especially that **removing an override** is also unapplied).
    ///
    /// Only keys that are `DbManaged`, non-secret and `restart_required` are judged.
    ///
    /// - Keys with `restart_required` false read the DB on every reference, so they are always applied.
    /// - Secrets leave no plaintext in the startup snapshot (`value` is always `None`), so they cannot be compared.
    /// - **Keys other than `DbManaged` are not compared even if a DB row exists.** `EnvLocked` / `Builtin` keys do not
    ///   consult the DB at all when resolving, so `source` can never be `Db`, and matching against leftover rows would show them
    ///   as unapplied forever. Moreover `editable` is false, so they cannot be removed from the screen and the warning would stay.
    ///   This actually happens in environments that still have `system_settings` rows for keys whose owner changed from `DbManaged`
    ///   (`PUBLIC_WEB_BASE_URL` and `COOKIE_DOMAIN` were moved to `EnvLocked` in ADR-0012).
    ///   Those rows do not affect resolution at all (they are ignored), so they are not unapplied.
    pub fn is_pending_restart(&self, db_current: Option<&str>) -> bool {
        if !self.restart_required || self.secret || self.owner != SettingOwner::DbManaged {
            return false;
        }
        match db_current {
            // There is a DB override: applied if the same value was also taken from the DB at startup.
            Some(value) => {
                !(self.source == SettingSource::Db && self.value.as_deref() == Some(value))
            }
            // There is no DB override: if it was taken from the DB at startup, the removal has not taken effect yet.
            None => self.source == SettingSource::Db,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSafetyStatus {
    Safe,
    NeedsAction,
}

#[derive(Clone)]
pub struct Config {
    issuer: String,
    bind_addr: String,
    database_url: String,
    db_max_connections: u32,
    log_format: LogFormat,
    auth_session_ttl: Duration,
    authorization_code_ttl: Duration,
    access_token_ttl: Duration,
    management_token_ttl: Duration,
    id_token_ttl: Duration,
    refresh_token_ttl: Duration,
    clock_skew: Duration,
    /// Default behavior when no authentication policy matches (same spec §9.4).
    auth_policy_default_effect: DefaultPolicyEffect,
    application_assignment_enforcement: AssignmentEnforcement,
    /// Endpoint for breached password checks (k-anonymity range API).
    password_breach_api_base_url: String,
    /// Names allowed to be sent to even if they resolve to internal addresses (`OUTBOUND_TRUSTED_HOSTS`. task #585).
    outbound_trusted_hosts: String,
    /// Destination of security notifications (`SECURITY_ALERT_WEBHOOK_URL`. task #872. Environment variable only).
    security_alert_webhook_url: String,
    /// The file from which its key is read (`SECURITY_ALERT_WEBHOOK_TOKEN_FILE`).
    security_alert_webhook_token_file: String,
    /// Parents allowed to frame the round trip tried without showing a screen (`SILENT_AUTH_FRAME_ANCESTORS`. task #888. Environment variable only).
    silent_auth_frame_ancestors: assay_contracts::frame_ancestors::FrameAncestors,
    /// Authenticator app (task #892. ADR-0077. Environment variable only).
    app_approver_package_name: String,
    app_approver_signing_cert_sha256: String,
    app_approver_extra_attestation_roots_file: String,
    app_approver_allow_software_attestation: bool,
    /// Timeout of one request of the breached password check.
    password_breach_check_timeout: Duration,
    /// TTL of the tenant resolution cache (ADR-0009 §7. The id -> tenant hot path).
    tenant_cache_ttl: Duration,
    /// TTL of the scope->permission resolution cache (ADR-0009 §7. Invalidated immediately on grant/revoke).
    permission_cache_ttl: Duration,
    /// Cookie attribute policy (`Secure` and cleanup of old `Domain` Cookies. ADR-0018 decisions 2, 4). Set the same value as web.
    cookie_policy: CookiePolicy,
    key_encryption_key: [u8; 32],
    key_encryption_key_is_dev: bool,
    /// Signing key rotation: generate a new key and retire the old one this many days before `not_after` (K2).
    key_rotation_lead_days: u32,
    key_rotation_publish_lead_hours: u32,
    /// Retention days of error/warning logs (`log` table). `0` means never delete.
    app_log_retention_days: u32,
    /// Retention days of audit logs (`audit_log` table). `0` (default) means never delete (G8).
    audit_log_retention_days: u32,
    /// Concurrency limit of token endpoints (`/token`, `/introspect`, `/revoke`) (SEC10).
    /// `0` is unlimited. Keeps Argon2 verification's peak memory and CPU to "limit x 19 MiB".
    token_endpoint_max_concurrency: u32,
    /// Per-source-IP rate limit of token endpoints (SEC10). `0` disables it.
    token_endpoint_rate_limit_max_requests: u32,
    /// Window (seconds) of the rate limit above.
    token_endpoint_rate_limit_window_secs: u64,
    /// Whether to serve Swagger UI and the OpenAPI document (SEC12. Default false).
    api_docs_enabled: bool,
    /// Additional origins allowed by CORS (raw comma-separated value. G1).
    cors_allowed_origins: String,
    /// Interval (seconds) of the bulk GC of expired records (G2). `0` means no cleanup.
    expired_record_purge_interval_secs: u64,
    /// Max resend count of back-channel logout notifications (G5).
    backchannel_logout_max_attempts: u32,
    /// Polling interval (seconds) of the back-channel logout delivery worker (G5).
    backchannel_logout_poll_interval_secs: u64,
    /// Retention days of settled rows in the back-channel logout delivery queue (`0` means never delete. G5).
    backchannel_logout_retention_days: u32,
    /// Whether to trust `X-Forwarded-For` / `X-Forwarded-Proto` added by a reverse proxy (S1).
    trust_forwarded_headers: bool,
    /// HSTS `max-age` (seconds). 0 = no HSTS header (S1).
    hsts_max_age: u64,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    /// CSRF token HMAC key (`CSRF_SECRET`). Set the same value in web and api (SEC7).
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    /// Public base URL of the web screens users open in the browser (e.g. the accept link in invitation emails. MT17).
    /// EnvLocked because api/web require the same value (ADR-0012 §2).
    public_web_base_url: String,
    /// **Explicitly set** `PUBLIC_WEB_BASE_URL` (`None` = follows the issuer).
    ///
    /// From the resolved value (`public_web_base_url`) one cannot tell "following the issuer" from "explicitly set
    /// to the same value by chance". Deciding whether a DB override of `ISSUER` may be saved (ADR-0017)
    /// needs this distinction: when following, changing the issuer does not misalign the scheme, but when explicitly set,
    /// a `COOKIE_DOMAIN` deployment gets a scheme mismatch and fails to start.
    public_web_base_url_override: Option<String>,
    resolved_settings: Vec<ResolvedSetting>,
}

/// ⚠ Do not show secrets (DB connection string, keys, inter-service token, CSRF key) in `Debug` (task #593).
/// Fields are chosen by hand so values do not leak even if dropped into a log with `{:?}` (when adding, only non-secrets).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("issuer", &self.issuer)
            .field("bind_addr", &self.bind_addr)
            .field("db_max_connections", &self.db_max_connections)
            .field("public_web_base_url", &self.public_web_base_url)
            .field("trust_forwarded_headers", &self.trust_forwarded_headers)
            .field("hsts_max_age", &self.hsts_max_age)
            .field(
                "silent_auth_frame_ancestors",
                &self.silent_auth_frame_ancestors,
            )
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_and_db_settings(&HashMap::new())
    }

    pub fn from_env_and_db_settings(db_settings: &HashMap<String, String>) -> anyhow::Result<Self> {
        let resolver = ConfigResolver::new(db_settings);
        let (key_encryption_key, key_encryption_key_is_dev) = load_key_encryption_key()?;
        let issuer = normalize_issuer(resolver.string("ISSUER", "http://localhost:8080"));
        // The Cookie Secure attribute. By default follows the issuer's scheme (enabled for https).
        let cookie_secure = resolver.parse("COOKIE_SECURE", issuer.starts_with("https://"))?;
        // Shared secret protecting web->api /internal/* calls (ADR-0007 §5).
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (validate_internal_service_token(v)?, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // CSRF token HMAC key (SEC7). Set the same value in web and api.
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // In production-like setups (public origins other than loopback), do not start with the development default
        // secrets (fail-fast. SEC11).
        ensure_production_secrets(
            &issuer,
            key_encryption_key_is_dev,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        // The base of accept links in invitation emails etc. In the single-origin setup (ADR-0007) the web screens live on the same
        // origin as the issuer, so the default is the issuer. Set explicitly only when placing the web on a different origin.
        let public_web_base_url_override = resolver
            .optional_string("PUBLIC_WEB_BASE_URL")
            .map(normalize_issuer);
        let public_web_base_url = public_web_base_url_override
            .clone()
            .unwrap_or_else(|| issuer.clone());
        // COOKIE_DOMAIN for cleaning up Domain-scoped Cookies of the old ADR-0012 setup (ADR-0018 decision 4).
        // When set, it is validated at startup to be a parent domain of both issuer / public_web_base_url and not a public suffix
        // (fail-fast rejecting values for which deletion Cookies would not be accepted by browsers).
        let cookie_domain = match resolver.optional_string("COOKIE_DOMAIN") {
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
        // Keys tenants can override are not held in `Config` (ADR-0058), but starting with global values of the wrong type
        // (environment variables, `system_settings`) is still stopped here as before. Otherwise a broken value would
        // first fail on the first request that references it, and everyone in tenants without rows would fail at once.
        for key in tenant_overridable_setting_keys() {
            if let (Some(def), Some(value)) = (
                runtime_setting_definition(key),
                resolver.optional_string(key),
            ) {
                validate_setting_value(def, &value)
                    .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}"))?;
            }
        }

        Ok(Self {
            issuer,
            bind_addr: resolver.string("BIND_ADDR", "0.0.0.0:8080"),
            database_url: resolver.string("DATABASE_URL", "mysql://idp:idp@127.0.0.1:3306/idp"),
            db_max_connections: resolver.parse("DB_MAX_CONNECTIONS", 10)?,
            log_format: match resolver
                .string("LOG_FORMAT", "json")
                .to_ascii_lowercase()
                .as_str()
            {
                "pretty" => LogFormat::Pretty,
                _ => LogFormat::Json,
            },
            auth_session_ttl: secs(resolver.parse("AUTH_SESSION_TTL_SECS", 600)?),
            authorization_code_ttl: secs(resolver.parse("AUTHORIZATION_CODE_TTL_SECS", 60)?),
            access_token_ttl: secs(resolver.parse("ACCESS_TOKEN_TTL_SECS", 900)?),
            management_token_ttl: secs(resolver.parse("MANAGEMENT_TOKEN_TTL_SECS", 300)?),
            id_token_ttl: secs(resolver.parse("ID_TOKEN_TTL_SECS", 3_600)?),
            // Refresh Tokens default to 30 days (issued with the offline_access scope. With rotation).
            refresh_token_ttl: secs(resolver.parse("REFRESH_TOKEN_TTL_SECS", 2_592_000)?),
            clock_skew: secs(resolver.parse("CLOCK_SKEW_SECS", 60)?),
            password_breach_api_base_url: resolver
                .string("PASSWORD_BREACH_API_BASE_URL", DEFAULT_BREACH_API_BASE_URL),
            outbound_trusted_hosts: resolver.string("OUTBOUND_TRUSTED_HOSTS", ""),
            security_alert_webhook_url: resolver.string("SECURITY_ALERT_WEBHOOK_URL", ""),
            security_alert_webhook_token_file: resolver
                .string("SECURITY_ALERT_WEBHOOK_TOKEN_FILE", ""),
            // Do not start with values that cannot be written (fail-fast. The web goes through the same check)
            silent_auth_frame_ancestors: assay_contracts::frame_ancestors::parse_frame_ancestors(
                &resolver.string("SILENT_AUTH_FRAME_ANCESTORS", ""),
            )
            .map_err(|e| anyhow::anyhow!(e))?,
            app_approver_package_name: resolver.string("APP_APPROVER_PACKAGE_NAME", ""),
            app_approver_signing_cert_sha256: resolver
                .string("APP_APPROVER_SIGNING_CERT_SHA256", ""),
            app_approver_extra_attestation_roots_file: resolver
                .string("APP_APPROVER_EXTRA_ATTESTATION_ROOTS_FILE", ""),
            app_approver_allow_software_attestation: resolver
                .parse("APP_APPROVER_ALLOW_SOFTWARE_ATTESTATION", false)?,
            password_breach_check_timeout: secs(
                resolver.parse("PASSWORD_BREACH_CHECK_TIMEOUT_SECS", 3u64)?,
            ),
            auth_policy_default_effect: DefaultPolicyEffect::parse(
                &resolver.string("AUTH_POLICY_DEFAULT_EFFECT", "allow"),
            )
            .map_err(|e| anyhow::anyhow!("invalid value for AUTH_POLICY_DEFAULT_EFFECT: {e}"))?,
            application_assignment_enforcement: AssignmentEnforcement::parse(
                &resolver.string("APPLICATION_ASSIGNMENT_ENFORCEMENT", "record_only"),
            )
            .map_err(|e| {
                anyhow::anyhow!("invalid value for APPLICATION_ASSIGNMENT_ENFORCEMENT: {e}")
            })?,
            tenant_cache_ttl: secs(resolver.parse("TENANT_CACHE_TTL_SECS", 60)?),
            permission_cache_ttl: secs(resolver.parse("PERMISSION_CACHE_TTL_SECS", 60)?),
            cookie_policy,
            key_encryption_key,
            key_encryption_key_is_dev,
            key_rotation_lead_days: resolver.parse("KEY_ROTATION_LEAD_DAYS", 30)?,
            key_rotation_publish_lead_hours: resolver
                .parse("KEY_ROTATION_PUBLISH_LEAD_HOURS", 24)?,
            app_log_retention_days: resolver.parse("APP_LOG_RETENTION_DAYS", 30)?,
            audit_log_retention_days: resolver.parse("AUDIT_LOG_RETENTION_DAYS", 0u32)?,
            token_endpoint_max_concurrency: resolver
                .parse("TOKEN_ENDPOINT_MAX_CONCURRENCY", 8u32)?,
            token_endpoint_rate_limit_max_requests: resolver
                .parse("TOKEN_ENDPOINT_RATE_LIMIT_MAX_REQUESTS", 300u32)?,
            token_endpoint_rate_limit_window_secs: resolver
                .parse("TOKEN_ENDPOINT_RATE_LIMIT_WINDOW_SECS", 60u64)?,
            api_docs_enabled: resolver.parse("API_DOCS_ENABLED", false)?,
            cors_allowed_origins: resolver.string("CORS_ALLOWED_ORIGINS", ""),
            expired_record_purge_interval_secs: resolver
                .parse("EXPIRED_RECORD_PURGE_INTERVAL_SECS", 3_600u64)?,
            backchannel_logout_max_attempts: resolver
                .parse("BACKCHANNEL_LOGOUT_MAX_ATTEMPTS", 8u32)?,
            backchannel_logout_poll_interval_secs: resolver
                .parse("BACKCHANNEL_LOGOUT_POLL_INTERVAL_SECS", 15u64)?,
            backchannel_logout_retention_days: resolver
                .parse("BACKCHANNEL_LOGOUT_RETENTION_DAYS", 7u32)?,
            trust_forwarded_headers: resolver.parse("TRUST_FORWARDED_HEADERS", false)?,
            hsts_max_age: resolver.parse("HSTS_MAX_AGE", 0u64)?,
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            public_web_base_url,
            public_web_base_url_override,
            resolved_settings: resolver.resolved_settings(),
        })
    }

    /// OIDC issuer (no trailing slash. Must exactly match the ID Token's `iss`).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }
    pub fn database_url(&self) -> &str {
        &self.database_url
    }
    pub fn db_max_connections(&self) -> u32 {
        self.db_max_connections
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
    pub fn auth_session_ttl(&self) -> Duration {
        self.auth_session_ttl
    }
    pub fn authorization_code_ttl(&self) -> Duration {
        self.authorization_code_ttl
    }
    pub fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }
    /// Lifetime of admin API access tokens (ADR-0037). Kept shorter than normal access tokens:
    /// the admin console exchanges from the SSO session on every request so it needs no lifetime, and for system
    /// clients it is the upper bound of "from disabling until it actually stops".
    pub fn management_token_ttl(&self) -> Duration {
        self.management_token_ttl
    }
    pub fn id_token_ttl(&self) -> Duration {
        self.id_token_ttl
    }
    pub fn refresh_token_ttl(&self) -> Duration {
        self.refresh_token_ttl
    }
    pub fn clock_skew(&self) -> Duration {
        self.clock_skew
    }

    /// Endpoint for breached password checks (k-anonymity range API).
    pub fn password_breach_api_base_url(&self) -> &str {
        &self.password_breach_api_base_url
    }
    /// URL to send security notifications to (not sent if empty. task #872).
    pub fn security_alert_webhook_url(&self) -> Option<&str> {
        Some(self.security_alert_webhook_url.trim()).filter(|v| !v.is_empty())
    }
    /// Parents allowed to frame the round trip tried without showing a screen (`prompt=none`) (not allowed if empty. task #888, ADR-0076).
    pub fn silent_auth_frame_ancestors(&self) -> &assay_contracts::frame_ancestors::FrameAncestors {
        &self.silent_auth_frame_ancestors
    }
    /// The file from which the security notification key is read (unset if empty. task #872).
    pub fn security_alert_webhook_token_file(&self) -> Option<&str> {
        Some(self.security_alert_webhook_token_file.trim()).filter(|v| !v.is_empty())
    }
    /// Package name of the authenticator app (closes the authenticator app endpoints if empty. task #892).
    pub fn app_approver_package_name(&self) -> Option<&str> {
        Some(self.app_approver_package_name.trim()).filter(|v| !v.is_empty())
    }
    /// SHA-256 of the authenticator app's signing certificate (`AB:CD:…`, comma-separated. Shape is checked by the consumer).
    pub fn app_approver_signing_cert_sha256(&self) -> &str {
        &self.app_approver_signing_cert_sha256
    }
    /// File of roots trusted in addition to Google's roots (for checks on stg).
    pub fn app_approver_extra_attestation_roots_file(&self) -> Option<&str> {
        Some(self.app_approver_extra_attestation_roots_file.trim()).filter(|v| !v.is_empty())
    }
    /// Whether software keys are also accepted (for checks on stg).
    pub fn app_approver_allow_software_attestation(&self) -> bool {
        self.app_approver_allow_software_attestation
    }
    /// Names allowed to be sent to even if they resolve to internal addresses (task #585).
    pub fn outbound_trust(&self) -> crate::domain::outbound_uri::OutboundTrust {
        crate::domain::outbound_uri::OutboundTrust::parse(&self.outbound_trusted_hosts)
    }
    /// Timeout of one request of the breached password check.
    pub fn password_breach_check_timeout(&self) -> Duration {
        self.password_breach_check_timeout
    }
    /// **The global value** of the default behavior when no authentication policy matches (`allow` / `deny`).
    ///
    /// ⚠ **Not used for decisions.** It is a key tenants decide (ADR-0058 §4), and deciders look up
    /// the tenant's value from `EffectiveTenantSettings`. Reading this would make only that path run on the global value.
    /// It is kept for validating the value's shape at startup and for tests comparing defaults.
    pub fn auth_policy_default_effect(&self) -> DefaultPolicyEffect {
        self.auth_policy_default_effect
    }
    /// **The global value** of how far app assignment checks go (ADR-0054. Default is "record only").
    ///
    /// ⚠ **Not used for decisions** (same reason as `auth_policy_default_effect`. ADR-0058 §4).
    pub fn application_assignment_enforcement(&self) -> AssignmentEnforcement {
        self.application_assignment_enforcement
    }
    /// TTL of the tenant resolution cache (id -> tenant) (ADR-0009 §7).
    pub fn tenant_cache_ttl(&self) -> Duration {
        self.tenant_cache_ttl
    }
    /// TTL of the scope->permission resolution cache (`has_permission`) (ADR-0009 §7).
    pub fn permission_cache_ttl(&self) -> Duration {
        self.permission_cache_ttl
    }
    /// Whether to add the `Secure` attribute to Cookies (design spec §2.4. Can be disabled with an http issuer during development).
    pub fn cookie_secure(&self) -> bool {
        self.cookie_policy.secure()
    }
    /// Cookie attribute policy. The api does not issue browser Cookies (ADR-0018 decision 2), so currently it is
    /// used only as a holder for the resolved `cookie_secure` / `cookie_domain`.
    pub fn cookie_policy(&self) -> &CookiePolicy {
        &self.cookie_policy
    }
    /// The 32-byte key used to encrypt private keys (SigningKeys.private_key_encrypted).
    pub fn key_encryption_key(&self) -> &[u8; 32] {
        &self.key_encryption_key
    }
    /// Whether the development default encryption key is used (a warning target in production).
    pub fn key_encryption_key_is_dev(&self) -> bool {
        self.key_encryption_key_is_dev
    }
    /// Signing key rotation: generate the next key and retire the old one this many days before `not_after` (K2).
    pub fn key_rotation_lead_days(&self) -> u32 {
        self.key_rotation_lead_days
    }

    /// Time from publishing the successor key in JWKS until starting to sign with it.
    pub fn key_rotation_publish_lead_hours(&self) -> u32 {
        self.key_rotation_publish_lead_hours
    }
    /// Retention days of error/warning logs (`0` = never delete).
    pub fn app_log_retention_days(&self) -> u32 {
        self.app_log_retention_days
    }
    /// Retention days of audit logs (`0` = never delete. G8). Not deleting by default because the
    /// retention period of audit logs is an operational decision set by law/contract, not something a default should start deleting.
    pub fn audit_log_retention_days(&self) -> u32 {
        self.audit_log_retention_days
    }
    /// Concurrency limit of token endpoints (SEC10). `None` is unlimited.
    pub fn token_endpoint_max_concurrency(&self) -> Option<usize> {
        (self.token_endpoint_max_concurrency > 0)
            .then_some(self.token_endpoint_max_concurrency as usize)
    }
    /// Per-IP rate limit of token endpoints (SEC10). `None` disables it.
    /// Returns `(max count, window)`.
    pub fn token_endpoint_rate_limit(&self) -> Option<(usize, Duration)> {
        (self.token_endpoint_rate_limit_max_requests > 0).then(|| {
            (
                self.token_endpoint_rate_limit_max_requests as usize,
                Duration::from_secs(self.token_endpoint_rate_limit_window_secs.max(1)),
            )
        })
    }
    /// Whether to serve Swagger UI and the OpenAPI document (SEC12).
    pub fn api_docs_enabled(&self) -> bool {
        self.api_docs_enabled
    }
    /// Additional origins allowed by CORS (G1). Added to origins derived from public clients in the tenant.
    pub fn cors_allowed_origins(&self) -> Vec<String> {
        crate::application::cors_policy::parse_configured_origins(&self.cors_allowed_origins)
    }
    /// Interval of the bulk GC of expired records (G2). `None` means no cleanup (`0` specified).
    pub fn expired_record_purge_interval(&self) -> Option<std::time::Duration> {
        (self.expired_record_purge_interval_secs > 0)
            .then(|| std::time::Duration::from_secs(self.expired_record_purge_interval_secs))
    }
    /// Max resend count of back-channel logout notifications (G5).
    pub fn backchannel_logout_max_attempts(&self) -> u32 {
        self.backchannel_logout_max_attempts
    }
    /// Polling interval of the back-channel logout delivery worker (G5).
    pub fn backchannel_logout_poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.backchannel_logout_poll_interval_secs)
    }
    /// Retention days of settled rows in the back-channel logout delivery queue (`0` = never delete. G5).
    pub fn backchannel_logout_retention_days(&self) -> u32 {
        self.backchannel_logout_retention_days
    }
    /// Whether to trust `X-Forwarded-For` / `X-Forwarded-Proto` added by a reverse proxy (S1).
    pub fn trust_forwarded_headers(&self) -> bool {
        self.trust_forwarded_headers
    }
    /// HSTS `max-age` (seconds). 0 = no HSTS header (S1).
    pub fn hsts_max_age(&self) -> u64 {
        self.hsts_max_age
    }
    /// Service auth token protecting web->api `/internal/*` calls (ADR-0007 §5).
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    /// Whether the development default internal service token is used (a warning target in production).
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    /// CSRF token HMAC key (SEC7). Used to derive CSRF tokens for the sign-in and consent forms.
    /// Set the same value (`CSRF_SECRET` environment variable) in web and api.
    pub fn csrf_secret(&self) -> &[u8; 32] {
        &self.csrf_secret
    }
    /// Whether the development default CSRF secret is used (startup is refused in production).
    pub fn csrf_secret_is_dev(&self) -> bool {
        self.csrf_secret_is_dev
    }

    /// The deployment state of the running process (ADR-0017), passed to the "can the next startup succeed with that value"
    /// check before saving a DB override of a runtime setting.
    ///
    /// Bundles the startup fail-fast conditions whose outcome depends on the value of `ISSUER` (use of development default secrets,
    /// `COOKIE_DOMAIN` / an explicitly set `PUBLIC_WEB_BASE_URL`).
    pub fn deployment_state(&self) -> DeploymentState {
        DeploymentState {
            development_secrets: DevelopmentSecrets {
                key_encryption_key: self.key_encryption_key_is_dev,
                internal_service_token: self.internal_service_token_is_dev,
                csrf_secret: self.csrf_secret_is_dev,
            },
            cookie_domain: self.cookie_domain().map(str::to_string),
            public_web_base_url_override: self.public_web_base_url_override.clone(),
        }
    }
    /// Public base URL of the web screens users open in the browser (no trailing slash. Used for accept links in
    /// invitation emails, etc. Defaults to the same origin as the issuer. MT17).
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }
    /// `COOKIE_DOMAIN` for cleaning up `Domain`-scoped Cookies of the old ADR-0012 setup (ADR-0018 decision 4).
    /// `None` = no cleanup (default). Session Cookies are always issued host-only (web side).
    pub fn cookie_domain(&self) -> Option<&str> {
        self.cookie_policy.legacy_cleanup_domain()
    }

    pub fn resolved_settings(&self) -> &[ResolvedSetting] {
        &self.resolved_settings
    }

    /// Returns the global value **without the DB layer** (environment variable -> built-in default) (ADR-0058).
    ///
    /// Tenant setting resolution falls through "tenant row -> `system_settings` row -> here".
    /// ⚠ **The DB layer is not taken from the startup snapshot ([`Self::resolved_settings`]).**
    /// The snapshot holds DB-derived and environment-derived values without distinction, so after a global override is cleared
    /// it would keep falling back to the supposedly cleared value until restart. Keys moved down to tenants are looked up on every reference
    /// (ADR-0058 §9), so the global layer follows at the same speed.
    ///
    /// Keys not in the definitions and secret keys give `None` (plaintext is never exposed).
    pub fn value_without_db(&self, key: &str) -> Option<String> {
        let def = runtime_setting_definition(key)?;
        if def.secret {
            return None;
        }
        env_lookup(key).or_else(|| def.default_value.map(str::to_string))
    }
}

struct ConfigResolver<'a> {
    db_settings: &'a HashMap<String, String>,
}

impl<'a> ConfigResolver<'a> {
    fn new(db_settings: &'a HashMap<String, String>) -> Self {
        Self { db_settings }
    }

    /// Resolves the effective value. Precedence is "default < ENV < DB".
    ///
    /// Only `DbManaged` keys prefer the DB (the idea that it can later be overridden in the DB).
    /// Others (`EnvLocked` / undefined keys) look only at ENV without consulting the DB. If neither DB nor ENV has it,
    /// `None` (the caller falls back to the default).
    fn optional_string(&self, key: &str) -> Option<String> {
        let db_allowed = runtime_setting_definition(key)
            .map(|def| def.owner == SettingOwner::DbManaged)
            .unwrap_or(false);
        // For DB-managed keys the DB value takes top priority (overrides ENV).
        if db_allowed {
            if let Some(v) = self.db_settings.get(key).filter(|v| !v.is_empty()) {
                return Some(v.clone());
            }
        }
        env_lookup(key)
    }

    fn string(&self, key: &str, default: &str) -> String {
        self.optional_string(key)
            .unwrap_or_else(|| default.to_string())
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

    /// Returns the source of the effective value (same precedence as [`optional_string`]: default < ENV < DB).
    fn source(&self, key: &str) -> SettingSource {
        let db_allowed = runtime_setting_definition(key)
            .map(|def| def.owner == SettingOwner::DbManaged)
            .unwrap_or(false);
        // For DB-managed keys, a DB value, if present, is effective (takes precedence over ENV).
        if db_allowed
            && self
                .db_settings
                .get(key)
                .filter(|v| !v.is_empty())
                .is_some()
        {
            return SettingSource::Db;
        }
        if env_lookup(key).is_some() {
            return SettingSource::Env;
        }
        SettingSource::Builtin
    }

    fn safety_status(&self, key: &str, default_risk: DefaultRisk) -> SettingSafetyStatus {
        match key {
            "KEY_ENCRYPTION_KEY" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "INTERNAL_SERVICE_TOKEN" if env_lookup(key).is_none() => {
                SettingSafetyStatus::NeedsAction
            }
            "CSRF_SECRET" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "COOKIE_SECURE" => match self.optional_string(key) {
                Some(v) if v.eq_ignore_ascii_case("false") => SettingSafetyStatus::NeedsAction,
                None => SettingSafetyStatus::NeedsAction,
                _ => SettingSafetyStatus::Safe,
            },
            "HSTS_MAX_AGE" => match self.optional_string(key) {
                Some(v) if v != "0" => SettingSafetyStatus::Safe,
                _ => SettingSafetyStatus::NeedsAction,
            },
            _ if default_risk == DefaultRisk::Dangerous
                && self.source(key) == SettingSource::Builtin =>
            {
                SettingSafetyStatus::NeedsAction
            }
            _ => SettingSafetyStatus::Safe,
        }
    }

    fn safety_reason(&self, key: &str, default_risk: DefaultRisk) -> String {
        match key {
            "KEY_ENCRYPTION_KEY" | "INTERNAL_SERVICE_TOKEN" | "CSRF_SECRET"
                if env_lookup(key).is_none() =>
            {
                "開発用の既知 secret が使われています。環境変数でランダム値を設定してください。".to_string()
            }
            "COOKIE_SECURE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "Cookie Secure が無効または組み込み既定です。HTTPS 配置では true にしてください。".to_string()
            }
            "HSTS_MAX_AGE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "HSTS が無効です。HTTPS 配置では正の max-age を設定してください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Dangerous => {
                "危険な組み込み既定値が使われています。環境変数または DB 管理値で上書きしてください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Review => {
                "組み込み既定値です。配置環境に適しているか確認してください。".to_string()
            }
            _ => "現在の出所では要対応項目は検出されていません。".to_string(),
        }
    }

    fn resolved_settings(&self) -> Vec<ResolvedSetting> {
        RUNTIME_SETTING_DEFINITIONS
            .iter()
            .map(|def| ResolvedSetting {
                key: def.key.to_string(),
                owner: def.owner,
                source: match def.owner {
                    SettingOwner::Builtin => SettingSource::Builtin,
                    SettingOwner::EnvLocked | SettingOwner::DbManaged => self.source(def.key),
                },
                secret: def.secret,
                restart_required: def.restart_required,
                default_risk: def.default_risk,
                status: self.safety_status(def.key, def.default_risk),
                reason: self.safety_reason(def.key, def.default_risk),
                value: (!def.secret)
                    .then(|| {
                        self.optional_string(def.key)
                            .or_else(|| def.default_value.map(str::to_string))
                    })
                    .flatten(),
                default_value: (!def.secret)
                    .then(|| def.default_value.map(str::to_string))
                    .flatten(),
                description: def.description.to_string(),
            })
            .collect()
    }
}

/// Normalizes a public base URL: drops the trailing slash and **lowercases the scheme**.
///
/// URI schemes are case-insensitive (RFC 3986 §3.1). If notation like `HTTPS://idp.example.com` were not
/// recognized as https, the Cookie `Secure` decision and the production secret fail-fast (both look at the scheme)
/// would slip through. Host and path are kept as is (the issuer must exactly match the ID Token's `iss`,
/// so it is not altered here).
fn normalize_issuer(raw: String) -> String {
    let trimmed = raw.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
        None => trimmed.to_string(),
    }
}

/// Fails startup if development default secrets are used in a production-like deployment.
///
/// The development defaults (`DEV_KEY_ENCRYPTION_KEY`, `DEV_INTERNAL_SERVICE_TOKEN`, `DEV_CSRF_SECRET`) are
/// known values embedded in the source; using them in production effectively disables signing key encryption, `/internal/*` protection and
/// CSRF defense. To avoid them being overlooked as warnings, a missing setting is a configuration error in any deployment
/// other than local loopback (SEC11. Deployments terminating TLS in front and setting `ISSUER` to http are also treated as production).
fn ensure_production_secrets(
    issuer: &str,
    key_encryption_key_is_dev: bool,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    // The decision rule is unified in the domain (to use the same predicate as the pre-save startup check. ADR-0017).
    if !requires_production_secrets(issuer) {
        return Ok(());
    }
    if key_encryption_key_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but KEY_ENCRYPTION_KEY is not set; \
             refusing to start with the built-in development key. \
             Set KEY_ENCRYPTION_KEY (base64, 32 bytes) in production."
        );
    }
    if internal_service_token_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with web) in production."
        );
    }
    if csrf_secret_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but CSRF_SECRET is not set; \
             refusing to start with the built-in development key. \
             Set CSRF_SECRET (base64, 32 bytes, shared with web) in production."
        );
    }
    Ok(())
}

/// Reads `KEY_ENCRYPTION_KEY` (base64, 32 bytes). Uses the development default if unset.
fn load_key_encryption_key() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("KEY_ENCRYPTION_KEY") {
        Some(v) => Ok((decode_secret_32("KEY_ENCRYPTION_KEY", &v)?, false)),
        None => Ok((*DEV_KEY_ENCRYPTION_KEY, true)),
    }
}

/// Reads `NEW_KEY_ENCRYPTION_KEY` (base64, 32 bytes), the destination key of re-wrapping (`assay-rewrap-secrets`).
///
/// A value given only when re-wrapping; not read at api startup. `None` if unset (does not fall back to the development default).
pub fn load_new_key_encryption_key() -> anyhow::Result<Option<[u8; 32]>> {
    env_lookup("NEW_KEY_ENCRYPTION_KEY")
        .map(|v| decode_secret_32("NEW_KEY_ENCRYPTION_KEY", &v))
        .transpose()
}

/// Reads `CSRF_SECRET` (base64, 32 bytes). Uses the development default if unset.
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => Ok((decode_secret_32("CSRF_SECRET", &v)?, false)),
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

/// Checks the minimum requirements of `INTERNAL_SERVICE_TOKEN` (SEC11). The rule lives in the contract shared with web.
fn validate_internal_service_token(value: String) -> anyhow::Result<String> {
    assay_contracts::deployment::validate_internal_service_token(&value)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Decodes a base64 32-byte secret (`KEY_ENCRYPTION_KEY`, `CSRF_SECRET`).
///
/// Starting with the `.env.*.example` placeholder `CHANGE-ME` left in place actually happens a lot
/// (a plain base64 error only says `Invalid symbol 45, offset 6`, which does not lead to the cause), so
/// the placeholder is detected before base64 decoding, with guidance on the fix (`openssl rand -base64 32`).
fn decode_secret_32(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.trim();
    if value.contains("CHANGE-ME") {
        anyhow::bail!(
            "{name} is still the .env template placeholder \"CHANGE-ME\"; \
             replace it with a real value (generate with `openssl rand -base64 32`)"
        );
    }
    let bytes = STANDARD.decode(value).map_err(|e| {
        anyhow::anyhow!("{name} must be base64 (generate with `openssl rand -base64 32`): {e}")
    })?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("{name} must decode to 32 bytes, got {}", b.len()))
}

fn secs(v: u64) -> Duration {
    Duration::from_secs(v)
}

/// Reads an environment variable. **An empty string is treated as "unset"**.
///
/// Docker Compose's `${VAR:-}` injects the key as an empty string even when unspecified, so unless empty is treated as
/// unset, number/bool parsing fails and startup is impossible (e.g. `COOKIE_SECURE=""`).
fn env_lookup(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Reads an environment variable as a string (default if unset or empty). Settings resolution has moved to [`ConfigResolver`],
/// and this is now used only by tests verifying fallback behavior.
#[cfg(test)]
fn env_or(key: &str, default: &str) -> String {
    env_lookup(key).unwrap_or_else(|| default.to_string())
}

/// Reads and parses an environment variable (default if unset or empty). Test-only helper like [`env_or`].
#[cfg(test)]
fn env_parse<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_lookup(key) {
        Some(v) => v
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Lock for serializing tests that touch process-wide environment variables.
    ///
    /// `cargo test` runs tests in parallel on multiple threads in one process, and `std::env` is
    /// shared across the whole process. If tests that set/remove environment variables while building `Config`
    /// run concurrently, one test can read a value set by another and fail nondeterministically
    /// (e.g. mixing up 14 and 7 for `KEY_ROTATION_LEAD_DAYS`). Such tests acquire this lock
    /// to serialize.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Acquires `ENV_LOCK`. Even if another test panics while holding the lock and poisons it,
    /// mutual exclusion itself is preserved, so the inner value is taken out and execution continues.
    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tests using public origins other than loopback are judged production-like (SEC11), so `Config` cannot be built
    /// with the development default secrets. Inject test values.
    fn set_production_secrets() {
        std::env::set_var("KEY_ENCRYPTION_KEY", STANDARD.encode([1u8; 32]));
        std::env::set_var("CSRF_SECRET", STANDARD.encode([2u8; 32]));
        std::env::set_var("INTERNAL_SERVICE_TOKEN", "t".repeat(32));
    }

    fn clear_production_secrets() {
        std::env::remove_var("KEY_ENCRYPTION_KEY");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
    }

    /// MT27: if the startup snapshot and the current DB override value differ, it is "saved but not applied".
    #[test]
    fn pending_restart_compares_the_startup_snapshot_with_the_stored_override() {
        let setting = |source: SettingSource, value: Option<&str>| ResolvedSetting {
            key: "COOKIE_SECURE".to_string(),
            owner: SettingOwner::DbManaged,
            source,
            secret: false,
            restart_required: true,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: value.map(str::to_string),
            default_value: Some("false".to_string()),
            description: String::new(),
        };

        // The value taken from the DB at startup matches the stored value -> applied.
        assert!(!setting(SettingSource::Db, Some("true")).is_pending_restart(Some("true")));
        // The stored value changed -> not applied.
        assert!(setting(SettingSource::Db, Some("true")).is_pending_restart(Some("false")));
        // ENV/default at startup, and a DB override was saved later -> not applied.
        assert!(setting(SettingSource::Env, Some("false")).is_pending_restart(Some("true")));
        // **Removing an override is also not applied** (it was taken from the DB at startup). Missing this would make
        // "removed it but it does not go back to the original value" invisible on screen.
        assert!(setting(SettingSource::Db, Some("true")).is_pending_restart(None));
        // No DB override either at startup or now -> applied.
        assert!(!setting(SettingSource::Env, Some("false")).is_pending_restart(None));
    }

    /// Leftover `system_settings` rows for keys whose owner changed from `DbManaged` to `EnvLocked` (ADR-0012's
    /// `PUBLIC_WEB_BASE_URL`, `COOKIE_DOMAIN`) are not reported as unapplied.
    ///
    /// `EnvLocked` does not look at the DB when resolving, so `source` can never be `Db`, and comparing would show
    /// unapplied forever. Moreover `editable` is false so it cannot be removed from the screen, leaving a warning that does not go away
    /// even after restart. Leftover rows do not affect resolution (they are ignored), so they are not unapplied.
    #[test]
    fn stale_rows_for_env_locked_keys_are_not_reported_as_pending() {
        let env_locked = ResolvedSetting {
            key: "PUBLIC_WEB_BASE_URL".to_string(),
            owner: SettingOwner::EnvLocked,
            // EnvLocked does not consult the DB, so even with a DB row the source can only be Env / Builtin.
            source: SettingSource::Env,
            secret: false,
            restart_required: true,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: Some("https://idp.example.com".to_string()),
            default_value: None,
            description: String::new(),
        };
        assert!(!env_locked.is_pending_restart(Some("https://old.example.com")));
        assert!(!env_locked.is_pending_restart(None));

        // Builtin (always the default) is excluded for the same reason.
        let builtin = ResolvedSetting {
            key: "BIND_ADDR".to_string(),
            owner: SettingOwner::Builtin,
            source: SettingSource::Builtin,
            ..env_locked.clone()
        };
        assert!(!builtin.is_pending_restart(Some("0.0.0.0:9999")));
    }

    /// Keys that need no restart read the DB on every reference, so they are always applied. Secrets leave no plaintext in the
    /// snapshot (cannot be compared), so they are not judged unapplied.
    #[test]
    fn pending_restart_is_never_reported_for_live_or_secret_settings() {
        let base = ResolvedSetting {
            key: "SMTP_HOST".to_string(),
            owner: SettingOwner::DbManaged,
            source: SettingSource::Db,
            secret: false,
            restart_required: false,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: Some("old".to_string()),
            default_value: None,
            description: String::new(),
        };
        assert!(!base.is_pending_restart(Some("new")));

        let secret = ResolvedSetting {
            secret: true,
            restart_required: true,
            value: None,
            ..base.clone()
        };
        assert!(!secret.is_pending_restart(Some("new")));
    }

    #[test]
    fn issuer_is_normalized_without_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://idp.example.com/".to_string()),
            "https://idp.example.com"
        );
        assert_eq!(
            normalize_issuer("https://idp.example.com".to_string()),
            "https://idp.example.com"
        );
        // Schemes are case-insensitive (RFC 3986 §3.1), so lowercase it. Without this,
        // `HTTPS://` notation would slip past the Cookie Secure decision and the production secret fail-fast.
        // The host must exactly match the ID Token's `iss`, so it is kept as is.
        assert_eq!(
            normalize_issuer("HTTPS://IdP.example.com/".to_string()),
            "https://IdP.example.com"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        // https issuer + development defaults -> configuration error (fail-fast).
        assert!(ensure_production_secrets("https://idp.example.com", true, false, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, true, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, false, true).is_err());
        // With everything set explicitly, it can start even on https.
        assert!(ensure_production_secrets("https://idp.example.com", false, false, false).is_ok());
        // http (local development) allows development defaults (only a warning at startup).
        assert!(ensure_production_secrets("http://localhost:8080", true, true, true).is_ok());
    }

    #[test]
    fn secret_decode_rejects_template_placeholder_with_guidance() {
        // A leftover CHANGE-ME from `.env.*.example` gets an explicit cause and fix rather than a base64 error.
        let err = decode_secret_32("KEY_ENCRYPTION_KEY", "CHANGE-ME").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHANGE-ME"), "message was: {msg}");
        assert!(
            msg.contains("openssl rand -base64 32"),
            "message was: {msg}"
        );
    }

    #[test]
    fn secret_decode_accepts_32_bytes_and_reports_bad_input() {
        let encoded = STANDARD.encode([7u8; 32]);
        assert_eq!(
            decode_secret_32("KEY_ENCRYPTION_KEY", &encoded).unwrap(),
            [7u8; 32]
        );
        // Leading/trailing whitespace is tolerated (easily slips in when hand-editing .env).
        assert_eq!(
            decode_secret_32("KEY_ENCRYPTION_KEY", &format!(" {encoded}\n")).unwrap(),
            [7u8; 32]
        );
        let short = decode_secret_32("CSRF_SECRET", &STANDARD.encode([7u8; 16])).unwrap_err();
        assert!(short.to_string().contains("32 bytes, got 16"));
        let not_base64 = decode_secret_32("CSRF_SECRET", "not/base64!!").unwrap_err();
        assert!(not_base64.to_string().contains("openssl rand -base64 32"));
    }

    #[test]
    fn db_managed_settings_override_builtin_defaults() {
        let _env = env_guard();
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 7);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Db);
        assert_eq!(rotation.owner, SettingOwner::DbManaged);
    }

    #[test]
    fn db_managed_settings_override_env() {
        // The "can later be overridden in the DB" idea: for DB_MANAGED keys the DB value overrides ENV.
        let _env = env_guard();
        std::env::set_var("KEY_ROTATION_LEAD_DAYS", "14");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 7);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Db);
        // With only ENV, ENV is effective (default < ENV).
        std::env::set_var("KEY_ROTATION_LEAD_DAYS", "21");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 21);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Env);
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
    }

    /// MT26 / ADR-0013: runtime settings shared by api and web also accept DB overrides
    /// (the web receives the same values from the api's `/internal/runtime-settings` at startup).
    #[test]
    fn shared_web_runtime_settings_are_db_managed() {
        let _env = env_guard();
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
        let db = HashMap::from([
            ("AUTH_SESSION_TTL_SECS".to_string(), "1200".to_string()),
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.auth_session_ttl(), Duration::from_secs(1_200));
        assert!(config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 31_536_000);
        for key in ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"] {
            let setting = config
                .resolved_settings()
                .iter()
                .find(|setting| setting.key == key)
                .unwrap();
            assert_eq!(setting.owner, SettingOwner::DbManaged, "{key}");
            assert_eq!(setting.source, SettingSource::Db, "{key}");
        }
    }

    #[test]
    fn env_locked_settings_ignore_db_values() {
        let _env = env_guard();
        std::env::remove_var("DB_MAX_CONNECTIONS");
        let db = HashMap::from([("DB_MAX_CONNECTIONS".to_string(), "99".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.db_max_connections(), 10);
        let db_max = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "DB_MAX_CONNECTIONS")
            .unwrap();
        assert_eq!(db_max.owner, SettingOwner::EnvLocked);
        assert_eq!(db_max.source, SettingSource::Builtin);
    }

    #[test]
    fn resolved_settings_flag_dangerous_bootstrap_defaults_without_exposing_values() {
        let _env = env_guard();
        std::env::remove_var("KEY_ENCRYPTION_KEY");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        for key in [
            "KEY_ENCRYPTION_KEY",
            "INTERNAL_SERVICE_TOKEN",
            "CSRF_SECRET",
            "COOKIE_SECURE",
            "HSTS_MAX_AGE",
        ] {
            let setting = settings.iter().find(|setting| setting.key == key).unwrap();
            assert_eq!(setting.status, SettingSafetyStatus::NeedsAction);
            assert!(!setting.reason.contains("idp-dev-insecure"));
        }
    }

    #[test]
    fn explicit_secure_cookie_and_hsts_are_marked_safe() {
        let _env = env_guard();
        std::env::set_var("COOKIE_SECURE", "true");
        std::env::set_var("HSTS_MAX_AGE", "31536000");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        let cookie = settings
            .iter()
            .find(|setting| setting.key == "COOKIE_SECURE")
            .unwrap();
        let hsts = settings
            .iter()
            .find(|setting| setting.key == "HSTS_MAX_AGE")
            .unwrap();
        assert_eq!(cookie.status, SettingSafetyStatus::Safe);
        assert_eq!(hsts.status, SettingSafetyStatus::Safe);

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
    }

    #[test]
    fn cookie_domain_is_validated_at_startup() {
        let _env = env_guard();
        set_production_secrets();
        std::env::set_var("ISSUER", "http://api.example.com");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com");

        // Accepted if it is a parent domain of both origins, and the normalized value is kept.
        std::env::set_var("COOKIE_DOMAIN", ".Example.com");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.cookie_domain(), Some("example.com"));

        // Not a parent of one of them, or a public suffix, fails startup (fail-fast).
        std::env::set_var("COOKIE_DOMAIN", "other.com");
        assert!(Config::from_env_and_db_settings(&HashMap::new()).is_err());
        std::env::set_var("COOKIE_DOMAIN", "com");
        assert!(Config::from_env_and_db_settings(&HashMap::new()).is_err());

        // Unset = host-only (conventional behavior).
        std::env::remove_var("COOKIE_DOMAIN");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.cookie_domain(), None);

        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        clear_production_secrets();
    }

    /// ADR-0017: ISSUER accepts DB overrides (to eliminate the state where the discovery document and `iss` stay
    /// `http://localhost:8080` and cannot be fixed). DB takes precedence over ENV.
    #[test]
    fn issuer_is_overridden_by_db_settings() {
        let _env = env_guard();
        // The issuer after the DB override is not loopback, so it is production-like (SEC11).
        set_production_secrets();
        std::env::set_var("ISSUER", "http://localhost:8080");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");

        let db = HashMap::from([("ISSUER".to_string(), "http://idp.example.test/".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        // The trailing slash is normalized (to exactly match `iss`).
        assert_eq!(config.issuer(), "http://idp.example.test");
        // If PUBLIC_WEB_BASE_URL is unset, it is the same origin as the issuer. The DB override reaches there.
        assert_eq!(config.public_web_base_url(), "http://idp.example.test");

        let setting = config
            .resolved_settings()
            .iter()
            .find(|s| s.key == "ISSUER")
            .cloned()
            .unwrap();
        assert_eq!(setting.owner, SettingOwner::DbManaged);
        assert_eq!(setting.source, SettingSource::Db);
        assert_eq!(setting.value.as_deref(), Some("http://idp.example.test/"));

        // Without a DB override it goes back to ENV.
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.issuer(), "http://localhost:8080");

        std::env::remove_var("ISSUER");
        clear_production_secrets();
    }

    #[test]
    fn public_web_base_url_is_env_locked_and_ignores_db() {
        // ADR-0012 §2: changed from DbManaged to EnvLocked because api/web require the same value. DB values are ignored.
        let _env = env_guard();
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("ISSUER");
        let db = HashMap::from([(
            "PUBLIC_WEB_BASE_URL".to_string(),
            "http://db-managed.example.com".to_string(),
        )]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        // Falls back to the default (same origin as the issuer), not the DB value.
        assert_eq!(config.public_web_base_url(), config.issuer());
        let setting = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "PUBLIC_WEB_BASE_URL")
            .unwrap();
        assert_eq!(setting.owner, SettingOwner::EnvLocked);
        assert_eq!(setting.source, SettingSource::Builtin);
    }

    #[test]
    fn env_parse_falls_back_to_default_when_unset() {
        // Unset keys return the default.
        let v: u64 = env_parse("IDP_TEST_DEFINITELY_UNSET_KEY", 42).unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        // Empty strings from Compose's `${VAR:-}` are treated as "unset" and fall back to the default.
        let key = "IDP_TEST_EMPTY_ENV_VAR";
        std::env::set_var(key, "");
        assert_eq!(env_or(key, "fallback"), "fallback");
        let v: bool = env_parse(key, true).unwrap();
        assert!(v);
        std::env::remove_var(key);
    }

    /// The built-in defaults of keys moved down to tenants live **in only one place**, the definition's `default_value` (`Config`
    /// no longer holds them). ⚠ If missing, references from tenants without rows fail converting an empty string.
    #[test]
    fn every_tenant_overridable_key_has_a_builtin_default() {
        let _env = env_guard();
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        for key in tenant_overridable_setting_keys() {
            std::env::remove_var(key);
            let value = config
                .value_without_db(key)
                .unwrap_or_else(|| panic!("{key} has no builtin default"));
            let def = runtime_setting_definition(key).unwrap();
            assert_eq!(validate_setting_value(def, &value), Ok(()), "{key}");
        }
    }

    /// The built-in defaults are the same values as `Config` had before moving them down (⚠ if they drift, the behavior of all tenants
    /// without rows silently changes. ADR-0058 §12 "not a single behavior changes").
    #[test]
    fn tenant_overridable_defaults_are_the_values_config_used_to_have() {
        let _env = env_guard();
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let expected = [
            ("PASSWORD_MIN_LENGTH", "8"),
            ("PASSWORD_HISTORY_COUNT", "5"),
            ("PASSWORD_MAX_AGE_DAYS", "0"),
            ("PASSWORD_BREACH_CHECK_ENABLED", "false"),
            ("LOGIN_MAX_FAILED_ATTEMPTS", "10"),
            ("LOGIN_LOCK_DURATION_SECS", "900"),
            ("LOGIN_MAX_LOCK_DURATION_SECS", "86400"),
            ("SSO_IDLE_TTL_SECS", "28800"),
            ("SSO_ABSOLUTE_TTL_SECS", "86400"),
            ("STEP_UP_MAX_AGE_SECS", "300"),
            ("INVITATION_TTL_SECS", "604800"),
            ("PASSWORD_RESET_TTL_SECS", "3600"),
            ("ACCOUNT_SETUP_TTL_SECS", "86400"),
            ("EMAIL_VERIFICATION_TTL_SECS", "86400"),
            ("PASSWORD_RESET_CONSOLE_LINK_ENABLED", "true"),
            ("AUTH_POLICY_DEFAULT_EFFECT", "allow"),
            ("APPLICATION_ASSIGNMENT_ENFORCEMENT", "record_only"),
            // Added in task #872 (not in `Config` before it was added. Default is "do not notify").
            ("UNREGISTERED_DEVICE_ALERTS_ENABLED", "false"),
            // Added in task #885 (default is "do not use").
            ("SSH_KEYS_ENABLED", "false"),
            // Added in task #887 (lifetime of signed-in states bound to a device key).
            ("SSO_BOUND_TTL_SECS", "2592000"),
            // Added in task #916 (default is "unregistered devices can also get in").
            ("REGISTERED_DEVICE_REQUIRED", "false"),
        ];
        assert_eq!(
            tenant_overridable_setting_keys().count(),
            expected.len(),
            "every tenant-overridable key needs a row in this test"
        );
        for (key, value) in expected {
            std::env::remove_var(key);
            assert_eq!(
                config.value_without_db(key).as_deref(),
                Some(value),
                "{key}"
            );
        }
    }

    /// Startup still fails with global values of the wrong type, as before (fail-fast remains even though `Config` no longer holds them).
    #[test]
    fn an_unparsable_global_value_for_a_tenant_key_still_fails_startup() {
        let _env = env_guard();
        std::env::remove_var("SSO_IDLE_TTL_SECS");
        let db = HashMap::from([("SSO_IDLE_TTL_SECS".to_string(), "eight hours".to_string())]);
        assert!(Config::from_env_and_db_settings(&db).is_err());
    }

    /// Secrets are not shown in `Debug` (task #593). Values do not leak even if dropped into a log with `{:?}`.
    #[test]
    fn debug_output_does_not_carry_the_secrets() {
        let _env = env_guard();
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains(DEV_INTERNAL_SERVICE_TOKEN), "{shown}");
        assert!(!shown.contains(config.database_url()), "{shown}");
        for name in [
            "database_url",
            "key_encryption_key",
            "internal_service_token",
            "csrf_secret",
        ] {
            assert!(!shown.contains(name), "{name}: {shown}");
        }
        assert!(shown.contains("issuer"), "{shown}");
    }
}
