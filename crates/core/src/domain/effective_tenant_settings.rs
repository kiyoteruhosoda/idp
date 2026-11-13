//! Entry point for reading the setting values in effect for a tenant (ADR-0058).
//!
//! Readers of keys a tenant can override (each authentication path, password policy, app gate, link
//! issuance, etc.) read values from **this one trait**, not from the startup `Config` nor a
//! concrete resolver. The implementation is `application::tenant_settings::TenantSettingsService`
//! (tenant row → global row → environment variable → built-in default).
//!
//! ⚠ **If even one path is left reading `Config`, only that path runs on the global value, and is
//! silently wrong.** Readers hold only the trait so that this is blocked by the type.
//!
//! # There used to be two entry points
//!
//! The two decision-default keys (#22) and password / lockout / SSO / step-up etc. (#24) were added
//! separately and reached the same resolver through different entry points (a trait and a concrete
//! type). Both go through the same resolution, so they were merged into one. Writes (`set` /
//! `clear`) and listings for screens are the admin entry point and are not here.
//!
//! # Which tenant to pass (ADR-0058 §13)
//!
//! | Group | Tenant to pass |
//! |---|---|
//! | Password policy, lockout, SSO session lifetime, step-up | the user's **home** tenant |
//! | Password reset and email verification links | the user's **home** tenant |
//! | Invitation links | the **joined** tenant that invited |
//! | Default effect of auth policies, enforcement of app assignment | the tenant making the decision |
//!
//! # The two decision-default keys
//!
//! - `AUTH_POLICY_DEFAULT_EFFECT` — default effect when no auth policy matches
//! - `APPLICATION_ASSIGNMENT_ENFORCEMENT` — whether app assignment checks refuse or only record
//!
//! Both are **decided by the tenant** (§4, §10). This lets tenants whose rosters are ready flip to
//! `enforce`; with one global sheet, "nobody can flip until every tenant's roster is ready".
//! Defaults for tenants with no row are `allow` and `record_only`; ⚠ a tenant without a roster
//! never flips to refusing on its own.
//!
//! When the admin console shows the default effect / enforcement, web does not hold the value; it
//! just draws the tenant's value carried in the api response (not part of ADR-0013's startup
//! snapshot).

use crate::domain::authentication_policy::{DefaultPolicyEffect, LockoutPolicy};
use crate::domain::error::Result;
use crate::domain::password_policy::PasswordPolicy;
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use async_trait::async_trait;
use chrono::Duration;

pub const AUTH_POLICY_DEFAULT_EFFECT: &str = "AUTH_POLICY_DEFAULT_EFFECT";
pub const APPLICATION_ASSIGNMENT_ENFORCEMENT: &str = "APPLICATION_ASSIGNMENT_ENFORCEMENT";
pub const REGISTERED_DEVICE_REQUIRED: &str = "REGISTERED_DEVICE_REQUIRED";

/// SSO session lifetimes (`SSO_IDLE_TTL_SECS` / `SSO_ABSOLUTE_TTL_SECS` / `SSO_BOUND_TTL_SECS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsoSessionLifetime {
    pub idle: Duration,
    pub absolute: Duration,
    /// Length when bound to a device key and the device is registered (task #887; ADR-0074).
    pub bound: Duration,
}

/// Returns values in effect for a tenant, typed.
///
/// Readers leave key spelling and type conversion to this (callers never parse strings). ⚠ When a
/// stored value does not fit the type, it returns an error rather than silently falling back to the
/// global value.
#[async_trait]
pub trait EffectiveTenantSettings: Send + Sync {
    /// Password policy (`PASSWORD_*`).
    async fn password_policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy>;
    /// Lockout (`LOGIN_*`).
    async fn login_lockout(&self, tenant_id: TenantId) -> Result<LockoutPolicy>;
    /// SSO session lifetimes (used both at establishment and for idle extension).
    async fn sso_session_lifetime(&self, tenant_id: TenantId) -> Result<SsoSessionLifetime>;
    /// Validity in seconds of step-up (re-verification right before a sensitive operation).
    async fn step_up_max_age_secs(&self, tenant_id: TenantId) -> Result<u64>;
    /// Validity period of invitation links.
    async fn invitation_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// Validity period of password reset links.
    async fn password_reset_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// Validity period of account setup links (issued by admins; ADR-0062).
    async fn account_setup_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// Whether reset links may be printed to the server console when SMTP cannot send.
    async fn password_reset_console_link_enabled(&self, tenant_id: TenantId) -> Result<bool>;
    /// Validity period of email verification links.
    async fn email_verification_ttl(&self, tenant_id: TenantId) -> Result<Duration>;
    /// Default effect when no auth policy matches.
    async fn policy_default_effect(&self, tenant_id: TenantId) -> Result<DefaultPolicyEffect>;
    /// How far the app assignment check goes.
    async fn assignment_enforcement(&self, tenant_id: TenantId) -> Result<AssignmentEnforcement>;
    /// Whether to alert on sign-ins from unregistered devices, device registrations, etc. (task
    /// #872).
    async fn unregistered_device_alerts_enabled(&self, tenant_id: TenantId) -> Result<bool>;
    /// Whether sign-ins complete only on registered devices (and authenticator app approval) (task
    /// #916). Pass the user's **home** tenant.
    async fn registered_device_required(&self, tenant_id: TenantId) -> Result<bool>;
    /// Whether users may register SSH public keys and the list is handed to distributing machines
    /// (task #885). Pass the **requested** tenant.
    async fn ssh_keys_enabled(&self, tenant_id: TenantId) -> Result<bool>;
}
