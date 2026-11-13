//! Resolution of tenant settings (ADR-0058).
//!
//! # Resolution order
//!
//! 1. **The tenant's rows** (`tenant_settings`): apply only to that tenant
//! 2. **Global rows** (`system_settings`)
//! 3. **Environment variable -> built-in default** (resolved at startup. Environment variables do not change at runtime)
//!
//! ⚠ **A tenant having no row is what "follows global" means.** Copies of default values are not handed out to tenants.
//! Copying would make that tenant stop following when the global value changes, while looking like the same value on screen.
//!
//! # Looked up on every reference
//!
//! Values differing per tenant cannot be expressed by resolving one at startup and handing it out via `Config` (ADR-0058 §9).
//! So 1 and 2 are looked up **on every reference**, kept cheap by a TTL cache (same lifetime as tenant resolution).
//! ⚠ **2 (global rows) is not taken from a snapshot either.** The startup `Config` holds DB-derived values and
//! environment-derived values without distinction, so after clearing a global override the old value would remain until restart.
//!
//! # Only "keys tenants can override" go through this endpoint
//!
//! Passing a key with `scope = Global` is refused. Global keys are read from `Config` as before: letting them
//! through here would make callers use the global value while mistakenly believing "it runs on the tenant's value".
//! Conversely, ⚠ **leave no place that reads a tenant-overridable key directly from `Config`** (only that place would
//! run on the global value, and be silently wrong).
//!
//! # Which tenant's value is used (ADR-0058 §13)
//!
//! Consumers look up through the domain trait [`EffectiveTenantSettings`] (implemented by the typed endpoints below). The tenant
//! passed is as follows, and ⚠ **always pass the same tenant for issuance and verification** (if only one differs,
//! links or sessions appear that are already expired right after issuance).
//!
//! | Group | Tenant passed | Reason |
//! |---|---|---|
//! | Password policy, lockout | The user's **home** | Credentials and lock state live in the user's row, managed only by the home tenant (ADR-0009 §2) |
//! | SSO session lifetime, step-up interval | The user's **home** | SSO sessions are shared per host across all tenants and have no tenant column |
//! | Password reset and email verification links | The user's **home** | Links point to the home tenant and can be consumed only there (MT26) |
//! | Invitation links | The inviting **joined** tenant | An invitation is a membership row of the joined tenant |

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::{DefaultPolicyEffect, LockoutPolicy};
use crate::domain::cache::Cache;
use crate::domain::effective_tenant_settings::{
    EffectiveTenantSettings, SsoSessionLifetime, APPLICATION_ASSIGNMENT_ENFORCEMENT,
    AUTH_POLICY_DEFAULT_EFFECT, REGISTERED_DEVICE_REQUIRED,
};
use crate::domain::error::{DomainError, Result};
use crate::domain::password_policy::{PasswordPolicy, MAX_PASSWORD_LEN};
use crate::domain::repositories::{SystemSettingsRepository, TenantSettingsRepository};
use crate::domain::system_setting::{
    runtime_setting_definition, validate_setting_value, SettingDefinition, SettingScope,
    RUNTIME_SETTING_DEFINITIONS,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_setting::{TenantOverrideEntry, TenantSetting};
use crate::domain::values::AssignmentEnforcement;
use async_trait::async_trait;
use chrono::Duration;
use std::collections::HashMap;
use std::sync::Arc;

/// A copy of stored overrides (key -> stored-format value). Rows with empty strings are excluded.
pub type SettingOverrides = HashMap<String, String>;

/// Where a resolved value came from. Held so the screen can tell "decided in this tenant" from "following global"
/// (ADR-0058 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingOrigin {
    /// A value overridden in this tenant.
    TenantOverride,
    /// Following the global value (a global row, environment variable, or built-in default).
    Inherited,
}

/// A setting value resolved for a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTenantSetting {
    pub value: String,
    pub origin: SettingOrigin,
}

/// One item listed on the tenant settings screen (ADR-0058 §6).
///
/// ⚠ **Do not show only the value.** Always hold together whether it was "decided in this tenant" or "following global" (`origin`) and
/// the global value (`whole_idp_value`). The global value is listed even for overridden items so that
/// users do not revert without being able to read "what it becomes when reverted to global".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSettingView {
    pub definition: &'static SettingDefinition,
    /// The value in effect in this tenant.
    pub value: String,
    pub origin: SettingOrigin,
    /// The global value (global row -> environment variable -> built-in default). Clearing the override reverts to this value.
    pub whole_idp_value: String,
}

/// For a key, how all tenants decide it (read by the global settings screen. ADR-0058 §6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantSettingAdoption {
    /// Number of tenants following the global value (having no row).
    pub following: u64,
    /// Tenants deviating from the default (overriding this key).
    pub overriding: Vec<TenantOverrideEntry>,
}

pub struct TenantSettingsService {
    tenant_settings: Arc<dyn TenantSettingsRepository>,
    system_settings: Arc<dyn SystemSettingsRepository>,
    /// The global value excluding the DB (environment variable -> built-in default). Held only for keys tenants can override.
    /// Assembled by the wiring side with `Config::value_without_db` (this service does not depend on `Config`).
    fallback: HashMap<String, String>,
    tenant_cache: Arc<dyn Cache<TenantId, SettingOverrides>>,
    /// Cache of global rows. There is only one key space, so `()` is the key.
    global_cache: Arc<dyn Cache<(), SettingOverrides>>,
    audit: Arc<AuditService>,
}

impl TenantSettingsService {
    pub fn new(
        tenant_settings: Arc<dyn TenantSettingsRepository>,
        system_settings: Arc<dyn SystemSettingsRepository>,
        fallback: HashMap<String, String>,
        tenant_cache: Arc<dyn Cache<TenantId, SettingOverrides>>,
        global_cache: Arc<dyn Cache<(), SettingOverrides>>,
        audit: Arc<AuditService>,
    ) -> Self {
        Self {
            tenant_settings,
            system_settings,
            fallback,
            tenant_cache,
            global_cache,
            audit,
        }
    }

    /// Resolves a key's value for a tenant (tenant row > global row > environment variable > built-in default).
    pub async fn resolve(&self, tenant_id: TenantId, key: &str) -> Result<ResolvedTenantSetting> {
        let def = overridable_definition(key)?;
        if let Some(value) = self.tenant_overrides(tenant_id).await?.get(def.key) {
            return Ok(ResolvedTenantSetting {
                value: value.clone(),
                origin: SettingOrigin::TenantOverride,
            });
        }
        Ok(ResolvedTenantSetting {
            value: self.whole_idp_value(def).await?,
            origin: SettingOrigin::Inherited,
        })
    }

    /// The global value (global row -> environment variable -> built-in default). Tenant rows are not looked at.
    async fn whole_idp_value(&self, def: &SettingDefinition) -> Result<String> {
        Ok(match self.global_overrides().await?.get(def.key) {
            Some(value) => value.clone(),
            None => self.fallback.get(def.key).cloned().unwrap_or_default(),
        })
    }

    /// Returns all items tenants can override, with origin and global value (in definition order).
    ///
    /// Items are derived from the key definitions (`scope = TenantOverridable`), so screens and API types need not
    /// be extended every time a key is added.
    pub async fn list(&self, tenant_id: TenantId) -> Result<Vec<TenantSettingView>> {
        let tenant = self.tenant_overrides(tenant_id).await?;
        let mut views = Vec::new();
        for def in overridable_definitions() {
            let whole_idp_value = self.whole_idp_value(def).await?;
            let (value, origin) = match tenant.get(def.key) {
                Some(value) => (value.clone(), SettingOrigin::TenantOverride),
                None => (whole_idp_value.clone(), SettingOrigin::Inherited),
            };
            views.push(TenantSettingView {
                definition: def,
                value,
                origin,
                whole_idp_value,
            });
        }
        Ok(views)
    }

    /// Decides a tenant's value (writes a row).
    ///
    /// - Keys not in the definitions, globally decided keys, and secret keys are refused (`InvalidValue`)
    /// - Types go through the same `validate_setting_value` as global saves
    /// - ⚠ **Values that may lock people out** (the definition's `locks_out`) are not saved without `confirmed`; `Conflict` is returned.
    ///   The screen asks for confirmation and then resends with `confirmed`
    /// - Empty values are not accepted. Reverting to global is [`Self::clear`] (leaving an empty row would make it unreadable from the row
    ///   whether it was "decided" or "reverted")
    pub async fn set(
        &self,
        tenant: TenantContext,
        key: &str,
        value: &str,
        confirmed: bool,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<()> {
        let def = overridable_definition(key)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::InvalidValue(format!(
                "setting {key} needs a value; clear the override to follow the whole IdP"
            )));
        }
        validate_setting_value(def, value).map_err(DomainError::InvalidValue)?;
        if def.needs_confirmation(value) && !confirmed {
            return Err(DomainError::Conflict(format!(
                "setting {key} = {value} can lock users out and needs confirmation"
            )));
        }
        let tenant_id = tenant.tenant_id();
        self.tenant_settings
            .upsert(&TenantSetting {
                tenant_id,
                key: def.key.to_string(),
                value: value.to_string(),
                is_secret: false,
            })
            .await?;
        self.invalidate(tenant_id);
        self.record(tenant_id, def.key, "set", actor, ctx).await;
        Ok(())
    }

    /// Clears the tenant's override (= goes back to following global). Succeeds even if there is no row.
    pub async fn clear(
        &self,
        tenant: TenantContext,
        key: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<()> {
        let def = overridable_definition(key)?;
        let tenant_id = tenant.tenant_id();
        self.tenant_settings.delete(tenant_id, def.key).await?;
        self.invalidate(tenant_id);
        self.record(tenant_id, def.key, "cleared", actor, ctx).await;
        Ok(())
    }

    async fn record(
        &self,
        tenant_id: TenantId,
        key: &str,
        change: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::TenantSettingsUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                // The value itself is not recorded (only the key and whether it was set or cleared).
                Some(&format!("{key} {change}")),
                ctx,
            )
            .await;
    }

    /// For each key tenants can override, returns the number of tenants following it and the tenants deviating from it.
    ///
    /// ⚠ Reads across tenants. Only the global settings screen (`idp.system.admin`) may call this.
    pub async fn adoption_across_tenants(
        &self,
    ) -> Result<HashMap<&'static str, TenantSettingAdoption>> {
        let across = self.tenant_settings.list_overrides_across_tenants().await?;
        let mut adoption: HashMap<&'static str, TenantSettingAdoption> = overridable_definitions()
            .map(|def| (def.key, TenantSettingAdoption::default()))
            .collect();
        for entry in across.overrides {
            // Rows not in the definitions and rows of global keys are not counted (do not show ineffective rows as "deviating").
            if let Some((_, item)) = adoption.iter_mut().find(|(key, _)| **key == entry.key) {
                item.overriding.push(entry);
            }
        }
        for item in adoption.values_mut() {
            item.following = across
                .tenant_count
                .saturating_sub(item.overriding.len() as u64);
        }
        Ok(adoption)
    }

    /// Converts a key's value for a tenant into its type and returns it.
    ///
    /// ⚠ If conversion fails, **return an error instead of silently falling back to global.** Types are validated at save time
    /// (`validate_setting_value`), so failing here only happens when the DB was edited directly, and
    /// silently falling back would hide "overridden but not taking effect".
    pub async fn parse<T>(&self, tenant_id: TenantId, key: &str) -> Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let resolved = self.resolve(tenant_id, key).await?;
        resolved.value.parse::<T>().map_err(|e| {
            DomainError::InvalidValue(format!(
                "stored value for {key} ({:?}) cannot be parsed: {e}",
                resolved.origin
            ))
        })
    }

    /// That tenant's overrides (as stored. Empty rows are excluded).
    pub async fn tenant_overrides(&self, tenant_id: TenantId) -> Result<SettingOverrides> {
        if let Some(cached) = self.tenant_cache.get(&tenant_id) {
            return Ok(cached);
        }
        let loaded: SettingOverrides = self
            .tenant_settings
            .load_for_tenant(tenant_id)
            .await?
            .into_iter()
            .filter(|setting| !setting.value.is_empty())
            .map(|setting| (setting.key, setting.value))
            .collect();
        self.tenant_cache.insert(tenant_id, loaded.clone());
        Ok(loaded)
    }

    /// Called after rewriting a tenant's overrides (forces the next reference to re-read the DB).
    pub fn invalidate(&self, tenant_id: TenantId) {
        self.tenant_cache.invalidate(&tenant_id);
    }

    /// Called after rewriting global settings.
    pub fn invalidate_global(&self) {
        self.global_cache.invalidate(&());
    }

    async fn global_overrides(&self) -> Result<SettingOverrides> {
        if let Some(cached) = self.global_cache.get(&()) {
            return Ok(cached);
        }
        let loaded: SettingOverrides = self
            .system_settings
            .load_all()
            .await?
            .into_iter()
            // Do not mix secret ciphertext into tenant resolution (no key tenants can override is a secret).
            .filter(|setting| !setting.is_secret && !setting.value.is_empty())
            .map(|setting| (setting.key, setting.value))
            .collect();
        self.global_cache.insert((), loaded.clone());
        Ok(loaded)
    }
}

/// Typed endpoints. Consumers leave key spelling and type conversion to these (callers are not made to write `parse`).
///
/// Readers hold only [`EffectiveTenantSettings`] (the domain trait). This implementation is not passed
/// as the concrete type (ADR-0058. Do not have two endpoints).
#[async_trait]
impl EffectiveTenantSettings for TenantSettingsService {
    /// Password policy (`PASSWORD_*`). Pass the user's **home** tenant.
    async fn password_policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy> {
        Ok(PasswordPolicy {
            min_length: self.parse(tenant_id, "PASSWORD_MIN_LENGTH").await?,
            // The upper limit is a defense on hashing cost (argon2 input length), not a value to relax in operation,
            // so it is not a setting and the domain default is used.
            max_length: MAX_PASSWORD_LEN,
            history_count: self.parse(tenant_id, "PASSWORD_HISTORY_COUNT").await?,
            max_age_days: self.parse(tenant_id, "PASSWORD_MAX_AGE_DAYS").await?,
            reject_breached: self
                .parse(tenant_id, "PASSWORD_BREACH_CHECK_ENABLED")
                .await?,
        })
    }

    /// Lockout (`LOGIN_*`). Pass the user's **home** tenant.
    async fn login_lockout(&self, tenant_id: TenantId) -> Result<LockoutPolicy> {
        let max_failed_attempts: u32 = self.parse(tenant_id, "LOGIN_MAX_FAILED_ATTEMPTS").await?;
        Ok(LockoutPolicy {
            // Huge values not fitting in i32 saturate to i32::MAX as "effectively never lock"
            // (an `as` cast would wrap to a negative number, giving the opposite behavior of locking immediately on the first failure).
            max_failed_attempts: i32::try_from(max_failed_attempts).unwrap_or(i32::MAX),
            lock_duration_secs: self.parse(tenant_id, "LOGIN_LOCK_DURATION_SECS").await?,
            max_lock_duration_secs: self
                .parse(tenant_id, "LOGIN_MAX_LOCK_DURATION_SECS")
                .await?,
        })
    }

    /// SSO session lifetime. Pass the user's **home** tenant (for both establishment and idle extension).
    async fn sso_session_lifetime(&self, tenant_id: TenantId) -> Result<SsoSessionLifetime> {
        Ok(SsoSessionLifetime {
            idle: self.seconds(tenant_id, "SSO_IDLE_TTL_SECS").await?,
            absolute: self.seconds(tenant_id, "SSO_ABSOLUTE_TTL_SECS").await?,
            bound: self.seconds(tenant_id, "SSO_BOUND_TTL_SECS").await?,
        })
    }

    /// Validity in seconds of step-up (identity verification right before sensitive operations). Pass the user's **home** tenant.
    async fn step_up_max_age_secs(&self, tenant_id: TenantId) -> Result<u64> {
        self.parse(tenant_id, "STEP_UP_MAX_AGE_SECS").await
    }

    /// Validity period of invitation links. Pass the inviting **joined** tenant.
    async fn invitation_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "INVITATION_TTL_SECS").await
    }

    /// Validity period of password reset links. Pass the user's **home** tenant.
    async fn password_reset_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "PASSWORD_RESET_TTL_SECS").await
    }

    /// Validity period of account setup links. Pass the user's **home** tenant.
    ///
    /// It is longer than reset because delivery differs: a reset is clicked by the user "now" and received in their own email,
    /// while a setup link is received by an admin and passed on by hand (ADR-0062).
    async fn account_setup_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "ACCOUNT_SETUP_TTL_SECS").await
    }

    /// Whether reset links may be printed to the server console when SMTP cannot send.
    async fn password_reset_console_link_enabled(&self, tenant_id: TenantId) -> Result<bool> {
        self.parse(tenant_id, "PASSWORD_RESET_CONSOLE_LINK_ENABLED")
            .await
    }

    /// Validity period of email verification links. Pass the user's **home** tenant.
    async fn email_verification_ttl(&self, tenant_id: TenantId) -> Result<Duration> {
        self.seconds(tenant_id, "EMAIL_VERIFICATION_TTL_SECS").await
    }

    /// Default behavior of authentication policies. Pass the tenant making the decision.
    async fn policy_default_effect(&self, tenant_id: TenantId) -> Result<DefaultPolicyEffect> {
        let resolved = self.resolve(tenant_id, AUTH_POLICY_DEFAULT_EFFECT).await?;
        DefaultPolicyEffect::parse(&resolved.value)
            .map_err(|e| unparsable(AUTH_POLICY_DEFAULT_EFFECT, e))
    }

    /// Enforcement of app assignments. Pass the tenant making the decision.
    async fn assignment_enforcement(&self, tenant_id: TenantId) -> Result<AssignmentEnforcement> {
        let resolved = self
            .resolve(tenant_id, APPLICATION_ASSIGNMENT_ENFORCEMENT)
            .await?;
        AssignmentEnforcement::parse(&resolved.value)
            .map_err(|e| unparsable(APPLICATION_ASSIGNMENT_ENFORCEMENT, e))
    }

    /// Whether to notify sign-ins on unregistered devices (task #872). Pass the user's **home** tenant.
    async fn unregistered_device_alerts_enabled(&self, tenant_id: TenantId) -> Result<bool> {
        self.parse(tenant_id, "UNREGISTERED_DEVICE_ALERTS_ENABLED")
            .await
    }

    /// Whether sign-in completes only on registered devices (task #916). Pass the user's **home** tenant.
    async fn registered_device_required(&self, tenant_id: TenantId) -> Result<bool> {
        self.parse(tenant_id, REGISTERED_DEVICE_REQUIRED).await
    }

    /// Whether SSH public key registration and distribution are used (task #885). Pass the requested tenant (the organization where the key was registered).
    async fn ssh_keys_enabled(&self, tenant_id: TenantId) -> Result<bool> {
        self.parse(tenant_id, "SSH_KEYS_ENABLED").await
    }
}

impl TenantSettingsService {
    async fn seconds(&self, tenant_id: TenantId, key: &str) -> Result<Duration> {
        let secs: u64 = self.parse(tenant_id, key).await?;
        i64::try_from(secs)
            .ok()
            .and_then(Duration::try_seconds)
            .ok_or_else(|| DomainError::InvalidValue(format!("{key} is out of range: {secs}")))
    }
}

/// A stored value does not match its type. ⚠ Do not silently fall back to global (same handling as [`TenantSettingsService::parse`]).
fn unparsable(key: &str, error: DomainError) -> DomainError {
    DomainError::InvalidValue(format!("stored value for {key} cannot be parsed: {error}"))
}

/// Definitions of keys tenants can override (non-secret). In definition order.
fn overridable_definitions() -> impl Iterator<Item = &'static SettingDefinition> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .filter(|def| def.scope == SettingScope::TenantOverridable && !def.secret)
}

/// Returns the definition of a key tenants can override. Refuses otherwise.
fn overridable_definition(key: &str) -> Result<&'static SettingDefinition> {
    let def = runtime_setting_definition(key)
        .ok_or_else(|| DomainError::InvalidValue(format!("unknown setting key: {key}")))?;
    if def.scope != SettingScope::TenantOverridable {
        return Err(DomainError::InvalidValue(format!(
            "setting {key} is decided by the whole IdP, not by a tenant"
        )));
    }
    // Secrets need a separate decryption endpoint (SMTP in ADR-0058 §8). Plaintext and ciphertext are not returned from the same endpoint.
    if def.secret {
        return Err(DomainError::InvalidValue(format!(
            "setting {key} is secret and cannot be resolved as plain text"
        )));
    }
    Ok(def)
}

/// The base used by consumers' unit tests (ADR-0058).
///
/// ⚠ **Tests put rows directly into the repository.** Going through the write endpoints (`set` / `clear`) would drag
/// consumers' tests into the concerns of auditing and input validation.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::clock::Clock;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::system_setting::{tenant_overridable_setting_keys, SystemSetting};
    use crate::domain::tenant_setting::TenantOverridesAcrossTenants;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeTenantSettings {
        pub rows: Mutex<Vec<TenantSetting>>,
        pub loads: AtomicUsize,
        /// Number of tenants holding no rows at all (for cross-tenant aggregation tests).
        pub extra_tenants: Mutex<u64>,
    }

    impl FakeTenantSettings {
        /// Inserts a secret row (for testing that rows like the SMTP password do not leak into aggregation).
        pub fn put_secret(&self, tenant_id: TenantId, key: &str, value: &str) {
            self.rows.lock().unwrap().push(TenantSetting {
                tenant_id,
                key: key.to_string(),
                value: value.to_string(),
                is_secret: true,
            });
        }
    }

    impl FakeTenantSettings {
        pub fn put(&self, tenant_id: TenantId, key: &str, value: &str) {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|row| !(row.tenant_id == tenant_id && row.key == key));
            rows.push(TenantSetting {
                tenant_id,
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            });
        }
    }

    #[async_trait]
    impl TenantSettingsRepository for FakeTenantSettings {
        async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|row| row.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn upsert(&self, setting: &TenantSetting) -> Result<()> {
            self.put(setting.tenant_id, &setting.key, &setting.value);
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|row| !(row.tenant_id == tenant_id && row.key == key));
            Ok(())
        }
        async fn list_overrides_across_tenants(&self) -> Result<TenantOverridesAcrossTenants> {
            let rows = self.rows.lock().unwrap();
            let mut tenants: Vec<TenantId> = rows.iter().map(|row| row.tenant_id).collect();
            tenants.sort_by_key(|id| id.to_string());
            tenants.dedup();
            Ok(TenantOverridesAcrossTenants {
                // Tenants without rows are counted too (`extra_tenants` of them).
                tenant_count: tenants.len() as u64 + *self.extra_tenants.lock().unwrap(),
                overrides: rows
                    .iter()
                    .filter(|row| !row.is_secret && !row.value.is_empty())
                    .map(|row| TenantOverrideEntry {
                        tenant_id: row.tenant_id,
                        tenant_name: format!("tenant-{}", row.tenant_id),
                        key: row.key.clone(),
                        value: row.value.clone(),
                    })
                    .collect(),
            })
        }
    }

    /// A sink that just accumulates audit events.
    #[derive(Default)]
    pub struct CapturingSink {
        pub events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct EpochClock;
    impl Clock for EpochClock {
        fn now(&self) -> DateTime<Utc> {
            DateTime::<Utc>::UNIX_EPOCH
        }
    }

    /// Audit service for tests (records are kept in `CapturingSink` instead of discarded).
    pub fn audit(sink: Arc<CapturingSink>) -> Arc<AuditService> {
        Arc::new(AuditService::new(sink, Arc::new(EpochClock)))
    }

    #[derive(Default)]
    pub struct FakeSystemSettings {
        pub rows: Mutex<Vec<SystemSetting>>,
    }

    #[async_trait]
    impl SystemSettingsRepository for FakeSystemSettings {
        async fn load_all(&self) -> Result<Vec<SystemSetting>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> Result<()> {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|row| row.key != setting.key);
            rows.push(setting.clone());
            Ok(())
        }
    }

    /// A cache that remembers nothing. Rows added mid-test are always visible on the next reference.
    pub struct NoCache;

    impl<K, V> Cache<K, V> for NoCache {
        fn get(&self, _key: &K) -> Option<V> {
            None
        }
        fn insert(&self, _key: K, _value: V) {}
        fn invalidate(&self, _key: &K) {}
    }

    /// A resolver with no rows (= all tenants follow built-in defaults), and a repository for inserting rows.
    pub struct TenantSettingsFixture {
        pub service: Arc<TenantSettingsService>,
        pub tenants: Arc<FakeTenantSettings>,
        pub system: Arc<FakeSystemSettings>,
    }

    impl TenantSettingsFixture {
        /// Inserts a row for that tenant (the tenant's override).
        pub fn set_tenant(&self, tenant_id: TenantId, key: &str, value: &str) {
            self.tenants.put(tenant_id, key, value);
        }

        /// Inserts a global row (`system_settings`).
        pub fn set_global(&self, key: &str, value: &str) {
            let mut rows = self.system.rows.lock().unwrap();
            rows.retain(|row| row.key != key);
            rows.push(SystemSetting {
                key: key.to_string(),
                value: value.to_string(),
                is_secret: false,
            });
        }
    }

    /// A resolver whose last layer is the built-in default (the definition's `default_value`).
    pub fn tenant_settings() -> TenantSettingsFixture {
        let fallback = tenant_overridable_setting_keys()
            .filter_map(|key| {
                runtime_setting_definition(key)
                    .and_then(|def| def.default_value)
                    .map(|value| (key.to_string(), value.to_string()))
            })
            .collect();
        let tenants = Arc::new(FakeTenantSettings::default());
        let system = Arc::new(FakeSystemSettings::default());
        let service = Arc::new(TenantSettingsService::new(
            tenants.clone(),
            system.clone(),
            fallback,
            Arc::new(NoCache),
            Arc::new(NoCache),
            audit(Arc::new(CapturingSink::default())),
        ));
        TenantSettingsFixture {
            service,
            tenants,
            system,
        }
    }

    /// A resolver that changes the global value of only some keys from the built-in defaults (for tests that used to inject values via `Config`).
    pub fn tenant_settings_with_global(values: &[(&str, &str)]) -> Arc<TenantSettingsService> {
        let fixture = tenant_settings();
        for (key, value) in values {
            fixture.set_global(key, value);
        }
        fixture.service
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{CapturingSink, FakeSystemSettings, FakeTenantSettings};
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::system_setting::SystemSetting;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::atomic::Ordering;
    use uuid::Uuid;

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct Fixture {
        service: TenantSettingsService,
        tenants: Arc<FakeTenantSettings>,
        system: Arc<FakeSystemSettings>,
        audit: Arc<CapturingSink>,
    }

    fn fixture() -> Fixture {
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
        ));
        let tenants = Arc::new(FakeTenantSettings::default());
        let system = Arc::new(FakeSystemSettings::default());
        let audit = Arc::new(CapturingSink::default());
        // The environment variable -> built-in default layer (what the wiring side builds with `Config::value_without_db`).
        let fallback = HashMap::from([
            ("PASSWORD_MIN_LENGTH".to_string(), "8".to_string()),
            ("LOGIN_MAX_FAILED_ATTEMPTS".to_string(), "10".to_string()),
        ]);
        let service = TenantSettingsService::new(
            tenants.clone(),
            system.clone(),
            fallback,
            Arc::new(InMemoryTtlCache::new(Duration::seconds(60), clock.clone())),
            Arc::new(InMemoryTtlCache::new(Duration::seconds(60), clock)),
            super::testing::audit(audit.clone()),
        );
        Fixture {
            service,
            tenants,
            system,
            audit,
        }
    }

    fn tenant() -> TenantId {
        Uuid::now_v7().into()
    }

    fn global_row(key: &str, value: &str) -> SystemSetting {
        SystemSetting {
            key: key.to_string(),
            value: value.to_string(),
            is_secret: false,
        }
    }

    #[tokio::test]
    async fn a_tenant_without_a_row_follows_the_fallback() {
        let f = fixture();
        let resolved = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGTH")
            .await
            .unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    #[tokio::test]
    async fn the_whole_idp_row_beats_the_fallback() {
        let f = fixture();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        let resolved = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGTH")
            .await
            .unwrap();
        assert_eq!(resolved.value, "12");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    #[tokio::test]
    async fn the_tenant_row_beats_the_whole_idp_row() {
        let f = fixture();
        let t = tenant();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "16");
        assert_eq!(resolved.origin, SettingOrigin::TenantOverride);
    }

    /// ⚠ A single-tenant test would pass even if it read the global value. Put different values in 2 tenants and
    /// check that neither sees the other's rows.
    #[tokio::test]
    async fn two_tenants_see_only_their_own_rows() {
        let f = fixture();
        let (a, b, c) = (tenant(), tenant(), tenant());
        f.tenants.put(a, "PASSWORD_MIN_LENGTH", "10");
        f.tenants.put(b, "PASSWORD_MIN_LENGTH", "20");

        assert_eq!(
            f.service
                .parse::<usize>(a, "PASSWORD_MIN_LENGTH")
                .await
                .unwrap(),
            10
        );
        assert_eq!(
            f.service
                .parse::<usize>(b, "PASSWORD_MIN_LENGTH")
                .await
                .unwrap(),
            20
        );
        // A tenant without rows follows global.
        let resolved = f.service.resolve(c, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// A key without an override follows global even in a tenant that overrode another key (no copies of defaults are made).
    #[tokio::test]
    async fn overriding_one_key_does_not_pin_the_others() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("LOGIN_MAX_FAILED_ATTEMPTS", "3"));

        let resolved = f
            .service
            .resolve(t, "LOGIN_MAX_FAILED_ATTEMPTS")
            .await
            .unwrap();
        assert_eq!(resolved.value, "3");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
        assert_eq!(f.tenants.rows.lock().unwrap().len(), 1, "no row is copied");
    }

    /// An empty row is the same as "no row" (same handling as `system_settings`).
    #[tokio::test]
    async fn an_empty_row_means_no_override() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "");
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "8");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// Globally decided keys do not go through this endpoint. If they did, callers would use the global value while mistakenly
    /// believing "it runs on the tenant's value".
    #[tokio::test]
    async fn keys_decided_by_the_whole_idp_are_refused() {
        let f = fixture();
        for key in ["ACCESS_TOKEN_TTL_SECS", "ISSUER", "COOKIE_SECURE"] {
            let err = f.service.resolve(tenant(), key).await.unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "{key}");
        }
    }

    #[tokio::test]
    async fn unknown_keys_are_refused() {
        let f = fixture();
        let err = f
            .service
            .resolve(tenant(), "PASSWORD_MIN_LENGHT")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }

    /// The cache returns old values after a rewrite until discarded by `invalidate`: writers must always call it.
    #[tokio::test]
    async fn invalidate_makes_the_next_lookup_reload() {
        let f = fixture();
        let t = tenant();
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");

        let cached = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(cached.value, "8", "served from the cache until invalidated");
        assert_eq!(f.tenants.loads.load(Ordering::SeqCst), 1);

        f.service.invalidate(t);
        let reloaded = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(reloaded.value, "16");
        assert_eq!(f.tenants.loads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_global_makes_the_whole_idp_row_reload() {
        let f = fixture();
        let t = tenant();
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));

        f.service.invalidate_global();
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "12");
    }

    /// A stored value not matching its type is an error, not a silent fallback to global.
    #[tokio::test]
    async fn an_unparsable_stored_value_is_an_error_not_a_silent_fallback() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "sixteen");
        let err = f
            .service
            .parse::<usize>(t, "PASSWORD_MIN_LENGTH")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }

    /// The typed endpoints are also checked with 2 tenants. A tenant with a row gets that value; a tenant without follows global.
    #[tokio::test]
    async fn typed_readers_resolve_each_tenant_separately() {
        let fixture = super::testing::tenant_settings();
        let (a, b) = (tenant(), tenant());
        fixture.set_global("SSO_ABSOLUTE_TTL_SECS", "7200");
        fixture.set_global("LOGIN_MAX_FAILED_ATTEMPTS", "7");
        fixture.set_tenant(a, "SSO_ABSOLUTE_TTL_SECS", "600");
        fixture.set_tenant(a, "LOGIN_MAX_FAILED_ATTEMPTS", "3");
        fixture.set_tenant(a, "PASSWORD_BREACH_CHECK_ENABLED", "true");
        let service = &fixture.service;

        assert_eq!(
            service.sso_session_lifetime(a).await.unwrap().absolute,
            Duration::seconds(600)
        );
        assert_eq!(
            service.sso_session_lifetime(b).await.unwrap().absolute,
            Duration::seconds(7200)
        );
        assert_eq!(
            service.login_lockout(a).await.unwrap().max_failed_attempts,
            3
        );
        assert_eq!(
            service.login_lockout(b).await.unwrap().max_failed_attempts,
            7
        );
        assert!(service.password_policy(a).await.unwrap().reject_breached);
        assert!(!service.password_policy(b).await.unwrap().reject_breached);
    }

    /// All endpoints can be looked up with built-in defaults alone (the spelling and type of the definitions' `default_value` match the endpoints).
    #[tokio::test]
    async fn every_typed_reader_works_on_the_builtin_defaults() {
        let fixture = super::testing::tenant_settings();
        let service = &fixture.service;
        let t = tenant();
        service.password_policy(t).await.unwrap();
        service.login_lockout(t).await.unwrap();
        service.sso_session_lifetime(t).await.unwrap();
        service.step_up_max_age_secs(t).await.unwrap();
        service.invitation_ttl(t).await.unwrap();
        service.password_reset_ttl(t).await.unwrap();
        service.account_setup_ttl(t).await.unwrap();
        service
            .password_reset_console_link_enabled(t)
            .await
            .unwrap();
        service.email_verification_ttl(t).await.unwrap();
        assert!(!service.unregistered_device_alerts_enabled(t).await.unwrap());
        assert!(!service.ssh_keys_enabled(t).await.unwrap());
    }

    /// A failure count not fitting in i32 saturates to i32::MAX instead of wrapping negative (no immediate lock on the first failure).
    #[tokio::test]
    async fn a_huge_failure_threshold_saturates_instead_of_wrapping() {
        let fixture = super::testing::tenant_settings();
        let t = tenant();
        fixture.set_tenant(t, "LOGIN_MAX_FAILED_ATTEMPTS", &u32::MAX.to_string());
        assert_eq!(
            fixture
                .service
                .login_lockout(t)
                .await
                .unwrap()
                .max_failed_attempts,
            i32::MAX
        );
    }

    fn actor() -> AdminActor {
        AdminActor::User(Uuid::now_v7())
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn set_writes_a_row_and_the_next_lookup_sees_it_without_waiting_for_the_cache() {
        let f = fixture();
        let t = tenant();
        // Look it up first to load it into the cache (without invalidate after writing, the old value is returned).
        f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();

        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                " 16 ",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();

        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "16", "trimmed and visible at once");
        assert_eq!(resolved.origin, SettingOrigin::TenantOverride);
    }

    /// "Revert to global" deletes the row. Unlike setting the value equal to global, it follows global changes from then on.
    #[tokio::test]
    async fn clear_removes_the_row_so_the_tenant_follows_the_whole_idp_again() {
        let f = fixture();
        let t = tenant();
        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                "8",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        f.service
            .clear(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(f.tenants.rows.lock().unwrap().is_empty(), "the row is gone");

        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.service.invalidate_global();
        let resolved = f.service.resolve(t, "PASSWORD_MIN_LENGTH").await.unwrap();
        assert_eq!(resolved.value, "12", "follows the new whole-IdP value");
        assert_eq!(resolved.origin, SettingOrigin::Inherited);
    }

    /// ⚠ Do not open system-section keys with tenant permissions (defense on the consumer side). Keys not in the definitions are not written either.
    #[tokio::test]
    async fn keys_decided_by_the_whole_idp_cannot_be_written_or_cleared_by_a_tenant() {
        let f = fixture();
        let t = tenant();
        for key in [
            "ACCESS_TOKEN_TTL_SECS",
            "ISSUER",
            "COOKIE_SECURE",
            "AUTH_SESSION_TTL_SECS",
            "DATABASE_URL",
            "KEY_ENCRYPTION_KEY",
            "PASSWORD_MIN_LENGHT",
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, "1", true, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "set {key}");
            let err = f
                .service
                .clear(TenantContext::new(t), key, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "clear {key}");
        }
        assert!(f.tenants.rows.lock().unwrap().is_empty());
        assert!(f.audit.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn values_are_checked_against_the_kind_and_empty_values_are_refused() {
        let f = fixture();
        let t = tenant();
        for (key, value) in [
            ("PASSWORD_MIN_LENGTH", "sixteen"),
            ("PASSWORD_MIN_LENGTH", "-1"),
            ("PASSWORD_BREACH_CHECK_ENABLED", "yes"),
            ("PASSWORD_MIN_LENGTH", "  "),
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, value, false, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::InvalidValue(_)), "{key}={value}");
        }
        assert!(f.tenants.rows.lock().unwrap().is_empty());
    }

    /// The audit log keeps only the key and whether it was set or cleared, not the value itself.
    #[tokio::test]
    async fn the_audit_log_records_the_key_and_the_change_but_not_the_value() {
        let f = fixture();
        let t = tenant();
        f.service
            .set(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                "123",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        f.service
            .clear(
                TenantContext::new(t),
                "PASSWORD_MIN_LENGTH",
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();

        let events = f.audit.events.lock().unwrap();
        let reasons: Vec<&str> = events.iter().filter_map(|e| e.reason.as_deref()).collect();
        assert_eq!(
            reasons,
            ["PASSWORD_MIN_LENGTH set", "PASSWORD_MIN_LENGTH cleared"]
        );
        assert!(events.iter().all(|e| {
            e.event_type == AuditEventType::TenantSettingsUpdated && e.tenant_id == Some(t)
        }));
        assert!(!reasons.iter().any(|r| r.contains("123")));
    }

    #[tokio::test]
    async fn list_shows_every_overridable_key_with_its_origin_and_the_whole_idp_value() {
        let f = fixture();
        let t = tenant();
        f.system
            .rows
            .lock()
            .unwrap()
            .push(global_row("PASSWORD_MIN_LENGTH", "12"));
        f.tenants.put(t, "PASSWORD_MIN_LENGTH", "16");

        let views = f.service.list(t).await.unwrap();
        let keys: Vec<&str> = views.iter().map(|v| v.definition.key).collect();
        let expected: Vec<&str> =
            crate::domain::system_setting::tenant_overridable_setting_keys().collect();
        assert_eq!(keys, expected, "derived from the definitions");

        let min_length = views
            .iter()
            .find(|v| v.definition.key == "PASSWORD_MIN_LENGTH")
            .unwrap();
        assert_eq!(min_length.value, "16");
        assert_eq!(min_length.origin, SettingOrigin::TenantOverride);
        assert_eq!(
            min_length.whole_idp_value, "12",
            "shown next to the override"
        );

        let attempts = views
            .iter()
            .find(|v| v.definition.key == "LOGIN_MAX_FAILED_ATTEMPTS")
            .unwrap();
        assert_eq!(attempts.value, "10");
        assert_eq!(attempts.origin, SettingOrigin::Inherited);
        assert_eq!(attempts.whole_idp_value, "10");
    }

    #[tokio::test]
    async fn adoption_counts_the_tenants_that_follow_and_lists_the_ones_that_do_not() {
        let f = fixture();
        let (a, b) = (tenant(), tenant());
        f.tenants.put(a, "PASSWORD_MIN_LENGTH", "16");
        f.tenants.put(b, "LOGIN_MAX_FAILED_ATTEMPTS", "3");
        // Rows of keys not in the definitions (misspellings) are not counted as "deviating".
        f.tenants.put(b, "PASSWORD_MIN_LENGHT", "4");
        *f.tenants.extra_tenants.lock().unwrap() = 1;

        let adoption = f.service.adoption_across_tenants().await.unwrap();
        let min_length = &adoption["PASSWORD_MIN_LENGTH"];
        assert_eq!(min_length.following, 2);
        assert_eq!(min_length.overriding.len(), 1);
        assert_eq!(min_length.overriding[0].tenant_id, a);
        assert_eq!(min_length.overriding[0].value, "16");

        assert_eq!(adoption["LOGIN_MAX_FAILED_ATTEMPTS"].following, 2);
        assert_eq!(adoption["SSO_IDLE_TTL_SECS"].following, 3);
        assert!(!adoption.contains_key("PASSWORD_MIN_LENGHT"));
        assert!(!adoption.contains_key("ACCESS_TOKEN_TTL_SECS"));
    }

    /// SMTP rows (which #113 puts in the same table), secret or not, do not leak into the aggregation of keys tenants
    /// can override (keys are narrowed from the definitions on the caller side).
    #[tokio::test]
    async fn smtp_rows_in_the_same_table_are_not_counted_as_overrides() {
        let f = fixture();
        let t = tenant();
        f.tenants.put(t, "smtp.host", "mail.example.com");
        f.tenants.put_secret(t, "smtp.password", "ciphertext");

        let adoption = f.service.adoption_across_tenants().await.unwrap();
        assert!(!adoption.contains_key("smtp.host"));
        assert!(!adoption.contains_key("smtp.password"));
        assert!(adoption.values().all(|item| item.overriding.is_empty()));
        assert!(adoption.values().all(|item| item.following == 1));
    }

    /// Values that may lock people out (the definition's `locks_out`) are not saved without confirmation. With confirmation they are saved.
    #[tokio::test]
    async fn a_value_that_can_lock_people_out_needs_confirmation() {
        let f = fixture();
        let t = tenant();
        for (key, value) in [
            ("AUTH_POLICY_DEFAULT_EFFECT", "deny"),
            ("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce"),
        ] {
            let err = f
                .service
                .set(TenantContext::new(t), key, value, false, &actor(), &ctx())
                .await
                .unwrap_err();
            assert!(matches!(err, DomainError::Conflict(_)), "{key}");
            assert!(f.tenants.rows.lock().unwrap().is_empty(), "{key} not saved");

            f.service
                .set(TenantContext::new(t), key, value, true, &actor(), &ctx())
                .await
                .unwrap();
            f.tenants.rows.lock().unwrap().clear();
        }
        // Values on the non-lockout side can be saved without confirmation.
        f.service
            .set(
                TenantContext::new(t),
                "AUTH_POLICY_DEFAULT_EFFECT",
                "allow",
                false,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap();
        // Values not among the choices are refused even with confirmation.
        let err = f
            .service
            .set(
                TenantContext::new(t),
                "AUTH_POLICY_DEFAULT_EFFECT",
                "denyy",
                true,
                &actor(),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }

    /// The 2 default decision keys (ADR-0058 §4, §10). Put different values in 2 tenants and check they do not mix.
    /// A tenant without rows follows the default.
    #[tokio::test]
    async fn each_tenant_gets_its_own_decision_defaults() {
        let (strict, lenient, untouched) = (tenant(), tenant(), tenant());
        let fixture = super::testing::tenant_settings();
        fixture.set_tenant(strict, AUTH_POLICY_DEFAULT_EFFECT, "deny");
        fixture.set_tenant(strict, APPLICATION_ASSIGNMENT_ENFORCEMENT, "enforce");
        fixture.set_tenant(lenient, AUTH_POLICY_DEFAULT_EFFECT, "allow");
        fixture.set_tenant(lenient, APPLICATION_ASSIGNMENT_ENFORCEMENT, "record_only");
        let settings = fixture.service;

        assert_eq!(
            settings.policy_default_effect(strict).await.unwrap(),
            DefaultPolicyEffect::Deny
        );
        assert_eq!(
            settings.assignment_enforcement(strict).await.unwrap(),
            AssignmentEnforcement::Enforce
        );
        assert_eq!(
            settings.policy_default_effect(lenient).await.unwrap(),
            DefaultPolicyEffect::Allow
        );
        assert_eq!(
            settings.assignment_enforcement(lenient).await.unwrap(),
            AssignmentEnforcement::RecordOnly
        );
        // Without rows, the default (allow / record_only). ⚠ If the default were enforce, everyone without a directory entry would be locked out.
        assert_eq!(
            settings.policy_default_effect(untouched).await.unwrap(),
            DefaultPolicyEffect::Allow
        );
        assert_eq!(
            settings.assignment_enforcement(untouched).await.unwrap(),
            AssignmentEnforcement::RecordOnly
        );
    }

    /// Even for the 2 default decision keys, a stored value not matching its type is an error, not a silent fallback to the default.
    #[tokio::test]
    async fn an_unparsable_decision_default_is_an_error() {
        let t = tenant();
        let fixture = super::testing::tenant_settings();
        fixture.set_tenant(t, AUTH_POLICY_DEFAULT_EFFECT, "maybe");
        fixture.set_tenant(t, APPLICATION_ASSIGNMENT_ENFORCEMENT, "sometimes");
        assert!(matches!(
            fixture.service.policy_default_effect(t).await,
            Err(DomainError::InvalidValue(_))
        ));
        assert!(matches!(
            fixture.service.assignment_enforcement(t).await,
            Err(DomainError::InvalidValue(_))
        ));
    }
}
