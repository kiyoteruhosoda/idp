//! Tenant settings (ADR-0058).
//!
//! Whereas `system_settings` is one sheet for the whole IdP, this holds **per-tenant** overrides.
//! Resolution order is **tenant row > global row > environment variable > built-in default**, and ⚠
//! **a tenant having no row means "follow the global value"** (default values are not copied out to
//! tenants).
//!
//! Which keys may be set is decided by `scope` in
//! [`crate::domain::system_setting::RUNTIME_SETTING_DEFINITIONS`] (the single source of scope).
//! Secrets are handled as in `system_settings`: when `is_secret`, `value` is ciphertext and the
//! read API never returns plaintext.
#![allow(dead_code)]

use crate::domain::tenant::TenantId;

/// One tenant setting record (key-value). `value` is in stored form (ciphertext when `is_secret`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSetting {
    pub tenant_id: TenantId,
    pub key: String,
    pub value: String,
    /// When `true`, `value` is ciphertext (base64 of AES-256-GCM).
    pub is_secret: bool,
}

/// One override across all tenants (read by the global settings screen to show "tenants deviating
/// from default").
///
/// ⚠ Secrets are not included (dropped at the repository).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOverrideEntry {
    pub tenant_id: TenantId,
    pub tenant_name: String,
    pub key: String,
    pub value: String,
}

/// Overview of overrides across all tenants. "Number of tenants following" is
/// `tenant_count` minus the number of tenants overriding that key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantOverridesAcrossTenants {
    /// Total number of tenants (including root).
    pub tenant_count: u64,
    /// All non-empty, non-secret overrides.
    pub overrides: Vec<TenantOverrideEntry>,
}
