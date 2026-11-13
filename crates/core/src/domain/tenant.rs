//! Tenants entity (ADR-0009 §1).
//!
//! Tenants are mutually independent administrative boundaries (Entra ID style). `parent_tenant_id`
//! is the lineage of creation and means nothing as a boundary for admin rights or data access
//! (authorization is §4 exact match only).
#![allow(dead_code)]

use crate::domain::values::TenantStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Unique identifier of a tenant (value object). Distinguished from a raw `Uuid` to prevent
/// mix-ups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for TenantId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<TenantId> for Uuid {
    fn from(id: TenantId) -> Self {
        id.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: TenantId,
    /// The tenant this was created from. `None` only for the root tenant (structurally the single
    /// such row).
    pub parent_tenant_id: Option<TenantId>,
    /// Display name. Not unique; never used in URLs.
    pub name: String,
    pub status: TenantStatus,
    /// Whether self-registration (`/auth/register`) is allowed. Disabled by default (fail-closed;
    /// SEC6).
    pub self_registration_enabled: bool,
    /// Whether `email` login identifiers take part in resolution. Disabled by default (fail-closed;
    /// ADR-0050).
    ///
    /// Primary email rows are created for every user by the migration (for uniqueness), but **they
    /// do not match in the login field until this switch is on**. Row existence and entry breadth
    /// are separate knobs.
    pub email_login_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Structurally identifies root as the single row with `parent_tenant_id IS NULL` (§1).
    pub fn is_root(&self) -> bool {
        self.parent_tenant_id.is_none()
    }

    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn tenant(parent: Option<TenantId>) -> Tenant {
        Tenant {
            id: Uuid::now_v7().into(),
            parent_tenant_id: parent,
            name: "Acme".to_string(),
            status: TenantStatus::Active,
            self_registration_enabled: false,
            email_login_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn root_has_no_parent() {
        assert!(tenant(None).is_root());
        assert!(!tenant(Some(Uuid::now_v7().into())).is_root());
    }
}
