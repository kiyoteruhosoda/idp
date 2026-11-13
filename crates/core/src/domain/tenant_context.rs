//! Tenant boundary value objects (ADR-0009 §4, §8).
//!
//! `TenantContext` is the tenant a use case operates on (the tenant resolved by `TenantResolver`);
//! it is always passed to repository calls (MariaDB has no RLS, so the app layer is the only
//! isolation defense; `CLAUDE.md` "Authorization").
//!
//! `TenantScope` is the scope of a permission (`user_permissions.tenant_id`). Checks use only
//! "exact match of the requested tenant ID and the permission scope"; ancestors and descendants are
//! never considered. There is no special root variant (whether something is root is decided
//! separately by `permission_code` being `idp.system.admin`).
#![allow(dead_code)]

use crate::domain::tenant::TenantId;

/// The tenant a use case operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantContext {
    tenant_id: TenantId,
}

impl TenantContext {
    pub fn new(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

/// The scope of a permission. Covers only that tenant (never its descendants or lineage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantScope(TenantId);

impl TenantScope {
    pub fn new(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    pub fn tenant_id(&self) -> TenantId {
        self.0
    }

    /// Exact-match check of the requested tenant and the scope (ancestors and descendants are not
    /// considered).
    pub fn matches(&self, requested: &TenantContext) -> bool {
        self.0 == requested.tenant_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn scope_matches_only_the_exact_tenant() {
        let a: TenantId = Uuid::now_v7().into();
        let b: TenantId = Uuid::now_v7().into();
        let scope = TenantScope::new(a);

        assert!(scope.matches(&TenantContext::new(a)));
        assert!(!scope.matches(&TenantContext::new(b)));
    }
}
