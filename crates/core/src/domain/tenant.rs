//! Tenants エンティティ（ADR-0009 §1）。
//!
//! テナントは互いに独立した管理境界（Entra ID 型）。`parent_tenant_id` は作成元の系譜であり、
//! 管理権限・データアクセスの境界としては意味を持たない（権限判定は §4 の完全一致のみ）。
#![allow(dead_code)]

use crate::domain::values::TenantStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// テナントの一意識別子（値オブジェクト）。生の `Uuid` と区別し、取り違えを防ぐ。
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
    /// 作成元テナント。`None` は root テナントのみ（構造的に唯一の行）。
    pub parent_tenant_id: Option<TenantId>,
    /// 表示名。一意制約なし・URL には使わない。
    pub name: String,
    pub status: TenantStatus,
    /// 自己登録（`/auth/register`）を許可するか。既定は無効（fail-closed。SEC6）。
    pub self_registration_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// `parent_tenant_id IS NULL` の唯一の行として root を構造的に識別する（§1）。
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
