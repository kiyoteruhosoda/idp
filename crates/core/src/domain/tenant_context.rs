//! テナント境界の値オブジェクト（ADR-0009 §4・§8）。
//!
//! `TenantContext` はユースケースが処理対象とするテナント（`TenantResolver` が解決したテナント）を
//! 表し、リポジトリ呼び出しには必ずこれを渡す（MariaDB に RLS はなく、アプリ層が唯一の分離防御線。
//! `CLAUDE.md`「権限管理」）。
//!
//! `TenantScope` は権限（`user_permissions.tenant_id`）の適用範囲を表す。判定は「要求テナント ID と
//! 権限 scope の完全一致」のみで行い、祖先・配下は一切考慮しない。root の特別バリアントは設けない
//! （root かどうかは `permission_code` が `idp.system.admin` か否かで別途判定する）。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;

/// ユースケースが処理対象とするテナント。
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

/// 権限の適用範囲（scope）。当該テナントのみに及ぶ（配下・系譜へは一切及ばない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantScope(TenantId);

impl TenantScope {
    pub fn new(tenant_id: TenantId) -> Self {
        Self(tenant_id)
    }

    pub fn tenant_id(&self) -> TenantId {
        self.0
    }

    /// 要求テナントと scope の完全一致判定（祖先・配下は考慮しない）。
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
