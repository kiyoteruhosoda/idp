//! `TenantProvisioningRepository` の sqlx 実装（REF2）。
//!
//! テナント行・作成者のブートストラップ管理者メンバーシップ（ACTIVE GUEST）・`idp.tenant.admin`
//! 付与の 3 INSERT を**単一トランザクション**で実行する（ADR-0009 §4）。途中で失敗した場合は全体が
//! ロールバックされ、「メンバーシップ／権限だけが残る中途半端なテナント」が残らないことを DB レベルで
//! 保証する。作成者ユーザーは親テナント所属の既存行のため新規作成しない。各 INSERT は個別リポジトリと
//! 同じ SQL（`insert_tenant` 等の共用ヘルパ）を使う。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantProvisioningRepository;
use crate::domain::tenant::Tenant;
use crate::domain::tenant_membership::TenantMembership;
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::tenant::insert_tenant;
use crate::infrastructure::repositories::tenant_membership::insert_membership;
use crate::infrastructure::repositories::user_permission::insert_grant;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub struct SqlxTenantProvisioningRepository {
    pool: Db,
}

impl SqlxTenantProvisioningRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl TenantProvisioningRepository for SqlxTenantProvisioningRepository {
    async fn provision(
        &self,
        tenant: &Tenant,
        admin_membership: &TenantMembership,
        admin_permission_code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        insert_tenant(&mut *tx, tenant).await?;
        insert_membership(&mut *tx, admin_membership).await?;
        insert_grant(
            &mut *tx,
            admin_membership.tenant_id,
            admin_membership.user_id,
            admin_permission_code,
            granted_at,
        )
        .await?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }
}
