//! sqlx implementation of `TenantProvisioningRepository` (REF2).
//!
//! Runs the 3 INSERTs -- the tenant row, the creator's bootstrap admin membership (ACTIVE GUEST) and the `idp.tenant.admin`
//! grant -- in a **single transaction** (ADR-0009 §4). If anything fails midway the whole thing is
//! rolled back, guaranteeing at the DB level that no "half-made tenant with only a membership/permission" remains.
//! The creator user is an existing row belonging to the parent tenant, so it is not created. Each INSERT uses the same SQL
//! as the individual repositories (shared helpers such as `insert_tenant`).

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
