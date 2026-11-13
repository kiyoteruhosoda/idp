//! sqlx implementation of `ClientAssertionReplayRepository` (ADR-0030 decision 5).
//!
//! "Record it if unused" is decided by **a single insert into the primary key**. Doing it in 2 steps,
//! SELECT then INSERT, could judge both as unused when the same assertion arrives twice concurrently
//! (and that concurrent arrival is exactly what replay prevention wants to stop).

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::ClientAssertionReplayRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub struct SqlxClientAssertionReplayRepository {
    pool: Db,
}

impl SqlxClientAssertionReplayRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    pub(super) fn pool(&self) -> &Db {
        &self.pool
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl ClientAssertionReplayRepository for SqlxClientAssertionReplayRepository {
    async fn record_if_unused(
        &self,
        tenant_id: TenantId,
        client_id: &str,
        jti: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO client_assertion_jtis (tenant_id, client_id, jti, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(tenant_id.to_string())
        .bind(client_id)
        .bind(jti)
        // The column is named `expires_at` to match the shared cleanup (`ExpiringRecordStore`), but what goes in is
        // "the time acceptance stops", not the assertion's `exp` (see the trait doc).
        .bind(retain_until.naive_utc())
        .execute(&self.pool)
        .await;

        match result {
            // Inserted = this `jti` was unused.
            Ok(_) => Ok(true),
            // Primary key violation = this `jti` was already used (= replay).
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
            Err(e) => Err(repo_err(e)),
        }
    }
}
