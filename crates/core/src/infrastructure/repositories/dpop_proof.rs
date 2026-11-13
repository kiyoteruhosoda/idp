//! sqlx implementation of `DpopProofReplayRepository` (ADR-0075 decision 4).
//!
//! "Record it unless already used" is decided by **a single insert on the primary key** (same shape as `client_assertion`).

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::DpopProofReplayRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub struct SqlxDpopProofReplayRepository {
    pool: Db,
}

impl SqlxDpopProofReplayRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    pub(super) fn pool(&self) -> &Db {
        &self.pool
    }
}

#[async_trait]
impl DpopProofReplayRepository for SqlxDpopProofReplayRepository {
    async fn record_if_unused(
        &self,
        proof_hash: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<bool> {
        let result =
            sqlx::query("INSERT INTO dpop_proof_jtis (proof_hash, expires_at) VALUES (?, ?)")
                .bind(proof_hash)
                .bind(retain_until.naive_utc())
                .execute(&self.pool)
                .await;
        match result {
            Ok(_) => Ok(true),
            // Primary key violation = a proof with the same key and the same jti was already used.
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
            Err(e) => Err(DomainError::Repository(e.to_string())),
        }
    }
}
