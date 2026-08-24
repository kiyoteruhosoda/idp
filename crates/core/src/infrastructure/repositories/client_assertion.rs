//! `ClientAssertionReplayRepository` の sqlx 実装（ADR-0030 決定 5）。
//!
//! 「使われていなければ記録する」を**主キーへの挿入 1 回**で判定する。SELECT してから INSERT する
//! 2 段階にすると、同じ assertion が同時に 2 本届いたときに両方とも未使用と判定され得る
//! （再生防止としては、まさにその同時到着を止めたい）。

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
        // 列名は掃除の共通処理（`ExpiringRecordStore`）に合わせた `expires_at` だが、入れるのは
        // assertion の `exp` ではなく「受理が止まる時刻」である（トレイトの doc 参照）。
        .bind(retain_until.naive_utc())
        .execute(&self.pool)
        .await;

        match result {
            // 挿入できた ＝ この `jti` は未使用だった。
            Ok(_) => Ok(true),
            // 主キー違反 ＝ この `jti` は既に使われている（＝再生）。
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
            Err(e) => Err(repo_err(e)),
        }
    }
}
