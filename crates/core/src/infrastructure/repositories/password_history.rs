//! `PasswordHistoryRepository` の sqlx 実装（AP7）。
//!
//! 積む（INSERT）と剪定（DELETE）を 1 つのメソッドで行う。剪定は「新しい順に `retain` 件を
//! 残して残りを消す」ので、`retain = 0` は当該利用者の履歴を空にする（履歴を見ない設定へ
//! 変えたときに、使わないハッシュを持ち続けない）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::PasswordHistoryRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxPasswordHistoryRepository {
    pool: Db,
}

impl SqlxPasswordHistoryRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl PasswordHistoryRepository for SqlxPasswordHistoryRepository {
    async fn push(
        &self,
        user_id: Uuid,
        password_hash: &str,
        retired_at: DateTime<Utc>,
        retain: u32,
    ) -> Result<()> {
        let user_id = user_id.to_string();
        sqlx::query(
            "INSERT INTO user_password_history (user_id, password_hash, retired_at) \
             VALUES (?, ?, ?)",
        )
        .bind(&user_id)
        .bind(password_hash)
        .bind(retired_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        // 残す件数を超えた古い行を消す。並びは `retired_at` の降順、同値なら `id`（単調増加＝
        // 挿入順）の降順で決める。境界行を先に読んでから値で比較するのは、MariaDB が
        // 「更新対象の表を副問い合わせで参照する DELETE」を許さないためである。
        let boundary = sqlx::query(
            "SELECT retired_at, id FROM user_password_history WHERE user_id = ? \
             ORDER BY retired_at DESC, id DESC LIMIT ? OFFSET ?",
        )
        .bind(&user_id)
        .bind(1u32)
        .bind(retain)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;

        if let Some(row) = boundary {
            let boundary_retired_at: chrono::NaiveDateTime =
                row.try_get("retired_at").map_err(repo_err)?;
            let boundary_id: i64 = row.try_get("id").map_err(repo_err)?;
            sqlx::query(
                "DELETE FROM user_password_history WHERE user_id = ? \
                 AND (retired_at < ? OR (retired_at = ? AND id <= ?))",
            )
            .bind(&user_id)
            .bind(boundary_retired_at)
            .bind(boundary_retired_at)
            .bind(boundary_id)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        }
        Ok(())
    }

    async fn recent(&self, user_id: Uuid, limit: u32) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT password_hash FROM user_password_history WHERE user_id = ? \
             ORDER BY retired_at DESC, id DESC LIMIT ?",
        )
        .bind(user_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.into_iter()
            .map(|row| row.try_get::<String, _>("password_hash").map_err(repo_err))
            .collect()
    }
}
