//! `UserRepository` の sqlx 実装。UUID は CHAR(36) 正準文字列として入出力する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserRepository {
    pool: Db,
}

impl SqlxUserRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, tenant_id, sub, email, email_verified, preferred_username, \
     name, language, password_hash, must_change_password, status, failed_login_count, locked_until, \
     created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<User> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let sub: String = row.try_get("sub").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
    Ok(User {
        id: parse_uuid(&id)?,
        tenant_id: parse_uuid(&tenant_id)?.into(),
        sub: parse_uuid(&sub)?,
        email: row.try_get("email").map_err(repo_err)?,
        email_verified: row.try_get("email_verified").map_err(repo_err)?,
        preferred_username: row.try_get("preferred_username").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        language: row.try_get("language").map_err(repo_err)?,
        password_hash: row.try_get("password_hash").map_err(repo_err)?,
        must_change_password: row.try_get("must_change_password").map_err(repo_err)?,
        status: UserStatus::parse(&status)?,
        failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
        locked_until: locked_until.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// users への INSERT（プール直接実行と provisioning トランザクションで共用する）。
pub(crate) async fn insert_user<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql>,
    user: &User,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO users \
         (id, tenant_id, sub, email, email_verified, preferred_username, name, language, \
          password_hash, must_change_password, status, failed_login_count, locked_until) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(user.tenant_id.to_string())
    .bind(user.sub.to_string())
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.preferred_username)
    .bind(&user.name)
    .bind(&user.language)
    .bind(&user.password_hash)
    .bind(user.must_change_password)
    .bind(user.status.as_str())
    .bind(user.failed_login_count)
    .bind(user.locked_until.map(|d| d.naive_utc()))
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("email or preferred_username already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    Ok(())
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn create(&self, user: &User) -> Result<()> {
        insert_user(&self.pool, user).await
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE sub = ?");
        let row = sqlx::query(&sql)
            .bind(sub.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE tenant_id = ? AND email = ?");
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM users WHERE tenant_id = ? AND preferred_username = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_ids(&self, ids: &[Uuid]) -> Result<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users WHERE id IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for id in ids {
            query = query.bind(id.to_string());
        }
        let rows = query.fetch_all(&self.pool).await.map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?")
            .bind(failed_login_count)
            .bind(locked_until.map(|d| d.naive_utc()))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
            .bind(password_hash)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn reset_password_forced(&self, id: Uuid, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?")
            .bind(password_hash)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()> {
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET language = ? WHERE id = ?")
            .bind(language)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
