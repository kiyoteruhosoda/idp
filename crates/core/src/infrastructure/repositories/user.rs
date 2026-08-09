//! `UserRepository` の sqlx 実装。UUID は CHAR(36) 正準文字列として入出力する。

use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::{LoginFailureRecord, User};
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

    /// ログイン欄の入力から解決する（AP8）。
    ///
    /// 登録簿（`user_login_identifiers`）の**有効な行**を、種別ごとの正規化キーで 1 クエリで引く。
    /// 「全件読んでアプリ側で正規化して突き合わせる」方式は取らない（テナントの規模に比例して
    /// 破綻するうえ、一意性の保証が DB から離れる）。
    ///
    /// 一致が無ければ `users.preferred_username` へ落とす。登録簿の導入は expand フェーズで、
    /// 主たる識別子はまだ `users` 側にあるため（migration 0029）。
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<Option<User>> {
        let candidates = crate::domain::login_identifier::lookup_candidates(input);
        if !candidates.is_empty() {
            let placeholders = vec!["(?, ?)"; candidates.len()].join(", ");
            let sql = format!(
                "SELECT u.id AS id, u.tenant_id AS tenant_id, u.sub AS sub, u.email AS email, \
                 u.email_verified AS email_verified, u.preferred_username AS preferred_username, \
                 u.name AS name, u.language AS language, u.password_hash AS password_hash, \
                 u.must_change_password AS must_change_password, u.status AS status, \
                 u.failed_login_count AS failed_login_count, u.locked_until AS locked_until, \
                 u.created_at AS created_at, u.updated_at AS updated_at \
                 FROM user_login_identifiers i \
                 JOIN users u ON u.id = i.user_id \
                 WHERE i.tenant_id = ? AND i.is_active = 1 \
                   AND (i.identifier_type, i.normalized_value) IN ({placeholders}) \
                 LIMIT 1"
            );
            let mut query = sqlx::query(&sql).bind(tenant_id.to_string());
            for (kind, normalized) in &candidates {
                query = query.bind(kind.as_str()).bind(normalized.clone());
            }
            let row = query.fetch_optional(&self.pool).await.map_err(repo_err)?;
            if let Some(row) = row {
                return map_row(&row).map(Some);
            }
        }
        self.find_by_username(tenant_id, input.trim()).await
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

    async fn record_login_failure(
        &self,
        id: Uuid,
        lockout: LockoutPolicy,
        now: DateTime<Utc>,
    ) -> Result<LoginFailureRecord> {
        // 加算とロック判定を 1 文で行う（SEC13）。読んで書き戻す方式では、並行する試行が同じ値を
        // 読んで同じ値を書くため、N 回失敗しても 1 しか進まないことがある。
        //
        // **代入の順序に意味がある。** MariaDB / MySQL の単一表 UPDATE は SET を左から右へ評価し、
        // 後続の式は先に更新された列の**新しい値**を見る。`locked_until` を先に置くことで、
        // その CASE の中の `failed_login_count` は更新前の値を指す（逆順にすると 2 回分進む）。
        let locked_until = now + chrono::Duration::seconds(lockout.lock_duration_secs as i64);
        sqlx::query(
            "UPDATE users \
                SET locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END, \
                    failed_login_count = failed_login_count + 1 \
              WHERE id = ?",
        )
        .bind(lockout.max_failed_attempts)
        .bind(locked_until.naive_utc())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        // 記録後の状態を読み直す（MariaDB の UPDATE は RETURNING を持たない）。並行する失敗が
        // 間に挟まれば、より進んだ値・より新しいロック期限が返る。どちらも「今ロックされているか」の
        // 判定としては正しく、監査に残る回数が実際の試行数を下回ることも無い。
        let row = sqlx::query("SELECT failed_login_count, locked_until FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        let Some(row) = row else {
            // 記録の途中で利用者が消えた（管理者削除）。ロック判定の対象が無いだけなので、
            // 「ロックされていない」として扱う。
            return Ok(LoginFailureRecord {
                failed_login_count: 0,
                locked_until: None,
            });
        };
        let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
        Ok(LoginFailureRecord {
            failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
            // 期限切れのロックは「掛かっていない」とみなす（読み直しの時点で判定する）。
            locked_until: locked_until.map(to_utc).filter(|until| *until > now),
        })
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

    async fn update_name(&self, id: Uuid, name: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_profile(
        &self,
        id: Uuid,
        email: &str,
        preferred_username: Option<&str>,
        name: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET email = ?, preferred_username = ?, name = ? WHERE id = ?")
            .bind(email)
            .bind(preferred_username)
            .bind(name)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| match &e {
                // 事前チェックとの競合（同時更新）は DB の UNIQUE 制約が最終的に保証する。
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    DomainError::Conflict("email or preferred_username already exists".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;
        Ok(())
    }
}
