//! sqlx implementation of `RefreshTokenRepository` (design spec §9.1).

use crate::domain::error::{DomainError, Result};
use crate::domain::refresh_token::RefreshToken;
use crate::domain::repositories::RefreshTokenRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::authentication_methods_json;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxRefreshTokenRepository {
    pool: Db,
}

impl SqlxRefreshTokenRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// Used by expired-row cleanup (the `ExpiringRecordStore` implementation in `expired_records`).
    pub(super) fn pool(&self) -> &Db {
        &self.pool
    }
}

/// Condition pointing at the given user's **currently usable** refresh tokens (not revoked and unexpired). Binds are `user_id`,
/// then the reference time.
///
/// The condition is written only here so the counting side ([`count_active_for_user`](RefreshTokenRepository::count_active_for_user), the
/// count the admin console shows before pressing) and the dropping side ([`revoke_all_for_user`](RefreshTokenRepository::revoke_all_for_user),
/// the count ADR-0047's reissue returns) cover the same range. Fixing only one side
/// brings back the drift "the screen says 0, but pressing says they were revoked" (task #123).
const ACTIVE_FOR_USER: &str = "user_id = ? AND revoked_at IS NULL AND expires_at > ?";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<RefreshToken> {
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let scope: Vec<u8> = row.try_get("scope").map_err(repo_err)?;
    let revoked_at: Option<NaiveDateTime> = row.try_get("revoked_at").map_err(repo_err)?;
    Ok(RefreshToken {
        token_hash: row.try_get("token_hash").map_err(repo_err)?,
        parent_hash: row.try_get("parent_hash").map_err(repo_err)?,
        grant_hash: row.try_get("grant_hash").map_err(repo_err)?,
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        sid: row.try_get("sid").map_err(repo_err)?,
        authentication_methods: authentication_methods_json::from_json_opt(
            row.try_get("authentication_methods").map_err(repo_err)?,
        ),
        auth_time: row
            .try_get::<Option<NaiveDateTime>, _>("auth_time")
            .map_err(repo_err)?
            .map(to_utc),
        dpop_jkt: row.try_get("dpop_jkt").map_err(repo_err)?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        revoked_at: revoked_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl RefreshTokenRepository for SqlxRefreshTokenRepository {
    async fn create(&self, token: &RefreshToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (token_hash, parent_hash, grant_hash, tenant_id, user_id, client_id, scope, sid, \
              authentication_methods, auth_time, dpop_jkt, expires_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.token_hash)
        .bind(&token.parent_hash)
        .bind(&token.grant_hash)
        .bind(token.tenant_id.to_string())
        .bind(token.user_id.to_string())
        .bind(&token.client_id)
        .bind(serde_json::to_string(&token.scope).map_err(repo_err)?)
        .bind(&token.sid)
        .bind(
            token
                .authentication_methods
                .as_deref()
                .map(authentication_methods_json::to_json),
        )
        .bind(token.auth_time.map(|d| d.naive_utc()))
        .bind(&token.dpop_jkt)
        .bind(token.expires_at.naive_utc())
        .bind(token.revoked_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_hash(
        &self,
        tenant_id: TenantId,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>> {
        let row = sqlx::query(
            "SELECT token_hash, parent_hash, grant_hash, tenant_id, user_id, client_id, scope, \
             sid, authentication_methods, auth_time, dpop_jkt, expires_at, revoked_at, created_at \
             FROM refresh_tokens WHERE token_hash = ? AND tenant_id = ?",
        )
        .bind(token_hash)
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn revoke(&self, token_hash: &str, revoked_at: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at.naive_utc())
        .bind(token_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn revoke_family(
        &self,
        tenant_id: TenantId,
        family_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64> {
        // Revoke tokens from the same grant in one statement (SEC8). `grant_hash` is indexed, so
        // one UPDATE suffices regardless of chain depth. Just in case, so the presented token itself
        // (a pre-migration row whose `grant_hash` is still NULL = a family of itself only) is also picked up by the same condition,
        // a `token_hash` match is included in the OR.
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE tenant_id = ? AND (grant_hash = ? OR token_hash = ?) AND revoked_at IS NULL",
        )
        .bind(revoked_at.naive_utc())
        .bind(tenant_id.to_string())
        .bind(family_hash)
        .bind(family_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn exists_by_parent_hash(&self, parent_hash: &str) -> Result<bool> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM refresh_tokens WHERE parent_hash = ? LIMIT 1")
                .bind(parent_hash)
                .fetch_one(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(row.0 > 0)
    }

    async fn revoke_all_for_session(
        &self,
        user_id: Uuid,
        sid: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64> {
        // `sid` is indexed (0050), so even if rotation has lengthened the chain, one
        // UPDATE suffices. The tenant is not part of the condition (see the trait comment).
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE user_id = ? AND sid = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at.naive_utc())
        .bind(user_id.to_string())
        .bind(sid)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at)
        .bind(tenant_id.as_uuid().to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn revoke_all_for_user_and_client(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE tenant_id = ? AND user_id = ? AND client_id = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at)
        .bind(tenant_id.as_uuid().to_string())
        .bind(user_id.to_string())
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid, revoked_at: DateTime<Utc>) -> Result<u64> {
        // The range dropped is the same as the range `count_active_for_user` counts (`ACTIVE_FOR_USER`). Expired
        // rows can no longer be used for refresh, so marking them revoked changes nothing except making the count drift from the screen.
        let result = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE refresh_tokens SET revoked_at = ? WHERE {ACTIVE_FOR_USER}"
        )))
        .bind(revoked_at.naive_utc())
        .bind(user_id.to_string())
        .bind(revoked_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn count_active_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<u64> {
        // Resolved via `refresh_tokens_user_idx (user_id)`. Rows per user are few, so no extra index is needed.
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM refresh_tokens WHERE {ACTIVE_FOR_USER}"
        )))
        .bind(user_id.to_string())
        .bind(now.naive_utc())
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
}
