//! sqlx implementation of authenticator-app keys, registration intake and "continue with the app" requests (task #892, ADR-0077).

use crate::domain::app_approver::{
    ApprovalRequest, ApprovalState, ApproverEnrollment, ApproverKey, EnrollmentStage,
};
use crate::domain::error::{DomainError, Result};
use crate::domain::key_attestation::KeySecurityLevel;
use crate::domain::repositories::{
    ApprovalRequestRepository, ApproverEnrollmentRepository, ApproverKeyRepository,
};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn utc(raw: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&raw)
}

fn uuid_of(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(repo_err)
}

fn level_of(raw: &str) -> Result<KeySecurityLevel> {
    KeySecurityLevel::parse(raw)
        .ok_or_else(|| DomainError::Repository(format!("unknown security level `{raw}`")))
}

// ─── Keys ─────────────────────────────────────────────────────────────

pub struct SqlxApproverKeyRepository {
    pool: Db,
}

impl SqlxApproverKeyRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn key_from_row(row: &MySqlRow) -> Result<ApproverKey> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let level: String = row.try_get("security_level").map_err(repo_err)?;
    let registered_at: NaiveDateTime = row.try_get("registered_at").map_err(repo_err)?;
    let last_used_at: Option<NaiveDateTime> = row.try_get("last_used_at").map_err(repo_err)?;
    Ok(ApproverKey {
        id: uuid_of(&id)?,
        user_id: uuid_of(&user_id)?,
        key_id: row.try_get("key_id").map_err(repo_err)?,
        public_key_spki: row.try_get("public_key_spki").map_err(repo_err)?,
        security_level: level_of(&level)?,
        device_name: row.try_get("device_name").map_err(repo_err)?,
        registered_at: utc(registered_at),
        last_used_at: last_used_at.map(utc),
    })
}

#[async_trait]
impl ApproverKeyRepository for SqlxApproverKeyRepository {
    async fn insert(&self, key: &ApproverKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_approver_keys (id, user_id, key_id, public_key_spki, security_level, \
             device_name, registered_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(key.id.to_string())
        .bind(key.user_id.to_string())
        .bind(&key.key_id)
        .bind(&key.public_key_spki)
        .bind(key.security_level.as_str())
        .bind(&key.device_name)
        .bind(key.registered_at.naive_utc())
        .bind(key.last_used_at.map(|t| t.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("approver key is already registered".to_string())
            }
            other => repo_err(other),
        })?;
        Ok(())
    }

    async fn find_by_key_id(&self, key_id: &str) -> Result<Option<ApproverKey>> {
        let row = sqlx::query(
            "SELECT id, user_id, key_id, public_key_spki, security_level, device_name, registered_at, last_used_at FROM app_approver_keys WHERE key_id = ?",
        )
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(key_from_row).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ApproverKey>> {
        let rows = sqlx::query(
            "SELECT id, user_id, key_id, public_key_spki, security_level, device_name, registered_at, last_used_at FROM app_approver_keys WHERE user_id = ? \
             ORDER BY registered_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(key_from_row).collect()
    }

    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<Option<ApproverKey>> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        let row = sqlx::query(
            "SELECT id, user_id, key_id, public_key_spki, security_level, device_name, registered_at, last_used_at FROM app_approver_keys WHERE id = ? AND user_id = ? FOR UPDATE",
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(repo_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key = key_from_row(&row)?;
        sqlx::query("DELETE FROM app_approver_keys WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(Some(key))
    }

    async fn touch(&self, id: Uuid, used_at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE app_approver_keys SET last_used_at = ? WHERE id = ?")
            .bind(used_at.naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn link_session(&self, session_hash: &str, id: Uuid) -> Result<()> {
        sqlx::query("INSERT IGNORE INTO sso_session_contexts (session_hash) VALUES (?)")
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        sqlx::query("UPDATE sso_session_contexts SET approver_key_id = ? WHERE session_hash = ?")
            .bind(id.to_string())
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn approved_sessions(&self, id: Uuid) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT session_hash FROM sso_session_contexts WHERE approver_key_id = ?")
                .bind(id.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(repo_err)?;
        rows.iter()
            .map(|r| r.try_get::<String, _>("session_hash").map_err(repo_err))
            .collect()
    }
}

// ─── Registration intake ──────────────────────────────────────────────

pub struct SqlxApproverEnrollmentRepository {
    pool: Db,
}

impl SqlxApproverEnrollmentRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &Db {
        &self.pool
    }
}

/// Stage name (the DB value).
pub fn stage_name(stage: &EnrollmentStage) -> &'static str {
    match stage {
        EnrollmentStage::AwaitingKey => "awaiting_key",
        EnrollmentStage::AwaitingConfirmation { .. } => "awaiting_confirmation",
        EnrollmentStage::Confirmed { .. } => "confirmed",
    }
}

fn enrollment_from_row(row: &MySqlRow) -> Result<ApproverEnrollment> {
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let stage: String = row.try_get("stage").map_err(repo_err)?;
    let spki: Option<Vec<u8>> = row.try_get("public_key_spki").map_err(repo_err)?;
    let level: Option<String> = row.try_get("security_level").map_err(repo_err)?;
    let device_name: Option<String> = row.try_get("device_name").map_err(repo_err)?;
    let user_id: Option<String> = row.try_get("user_id").map_err(repo_err)?;
    let code_hash: Option<String> = row.try_get("code_hash").map_err(repo_err)?;
    let code_expires_at: Option<NaiveDateTime> =
        row.try_get("code_expires_at").map_err(repo_err)?;
    let created_at: NaiveDateTime = row.try_get("created_at").map_err(repo_err)?;
    let expires_at: NaiveDateTime = row.try_get("expires_at").map_err(repo_err)?;
    let broken = || DomainError::Repository(format!("enrollment stage `{stage}` is incomplete"));
    let stage = match stage.as_str() {
        "awaiting_key" => EnrollmentStage::AwaitingKey,
        "awaiting_confirmation" => EnrollmentStage::AwaitingConfirmation {
            public_key_spki: spki.ok_or_else(broken)?,
            security_level: level_of(&level.ok_or_else(broken)?)?,
            device_name: device_name.ok_or_else(broken)?,
        },
        "confirmed" => EnrollmentStage::Confirmed {
            public_key_spki: spki.ok_or_else(broken)?,
            security_level: level_of(&level.ok_or_else(broken)?)?,
            device_name: device_name.ok_or_else(broken)?,
            user_id: uuid_of(&user_id.ok_or_else(broken)?)?,
            code_hash: code_hash.ok_or_else(broken)?,
            code_expires_at: utc(code_expires_at.ok_or_else(broken)?),
        },
        other => {
            return Err(DomainError::Repository(format!(
                "unknown enrollment stage `{other}`"
            )))
        }
    };
    Ok(ApproverEnrollment {
        id: row.try_get("id").map_err(repo_err)?,
        tenant_id: uuid_of(&tenant_id)?,
        challenge: row.try_get("challenge").map_err(repo_err)?,
        stage,
        created_at: utc(created_at),
        expires_at: utc(expires_at),
    })
}

#[async_trait]
impl ApproverEnrollmentRepository for SqlxApproverEnrollmentRepository {
    async fn insert(&self, e: &ApproverEnrollment) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_approver_enrollments (id, tenant_id, challenge, stage, created_at, \
             expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&e.id)
        .bind(e.tenant_id.to_string())
        .bind(&e.challenge)
        .bind(stage_name(&e.stage))
        .bind(e.created_at.naive_utc())
        .bind(e.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find(&self, tenant_id: Uuid, id: &str) -> Result<Option<ApproverEnrollment>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, challenge, stage, public_key_spki, security_level, device_name, \
             user_id, code_hash, code_expires_at, created_at, expires_at \
             FROM app_approver_enrollments WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(enrollment_from_row).transpose()
    }

    async fn advance(&self, e: &ApproverEnrollment, expected: &str) -> Result<bool> {
        let (spki, level, device_name, user_id, code_hash, code_expires_at) = match &e.stage {
            EnrollmentStage::AwaitingKey => (None, None, None, None, None, None),
            EnrollmentStage::AwaitingConfirmation {
                public_key_spki,
                security_level,
                device_name,
            } => (
                Some(public_key_spki.clone()),
                Some(security_level.as_str()),
                Some(device_name.clone()),
                None,
                None,
                None,
            ),
            EnrollmentStage::Confirmed {
                public_key_spki,
                security_level,
                device_name,
                user_id,
                code_hash,
                code_expires_at,
            } => (
                Some(public_key_spki.clone()),
                Some(security_level.as_str()),
                Some(device_name.clone()),
                Some(user_id.to_string()),
                Some(code_hash.clone()),
                Some(code_expires_at.naive_utc()),
            ),
        };
        let result = sqlx::query(
            "UPDATE app_approver_enrollments SET stage = ?, public_key_spki = ?, security_level = ?, \
             device_name = ?, user_id = ?, code_hash = ?, code_expires_at = ? \
             WHERE id = ? AND stage = ?",
        )
        .bind(stage_name(&e.stage))
        .bind(spki)
        .bind(level)
        .bind(device_name)
        .bind(user_id)
        .bind(code_hash)
        .bind(code_expires_at)
        .bind(&e.id)
        .bind(expected)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM app_approver_enrollments WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}

// ─── "Continue with the app" requests ──────────────────────────────────

pub struct SqlxApprovalRequestRepository {
    pool: Db,
}

impl SqlxApprovalRequestRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &Db {
        &self.pool
    }
}

fn request_from_row(row: &MySqlRow) -> Result<ApprovalRequest> {
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let state: String = row.try_get("state").map_err(repo_err)?;
    let approver_key: Option<String> = row.try_get("approver_key_id").map_err(repo_err)?;
    let user_id: Option<String> = row.try_get("user_id").map_err(repo_err)?;
    let code_expires_at: Option<NaiveDateTime> =
        row.try_get("code_expires_at").map_err(repo_err)?;
    let created_at: NaiveDateTime = row.try_get("created_at").map_err(repo_err)?;
    let expires_at: NaiveDateTime = row.try_get("expires_at").map_err(repo_err)?;
    Ok(ApprovalRequest {
        id: row.try_get("id").map_err(repo_err)?,
        tenant_id: uuid_of(&tenant_id)?,
        browser_binding_hash: row.try_get("browser_binding_hash").map_err(repo_err)?,
        auth_session_hash: row.try_get("auth_session_hash").map_err(repo_err)?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        challenge: row.try_get("challenge").map_err(repo_err)?,
        state: ApprovalState::parse(&state)
            .ok_or_else(|| DomainError::Repository(format!("unknown approval state `{state}`")))?,
        ip_address: row.try_get("ip_address").map_err(repo_err)?,
        country: row.try_get("country").map_err(repo_err)?,
        approver_key: approver_key.as_deref().map(uuid_of).transpose()?,
        user_id: user_id.as_deref().map(uuid_of).transpose()?,
        code_hash: row.try_get("code_hash").map_err(repo_err)?,
        code_expires_at: code_expires_at.map(utc),
        created_at: utc(created_at),
        expires_at: utc(expires_at),
    })
}

#[async_trait]
impl ApprovalRequestRepository for SqlxApprovalRequestRepository {
    async fn insert(&self, r: &ApprovalRequest) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_approval_requests (id, tenant_id, browser_binding_hash, \
             auth_session_hash, client_id, challenge, state, ip_address, country, created_at, \
             expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&r.id)
        .bind(r.tenant_id.to_string())
        .bind(&r.browser_binding_hash)
        .bind(&r.auth_session_hash)
        .bind(&r.client_id)
        .bind(&r.challenge)
        .bind(r.state.as_str())
        .bind(&r.ip_address)
        .bind(&r.country)
        .bind(r.created_at.naive_utc())
        .bind(r.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find(&self, tenant_id: Uuid, id: &str) -> Result<Option<ApprovalRequest>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, browser_binding_hash, auth_session_hash, client_id, challenge, \
             state, ip_address, country, approver_key_id, user_id, code_hash, code_expires_at, \
             created_at, expires_at FROM app_approval_requests WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(request_from_row).transpose()
    }

    async fn approve(
        &self,
        id: &str,
        approver_key: Uuid,
        user_id: Uuid,
        code_hash: &str,
        code_expires_at: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE app_approval_requests SET state = 'approved', approver_key_id = ?, user_id = ?, \
             code_hash = ?, code_expires_at = ? WHERE id = ? AND state = 'pending'",
        )
        .bind(approver_key.to_string())
        .bind(user_id.to_string())
        .bind(code_hash)
        .bind(code_expires_at.naive_utc())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn transition(&self, id: &str, from: ApprovalState, to: ApprovalState) -> Result<bool> {
        let result =
            sqlx::query("UPDATE app_approval_requests SET state = ? WHERE id = ? AND state = ?")
                .bind(to.as_str())
                .bind(id)
                .bind(from.as_str())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}
