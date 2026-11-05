//! `SecurityStatusQuery` の sqlx 実装（task #896。ADR-0078）。読むだけ。

use crate::domain::audit::AuditEventType;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SecurityStatusQuery;
use crate::domain::security_status::{
    AppTokenStatus, ApproverStatus, Occurrences, RegisteredDeviceStatus, SecurityWarnings,
    SessionContextStatus, SessionKeyStatus, FAILURE_DAY_THRESHOLD,
};
use crate::domain::user_device::CountryCode;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

pub struct SqlxSecurityStatusQuery {
    pool: Db,
}

impl SqlxSecurityStatusQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn opt_time(row: &MySqlRow, name: &str) -> Result<Option<DateTime<Utc>>> {
    let v: Option<NaiveDateTime> = row.try_get(name).map_err(repo_err)?;
    Ok(v.map(to_utc))
}

fn count(row: &MySqlRow, name: &str) -> Result<u32> {
    let v: Option<i64> = row.try_get(name).map_err(repo_err)?;
    Ok(u32::try_from(v.unwrap_or(0).max(0)).unwrap_or(u32::MAX))
}

/// アプリを (組織, client_id) で見分ける。
type AppKey = (String, String);

#[async_trait]
impl SecurityStatusQuery for SqlxSecurityStatusQuery {
    async fn session_contexts(&self, user_id: Uuid) -> Result<Vec<SessionContextStatus>> {
        let rows = sqlx::query(
            "SELECT x.session_hash, x.device_hash, x.country, x.passkey_verified_at, \
                    x.key_algorithm, x.key_thumbprint, x.key_bound_at, x.key_refreshed_at, \
                    d.name AS device_name, d.registered_at AS device_registered_at, \
                    d.last_used_at AS device_last_used_at, \
                    k.device_name AS approver_device_name, k.security_level AS approver_level \
             FROM sso_session_contexts x \
             JOIN sso_sessions s ON s.session_hash = x.session_hash \
             LEFT JOIN user_devices d ON d.user_id = s.user_id AND d.device_hash = x.device_hash \
             LEFT JOIN app_approver_keys k ON k.id = x.approver_key_id \
             WHERE s.user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter()
            .map(|row| {
                let device_hash: Option<String> = row.try_get("device_hash").map_err(repo_err)?;
                let country: Option<String> = row.try_get("country").map_err(repo_err)?;
                let device_name: Option<String> = row.try_get("device_name").map_err(repo_err)?;
                let registered_device = match device_name {
                    Some(name) => Some(RegisteredDeviceStatus {
                        name,
                        registered_at: to_utc(
                            row.try_get("device_registered_at").map_err(repo_err)?,
                        ),
                        last_used_at: to_utc(row.try_get("device_last_used_at").map_err(repo_err)?),
                    }),
                    None => None,
                };
                let algorithm: Option<String> = row.try_get("key_algorithm").map_err(repo_err)?;
                let key = match (algorithm, opt_time(row, "key_bound_at")?) {
                    (Some(algorithm), Some(bound_at)) => Some(SessionKeyStatus {
                        algorithm,
                        thumbprint: row
                            .try_get::<Option<String>, _>("key_thumbprint")
                            .map_err(repo_err)?
                            .unwrap_or_default(),
                        bound_at,
                        refreshed_at: opt_time(row, "key_refreshed_at")?,
                    }),
                    _ => None,
                };
                let approver_name: Option<String> =
                    row.try_get("approver_device_name").map_err(repo_err)?;
                let approver = match approver_name {
                    Some(device_name) => Some(ApproverStatus {
                        device_name,
                        security_level: row.try_get("approver_level").map_err(repo_err)?,
                    }),
                    None => None,
                };
                Ok(SessionContextStatus {
                    session_hash: row.try_get("session_hash").map_err(repo_err)?,
                    device_identified: device_hash.is_some(),
                    registered_device,
                    country: country.as_deref().and_then(CountryCode::parse),
                    key,
                    approver,
                    passkey_verified_at: opt_time(row, "passkey_verified_at")?,
                })
            })
            .collect()
    }

    async fn app_tokens(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
        recent_since: DateTime<Utc>,
    ) -> Result<Vec<AppTokenStatus>> {
        let user = user_id.to_string();
        let mut apps: BTreeMap<AppKey, AppTokenStatus> = BTreeMap::new();
        let blank = |client_id: &str| AppTokenStatus {
            client_id: client_id.to_string(),
            app_name: String::new(),
            scopes: Vec::new(),
            active_refresh_tokens: 0,
            dpop_bound_refresh_tokens: 0,
            last_issued_at: None,
            refresh_use_count: 0,
            refresh_last_used_at: None,
            refresh_last_ip: None,
            refresh_last_user_agent: None,
            refresh_reuse_detected_at: None,
        };

        // 1. 同意したアプリ（範囲）。
        let consents = sqlx::query(
            "SELECT tenant_id, client_id, scopes FROM client_consents WHERE user_id = ?",
        )
        .bind(&user)
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        for row in &consents {
            let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
            let client_id: String = row.try_get("client_id").map_err(repo_err)?;
            let raw: Vec<u8> = row.try_get("scopes").map_err(repo_err)?;
            let scopes: Vec<String> = serde_json::from_slice(&raw).unwrap_or_default();
            apps.entry((tenant_id, client_id.clone()))
                .or_insert_with(|| blank(&client_id))
                .scopes = scopes;
        }

        // 2. いま有効なリフレッシュトークン（DPoP の結び付きの数も）。
        let tallies = sqlx::query(
            "SELECT tenant_id, client_id, COUNT(*) AS active_count, \
                    CAST(SUM(dpop_jkt IS NOT NULL) AS SIGNED) AS bound_count \
             FROM refresh_tokens \
             WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? \
             GROUP BY tenant_id, client_id",
        )
        .bind(&user)
        .bind(now.naive_utc())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        for row in &tallies {
            let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
            let client_id: String = row.try_get("client_id").map_err(repo_err)?;
            let app = apps
                .entry((tenant_id, client_id.clone()))
                .or_insert_with(|| blank(&client_id));
            app.active_refresh_tokens = count(row, "active_count")?;
            app.dpop_bound_refresh_tokens = count(row, "bound_count")?;
        }

        // 3. 最近トークンを出した・更新した記録（ログイン × アプリの行）。
        let usage = sqlx::query(
            "SELECT tenant_id, client_id, last_issued_at, refresh_use_count, refresh_last_used_at, \
                    refresh_last_ip, refresh_last_user_agent, refresh_reuse_detected_at \
             FROM sign_in_app_usage \
             WHERE user_id = ? AND (last_issued_at >= ? OR refresh_last_used_at >= ?)",
        )
        .bind(&user)
        .bind(recent_since.naive_utc())
        .bind(recent_since.naive_utc())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        for row in &usage {
            let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
            let client_id: String = row.try_get("client_id").map_err(repo_err)?;
            let app = apps
                .entry((tenant_id, client_id.clone()))
                .or_insert_with(|| blank(&client_id));
            let issued = to_utc(row.try_get("last_issued_at").map_err(repo_err)?);
            app.last_issued_at = Some(app.last_issued_at.map_or(issued, |t| t.max(issued)));
            let uses: i32 = row.try_get("refresh_use_count").map_err(repo_err)?;
            app.refresh_use_count = app
                .refresh_use_count
                .saturating_add(u32::try_from(uses).unwrap_or(0));
            if let Some(used) = opt_time(row, "refresh_last_used_at")? {
                if app.refresh_last_used_at.is_none_or(|t| used > t) {
                    app.refresh_last_used_at = Some(used);
                    app.refresh_last_ip = row.try_get("refresh_last_ip").map_err(repo_err)?;
                    app.refresh_last_user_agent =
                        row.try_get("refresh_last_user_agent").map_err(repo_err)?;
                }
            }
            if let Some(reuse) = opt_time(row, "refresh_reuse_detected_at")? {
                app.refresh_reuse_detected_at = Some(
                    app.refresh_reuse_detected_at
                        .map_or(reuse, |t| t.max(reuse)),
                );
            }
        }

        if apps.is_empty() {
            return Ok(Vec::new());
        }
        // 4. 表示名（消えたアプリは client_id のまま）。
        let mut q: QueryBuilder<MySql> =
            QueryBuilder::new("SELECT tenant_id, client_id, app_name FROM clients WHERE ");
        let mut first = true;
        for (tenant_id, client_id) in apps.keys() {
            if !first {
                q.push(" OR ");
            }
            first = false;
            q.push("(tenant_id = ")
                .push_bind(tenant_id.clone())
                .push(" AND client_id = ")
                .push_bind(client_id.clone())
                .push(")");
        }
        let names = q.build().fetch_all(&self.pool).await.map_err(repo_err)?;
        for row in &names {
            let key: AppKey = (
                row.try_get("tenant_id").map_err(repo_err)?,
                row.try_get("client_id").map_err(repo_err)?,
            );
            if let Some(app) = apps.get_mut(&key) {
                app.app_name = row.try_get("app_name").map_err(repo_err)?;
            }
        }
        let mut list: Vec<AppTokenStatus> = apps
            .into_values()
            .map(|mut app| {
                if app.app_name.is_empty() {
                    app.app_name = app.client_id.clone();
                }
                app
            })
            .collect();
        list.sort_by(|a, b| {
            a.app_name
                .to_lowercase()
                .cmp(&b.app_name.to_lowercase())
                .then_with(|| a.client_id.cmp(&b.client_id))
        });
        Ok(list)
    }

    async fn warnings(&self, user_id: Uuid, since: DateTime<Utc>) -> Result<SecurityWarnings> {
        let user = user_id.to_string();
        let since = since.naive_utc();

        let reuse = sqlx::query(
            "SELECT COUNT(*) AS n, MAX(refresh_reuse_detected_at) AS last_at \
             FROM sign_in_app_usage WHERE user_id = ? AND refresh_reuse_detected_at >= ?",
        )
        .bind(&user)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;

        // 別の鍵の署名は監査ログにだけ残る（ログイン状態・トークンは消える）。
        let mismatch = |event: &'static str, reason: Option<&'static str>| {
            let mut q: QueryBuilder<MySql> = QueryBuilder::new(
                "SELECT COUNT(*) AS n, MAX(occurred_at) AS last_at FROM audit_log WHERE event_type = ",
            );
            q.push_bind(event)
                .push(" AND user_id = ")
                .push_bind(user.clone())
                .push(" AND occurred_at >= ")
                .push_bind(since);
            if let Some(reason) = reason {
                q.push(" AND reason = ").push_bind(reason);
            }
            q
        };
        let mut session_q = mismatch(
            AuditEventType::SessionKeyRejected.as_str(),
            Some("key_mismatch"),
        );
        let session_key = session_q
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(repo_err)?;
        let mut dpop_q = mismatch(AuditEventType::RefreshTokenKeyMismatch.as_str(), None);
        let dpop_key = dpop_q
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(repo_err)?;

        let unregistered = sqlx::query(
            "SELECT COUNT(*) AS n, MAX(occurred_at) AS last_at FROM sign_in_history \
             WHERE user_id = ? AND occurred_at >= ? AND outcome = 'succeeded' \
               AND device_registered = FALSE",
        )
        .bind(&user)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;

        let failure_rows = sqlx::query(
            "SELECT DATE(occurred_at) AS day, COUNT(*) AS n FROM sign_in_history \
             WHERE user_id = ? AND occurred_at >= ? AND outcome <> 'succeeded' \
             GROUP BY DATE(occurred_at) HAVING COUNT(*) >= ? ORDER BY day DESC",
        )
        .bind(&user)
        .bind(since)
        .bind(i64::from(FAILURE_DAY_THRESHOLD))
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        let failure_days = failure_rows
            .iter()
            .map(|row| {
                let day: NaiveDate = row.try_get("day").map_err(repo_err)?;
                Ok((day, count(row, "n")?))
            })
            .collect::<Result<Vec<_>>>()?;

        let occurrences = |row: &MySqlRow| -> Result<Occurrences> {
            Ok(Occurrences {
                count: count(row, "n")?,
                last_at: opt_time(row, "last_at")?,
            })
        };
        Ok(SecurityWarnings {
            refresh_reuse: occurrences(&reuse)?,
            session_key_mismatch: occurrences(&session_key)?,
            dpop_key_mismatch: occurrences(&dpop_key)?,
            unregistered_sign_ins: occurrences(&unregistered)?,
            failure_days,
        })
    }
}
