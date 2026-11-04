//! `SignInHistoryRepository` の sqlx 実装（task #879。ADR-0073）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SignInHistoryRepository;
use crate::domain::sign_in_history::{
    RefreshTokenTally, RefreshUsage, SignInAppUse, SignInFailure, SignInFailureKind, SignInOutcome,
    SignInRecord, SignInSuccess,
};
use crate::domain::tenant::TenantId;
use crate::domain::user_device::CountryCode;
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::authentication_methods_json;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::{MySql, QueryBuilder, Row};
use std::collections::HashMap;
use uuid::Uuid;

pub struct SqlxSignInHistoryRepository {
    pool: Db,
}

impl SqlxSignInHistoryRepository {
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

/// 長い値で INSERT を落とさないよう、列の長さに切り詰める。
fn clip(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|v| v.chars().take(max_chars).collect())
}

#[async_trait]
impl SignInHistoryRepository for SqlxSignInHistoryRepository {
    async fn record_success(&self, s: &SignInSuccess) -> Result<bool> {
        // 同じ sid の 2 回目は何もしない（`id = id` は行を変えないので影響行数が 0 になる）。
        let result = sqlx::query(
            "INSERT INTO sign_in_history \
             (user_id, tenant_id, occurred_at, outcome, ip_address, user_agent, country, \
              authentication_methods, sid, device_registered) \
             VALUES (?, ?, ?, 'succeeded', ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE id = id",
        )
        .bind(s.user_id.to_string())
        .bind(s.tenant_id.to_string())
        .bind(s.occurred_at.naive_utc())
        .bind(clip(s.ip_address.as_deref(), 45))
        .bind(clip(s.user_agent.as_deref(), 512))
        .bind(s.country.as_ref().map(CountryCode::as_str))
        .bind(authentication_methods_json::to_json(&s.methods))
        .bind(&s.sid)
        .bind(s.device_registered)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn record_failure(&self, f: &SignInFailure) -> Result<()> {
        sqlx::query(
            "INSERT INTO sign_in_history \
             (user_id, tenant_id, occurred_at, outcome, failure_kind, ip_address, user_agent, \
              client_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(f.user_id.to_string())
        .bind(f.tenant_id.map(|t| t.to_string()))
        .bind(f.occurred_at.naive_utc())
        .bind(f.outcome.as_str())
        .bind(f.kind.as_str())
        .bind(clip(f.ip_address.as_deref(), 45))
        .bind(clip(f.user_agent.as_deref(), 512))
        .bind(clip(f.client_id.as_deref(), 255))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn record_app_issue(
        &self,
        user_id: Uuid,
        tenant_id: TenantId,
        sid: &str,
        client_id: &str,
        issued_at: DateTime<Utc>,
        refresh_issued: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sign_in_app_usage \
             (sid, client_id, user_id, tenant_id, first_issued_at, last_issued_at, refresh_issued) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE last_issued_at = VALUES(last_issued_at), \
               refresh_issued = refresh_issued OR VALUES(refresh_issued)",
        )
        .bind(sid)
        .bind(client_id)
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .bind(issued_at.naive_utc())
        .bind(issued_at.naive_utc())
        .bind(refresh_issued)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn record_refresh_use(
        &self,
        sid: &str,
        client_id: &str,
        used_at: DateTime<Utc>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<()> {
        // この機能より前に出したトークンには行が無い。その更新は数えない（0 行で終わる）。
        sqlx::query(
            "UPDATE sign_in_app_usage \
             SET refresh_use_count = refresh_use_count + 1, refresh_last_used_at = ?, \
                 refresh_last_ip = ?, refresh_last_user_agent = ? \
             WHERE sid = ? AND client_id = ?",
        )
        .bind(used_at.naive_utc())
        .bind(clip(ip_address, 45))
        .bind(clip(user_agent, 512))
        .bind(sid)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn record_refresh_reuse(
        &self,
        sid: &str,
        client_id: &str,
        detected_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sign_in_app_usage SET refresh_reuse_detected_at = ? \
             WHERE sid = ? AND client_id = ?",
        )
        .bind(detected_at.naive_utc())
        .bind(sid)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn list_for_user(
        &self,
        user_id: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<SignInRecord>> {
        let mut q: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT h.id, h.occurred_at, h.outcome, h.failure_kind, h.ip_address, h.user_agent, \
                    h.country, h.authentication_methods, h.client_id, h.sid, h.device_registered, \
                    c.app_name \
             FROM sign_in_history h \
             LEFT JOIN clients c ON c.tenant_id = h.tenant_id AND c.client_id = h.client_id \
             WHERE h.user_id = ",
        );
        q.push_bind(user_id.to_string());
        if let Some(before) = before {
            q.push(" AND h.id < ").push_bind(before);
        }
        q.push(" ORDER BY h.id DESC LIMIT ")
            .push_bind(i64::from(limit));
        let rows = q.build().fetch_all(&self.pool).await.map_err(repo_err)?;
        rows.iter()
            .map(|row| {
                let outcome: String = row.try_get("outcome").map_err(repo_err)?;
                let kind: Option<String> = row.try_get("failure_kind").map_err(repo_err)?;
                let country: Option<String> = row.try_get("country").map_err(repo_err)?;
                Ok(SignInRecord {
                    id: row.try_get("id").map_err(repo_err)?,
                    occurred_at: to_utc(row.try_get("occurred_at").map_err(repo_err)?),
                    outcome: SignInOutcome::parse(&outcome).map_err(repo_err)?,
                    // 未知の分類（新しい版が書いた値）は「その他」として読む。
                    failure_kind: kind
                        .map(|k| SignInFailureKind::parse(&k).unwrap_or(SignInFailureKind::Other)),
                    ip_address: row.try_get("ip_address").map_err(repo_err)?,
                    user_agent: row.try_get("user_agent").map_err(repo_err)?,
                    country: country.as_deref().and_then(CountryCode::parse),
                    methods: authentication_methods_json::from_json(
                        row.try_get("authentication_methods").map_err(repo_err)?,
                    ),
                    client_id: row.try_get("client_id").map_err(repo_err)?,
                    app_name: row.try_get("app_name").map_err(repo_err)?,
                    sid: row.try_get("sid").map_err(repo_err)?,
                    device_registered: row
                        .try_get::<Option<bool>, _>("device_registered")
                        .map_err(repo_err)?,
                })
            })
            .collect()
    }

    async fn app_usage(
        &self,
        user_id: Uuid,
        sids: &[String],
        now: DateTime<Utc>,
    ) -> Result<Vec<SignInAppUse>> {
        if sids.is_empty() {
            return Ok(Vec::new());
        }
        let mut q: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT u.sid, u.client_id, u.first_issued_at, u.last_issued_at, u.refresh_issued, \
                    u.refresh_use_count, u.refresh_last_used_at, u.refresh_last_ip, \
                    u.refresh_last_user_agent, u.refresh_reuse_detected_at, c.app_name \
             FROM sign_in_app_usage u \
             LEFT JOIN clients c ON c.tenant_id = u.tenant_id AND c.client_id = u.client_id \
             WHERE u.user_id = ",
        );
        q.push_bind(user_id.to_string());
        push_sids(&mut q, "u.sid", sids);
        q.push(" ORDER BY u.first_issued_at");
        let usage_rows = q.build().fetch_all(&self.pool).await.map_err(repo_err)?;

        // リフレッシュトークンの今の状態は refresh_tokens から数える（取り消しの経路は多いので、
        // 経路ごとに写すより残っている行を見るほうが漏れない）。
        let mut t: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT sid, client_id, COUNT(*) AS row_count, \
                    CAST(SUM(revoked_at IS NULL AND expires_at > ",
        );
        t.push_bind(now.naive_utc());
        t.push(") AS SIGNED) AS active_count, CAST(SUM(expires_at > ");
        t.push_bind(now.naive_utc());
        t.push(
            ") AS SIGNED) AS unexpired_count, MAX(revoked_at) AS last_revoked_at \
             FROM refresh_tokens WHERE user_id = ",
        );
        t.push_bind(user_id.to_string());
        push_sids(&mut t, "sid", sids);
        t.push(" GROUP BY sid, client_id");
        let tally_rows = t.build().fetch_all(&self.pool).await.map_err(repo_err)?;
        let mut tallies: HashMap<(String, String), RefreshTokenTally> = HashMap::new();
        for row in &tally_rows {
            let sid: String = row.try_get("sid").map_err(repo_err)?;
            let client_id: String = row.try_get("client_id").map_err(repo_err)?;
            let count = |name: &str| -> Result<u32> {
                let v: Option<i64> = row.try_get(name).map_err(repo_err)?;
                Ok(u32::try_from(v.unwrap_or(0)).unwrap_or(u32::MAX))
            };
            let last_revoked: Option<NaiveDateTime> =
                row.try_get("last_revoked_at").map_err(repo_err)?;
            tallies.insert(
                (sid, client_id),
                RefreshTokenTally {
                    rows: count("row_count")?,
                    active: count("active_count")?,
                    unexpired: count("unexpired_count")?,
                    last_revoked_at: last_revoked.map(to_utc),
                },
            );
        }

        usage_rows
            .iter()
            .map(|row| {
                let sid: String = row.try_get("sid").map_err(repo_err)?;
                let client_id: String = row.try_get("client_id").map_err(repo_err)?;
                let refresh_issued: bool = row.try_get("refresh_issued").map_err(repo_err)?;
                let opt_time = |name: &str| -> Result<Option<DateTime<Utc>>> {
                    let v: Option<NaiveDateTime> = row.try_get(name).map_err(repo_err)?;
                    Ok(v.map(to_utc))
                };
                let refresh = if refresh_issued {
                    let use_count: i32 = row.try_get("refresh_use_count").map_err(repo_err)?;
                    let tally = tallies
                        .get(&(sid.clone(), client_id.clone()))
                        .copied()
                        .unwrap_or_default();
                    Some(RefreshUsage {
                        use_count: u32::try_from(use_count).unwrap_or(0),
                        last_used_at: opt_time("refresh_last_used_at")?,
                        last_ip_address: row.try_get("refresh_last_ip").map_err(repo_err)?,
                        last_user_agent: row
                            .try_get("refresh_last_user_agent")
                            .map_err(repo_err)?,
                        reuse_detected_at: opt_time("refresh_reuse_detected_at")?,
                        state: tally.state(),
                    })
                } else {
                    None
                };
                Ok(SignInAppUse {
                    first_issued_at: to_utc(row.try_get("first_issued_at").map_err(repo_err)?),
                    last_issued_at: to_utc(row.try_get("last_issued_at").map_err(repo_err)?),
                    app_name: row.try_get("app_name").map_err(repo_err)?,
                    sid,
                    client_id,
                    refresh,
                })
            })
            .collect()
    }
}

/// ` AND <column> IN (?, ?, …)` を足す。
fn push_sids(q: &mut QueryBuilder<MySql>, column: &'static str, sids: &[String]) {
    q.push(" AND ").push(column).push(" IN (");
    let mut list = q.separated(", ");
    for sid in sids {
        list.push_bind(sid.clone());
    }
    list.push_unseparated(")");
}
