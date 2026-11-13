//! G8: audit log retention period and filter indexes.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test audit_log_retention
//!
//! Three things are checked:
//!   1. With the default retention (`0`) **nothing is deleted** — audit logs do not start disappearing by default.
//!   2. With a retention period set, only rows past it disappear.
//!   3. The filters the admin console sends use the composite index — period searches do not fall back to full scans.

mod support;

use assay_api::application::audit::AuditService;
use assay_api::domain::audit::AuditEvent;
use assay_api::domain::repositories::AuditLogSink;
use assay_api::infrastructure::repositories::audit_log::SqlxAuditLogSink;
use chrono::{Duration, Utc};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// Retention deletion sweeps **the whole table** by time (`purge_older_than(cutoff)`). Tests in the same
/// binary run in parallel, so one test's purge sweeps up the "old enough rows" another inserted
/// — counting right after inserting gives 0. Other binaries sharing the DB only write rows at the current time,
/// so serialization is needed only within this file.
static PURGE_SERIALIZATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Writes one audit event at the given time. `correlation_id` is unique per test so
/// rows do not mix with those written by other tests.
async fn record_at(
    sink: &SqlxAuditLogSink,
    correlation_id: &str,
    occurred_at: chrono::DateTime<Utc>,
) {
    use assay_api::domain::audit::{AuditEventType, AuditResult};
    sink.record(&AuditEvent {
        event_type: AuditEventType::LoginSucceeded,
        occurred_at,
        tenant_id: None,
        user_id: None,
        client_id: None,
        ip_address: None,
        user_agent: None,
        result: AuditResult::Success,
        reason: None,
        correlation_id: correlation_id.to_string(),
    })
    .await
    .expect("record audit event");
}

async fn count_by_correlation(pool: &sqlx::MySqlPool, correlation_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM audit_log WHERE correlation_id = ?")
        .bind(correlation_id)
        .fetch_one(pool)
        .await
        .expect("count audit rows")
        .get(0)
}

/// With the default (`AUDIT_LOG_RETENTION_DAYS = 0`) not a single row is deleted. Audit log retention is set by
/// law and contract, so this guarantees forgetting to configure it does not turn into "silently deleted".
#[tokio::test]
async fn the_default_retention_never_deletes_anything() {
    let Some(env) = support::setup("audit log retention default").await else {
        return;
    };
    let _serialized = PURGE_SERIALIZATION.lock().await;
    let correlation = format!("retention-default-{}", Uuid::new_v4());
    let sink = SqlxAuditLogSink::new(env.pool.clone());
    // Even a row from 10 years ago remains.
    record_at(&sink, &correlation, Utc::now() - Duration::days(3_650)).await;

    let audit = AuditService::new(
        Arc::new(SqlxAuditLogSink::new(env.pool.clone())),
        Arc::new(support::SystemClock),
    );
    assert_eq!(audit.purge_expired(0).await.expect("purge"), 0);
    assert_eq!(count_by_correlation(&env.pool, &correlation).await, 1);
}

/// With a retention period set, only rows older than the boundary disappear.
#[tokio::test]
async fn only_rows_older_than_the_retention_window_are_deleted() {
    let Some(env) = support::setup("audit log retention window").await else {
        return;
    };
    let _serialized = PURGE_SERIALIZATION.lock().await;
    let old = format!("retention-old-{}", Uuid::new_v4());
    let fresh = format!("retention-fresh-{}", Uuid::new_v4());
    let sink = SqlxAuditLogSink::new(env.pool.clone());
    record_at(&sink, &old, Utc::now() - Duration::days(40)).await;
    record_at(&sink, &fresh, Utc::now() - Duration::days(3)).await;

    let audit = AuditService::new(
        Arc::new(SqlxAuditLogSink::new(env.pool.clone())),
        Arc::new(support::SystemClock),
    );
    let deleted = audit.purge_expired(30).await.expect("purge");
    assert!(deleted >= 1, "expected the 40-day-old row to be deleted");
    assert_eq!(count_by_correlation(&env.pool, &old).await, 0);
    assert_eq!(count_by_correlation(&env.pool, &fresh).await, 1);
}

/// The admin console's filter (tenant × period × result) uses the composite index.
///
/// The G8 symptom was "only single-column indexes, so period searches are effectively full scans".
/// If `EXPLAIN` does not choose an index (`type = ALL`), the index design does not fit the requirement.
#[tokio::test]
async fn the_console_filter_uses_a_composite_index() {
    let Some(env) = support::setup("audit log index").await else {
        return;
    };

    let row = sqlx::query(
        "EXPLAIN SELECT id FROM audit_log \
         WHERE tenant_id = ? AND result = ? AND occurred_at >= ? \
         ORDER BY occurred_at DESC, id DESC LIMIT 50",
    )
    .bind(env.root_tenant_id.to_string())
    .bind("failure")
    .bind((Utc::now() - Duration::days(7)).naive_utc())
    .fetch_one(&env.pool)
    .await
    .expect("explain the console filter");

    let access_type: String = row.try_get("type").expect("EXPLAIN type column");
    let key: Option<String> = row.try_get("key").expect("EXPLAIN key column");
    assert_ne!(
        access_type, "ALL",
        "the console filter fell back to a full table scan (key = {key:?})"
    );
    assert!(
        key.as_deref()
            .is_some_and(|k| k.starts_with("audit_log_tenant_")),
        "expected one of the tenant-scoped composite indexes, got {key:?}"
    );
}
