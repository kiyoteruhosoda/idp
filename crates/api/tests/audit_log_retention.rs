//! G8: 監査ログの保持期間と絞り込み索引。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test audit_log_retention
//!
//! 検証するのは 3 点:
//!   1. 保持期間が既定（`0`）では**削除しない** —— 既定値で監査ログが消え始めない。
//!   2. 保持期間を設定すると、期限を過ぎた行だけが消える。
//!   3. 管理コンソールが投げる絞り込みが複合索引を使う —— 期間検索が全表走査に落ちない。

mod support;

use chrono::{Duration, Utc};
use idp_api::application::audit::AuditService;
use idp_api::domain::audit::AuditEvent;
use idp_api::domain::repositories::AuditLogSink;
use idp_api::infrastructure::repositories::audit_log::SqlxAuditLogSink;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

/// 保持期間の削除は**表全体**を時刻で薙ぐ（`purge_older_than(cutoff)`）。同じバイナリの
/// テストは並行に走るため、片方が入れた「十分に古い行」をもう片方の purge が巻き込む
/// —— 入れた直後に数えても 0 件になる。共有 DB の他バイナリは現在時刻の行しか書かないので、
/// 直列化が要るのはこのファイルの中だけである。
static PURGE_SERIALIZATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 監査イベントを 1 件、指定時刻で書き込む。`correlation_id` はテストごとに固有にして、
/// 他のテストが書いた行と混ざらないようにする。
async fn record_at(
    sink: &SqlxAuditLogSink,
    correlation_id: &str,
    occurred_at: chrono::DateTime<Utc>,
) {
    use idp_api::domain::audit::{AuditEventType, AuditResult};
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

/// 既定（`AUDIT_LOG_RETENTION_DAYS = 0`）では 1 行も消さない。監査ログの保存期間は法令・契約で
/// 決まるため、設定し忘れが「黙って消える」に転ばないことを保証する。
#[tokio::test]
async fn the_default_retention_never_deletes_anything() {
    let Some(env) = support::setup("audit log retention default").await else {
        return;
    };
    let _serialized = PURGE_SERIALIZATION.lock().await;
    let correlation = format!("retention-default-{}", Uuid::new_v4());
    let sink = SqlxAuditLogSink::new(env.pool.clone());
    // 10 年前の行でも残る。
    record_at(&sink, &correlation, Utc::now() - Duration::days(3_650)).await;

    let audit = AuditService::new(
        Arc::new(SqlxAuditLogSink::new(env.pool.clone())),
        Arc::new(support::SystemClock),
    );
    assert_eq!(audit.purge_expired(0).await.expect("purge"), 0);
    assert_eq!(count_by_correlation(&env.pool, &correlation).await, 1);
}

/// 保持期間を設定すると、境界より古い行だけが消える。
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

/// 管理コンソールの絞り込み（テナント × 期間 × result）が複合索引を使う。
///
/// G8 の症状は「索引が単一列しかなく、期間検索が事実上の全表走査になる」ことだった。
/// `EXPLAIN` が索引を選ばない（`type = ALL`）なら索引の設計が要件と噛み合っていない。
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
