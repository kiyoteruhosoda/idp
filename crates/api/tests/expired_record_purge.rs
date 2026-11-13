//! G2: bulk GC of expired records.
//!
//! Two things are checked:
//!   1. **Coverage** of the purge — every table with `expires_at` is a purge target (detects forgotten ones).
//!   2. **Behaviour** of the purge — only expired rows disappear; rows still valid remain.
//!
//! Run the same way as `schema.rs` (`TEST_DATABASE_URL` is required).

mod support;

use assay_api::application::expired_record_purge::ExpiredRecordPurgeService;
use assay_api::infrastructure::repositories::expired_records::{
    all_expiring_record_stores, PURGED_TABLES,
};
use sqlx::Row;
use std::sync::Arc;

/// Detects tables that have `expires_at` but are not purge targets.
///
/// The G2 symptom was not "no purge" but "a mix of tables that are purged and tables that are not".
/// If this fails when a table is added, the purge entry was forgotten.
#[tokio::test]
async fn every_table_with_an_expiry_column_is_swept() {
    let Some(env) = support::setup("expired_record_purge_coverage").await else {
        return;
    };

    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.columns \
         WHERE table_schema = DATABASE() AND column_name = 'expires_at'",
    )
    .fetch_all(&env.pool)
    .await
    .expect("query information_schema");

    let mut missing: Vec<String> = Vec::new();
    for row in &rows {
        let table: String = row.get(0);
        // `log` is deleted separately by retention days (APP_LOG_RETENTION_DAYS) and has no `expires_at`.
        if !PURGED_TABLES.contains(&table.as_str()) {
            missing.push(table);
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "these tables have an `expires_at` but are not swept by the purge task: {missing:?}"
    );

    // The reverse: tables listed as purge targets that do not exist (missed renames / drops) also fail.
    for table in PURGED_TABLES {
        let n: i64 = sqlx::query(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = ?",
        )
        .bind(table)
        .fetch_one(&env.pool)
        .await
        .expect("query information_schema")
        .get(0);
        assert_eq!(n, 1, "swept table `{table}` does not exist");
    }
}

/// Only expired rows disappear (in-progress flows that are still valid are not affected).
#[tokio::test]
async fn only_expired_rows_are_deleted() {
    let Some(env) = support::setup("expired_record_purge_behaviour").await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let expired = insert_auth_session(&env, &client_id, -60).await;
    let live = insert_auth_session(&env, &client_id, 600).await;

    let service = ExpiredRecordPurgeService::new(
        all_expiring_record_stores(env.pool.clone()),
        Arc::new(support::SystemClock),
    );
    let deleted = service.purge_once().await;
    assert!(deleted >= 1, "at least one expired row was deleted");

    assert_eq!(
        count_auth_session(&env, &expired).await,
        0,
        "expired rows disappear"
    );
    assert_eq!(
        count_auth_session(&env, &live).await,
        1,
        "rows still valid remain"
    );
}

/// Inserts one row into `auth_sessions` and returns its `id_hash` (`expires_at` is `offset_secs` seconds from now).
async fn insert_auth_session(env: &support::TestEnv, client_id: &str, offset_secs: i64) -> String {
    let id_hash = assay_api::domain::auth_session::AuthSessionIdHash::of_plain(&format!(
        "purge-test-{}-{offset_secs}",
        uuid::Uuid::now_v7()
    ))
    .into_string();
    sqlx::query(
        "INSERT INTO auth_sessions \
         (id_hash, tenant_id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
          code_challenge_method, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', 's', 'n', 'c', 'S256', ?)",
    )
    .bind(&id_hash)
    .bind(&env.root_tenant_id)
    .bind(client_id)
    .bind(support::REDIRECT_URI)
    .bind((chrono::Utc::now() + chrono::Duration::seconds(offset_secs)).naive_utc())
    .execute(&env.pool)
    .await
    .expect("insert auth session");
    id_hash
}

async fn count_auth_session(env: &support::TestEnv, id_hash: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM auth_sessions WHERE id_hash = ?")
        .bind(id_hash)
        .fetch_one(&env.pool)
        .await
        .expect("count auth session")
        .get(0)
}
