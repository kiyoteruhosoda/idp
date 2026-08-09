//! G2: 期限切れレコードの一括 GC。
//!
//! 検証するのは 2 点:
//!   1. 掃除の**網羅性** —— `expires_at` を持つ表がすべて掃除対象に載っている（載せ忘れの検出）。
//!   2. 掃除の**動作** —— 期限切れ行だけが消え、期限内の行は残る。
//!
//! 実行方法は `schema.rs` と同じ（`TEST_DATABASE_URL` が必須）。

mod support;

use idp_api::application::expired_record_purge::ExpiredRecordPurgeService;
use idp_api::infrastructure::repositories::expired_records::{
    all_expiring_record_stores, PURGED_TABLES,
};
use sqlx::Row;
use std::sync::Arc;

/// `expires_at` を持ちながら掃除対象に載っていない表を検出する。
///
/// G2 の症状は「掃除が無い」ではなく「掃除される表とされない表が混ざっている」ことだった。
/// 表を足したときにここが落ちれば、掃除口の追加を忘れたと分かる。
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
        // `log` は保持日数（APP_LOG_RETENTION_DAYS）で別途削除しており、`expires_at` も持たない。
        if !PURGED_TABLES.contains(&table.as_str()) {
            missing.push(table);
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "these tables have an `expires_at` but are not swept by the purge task: {missing:?}"
    );

    // 逆向き: 掃除対象に載っているのに存在しない表（改名・削除の追随漏れ）も落とす。
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

/// 期限切れ行だけが消える（期限内の進行中フローを巻き込まない）。
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
    assert!(deleted >= 1, "期限切れ行が 1 件以上消えている");

    assert_eq!(
        count_auth_session(&env, &expired).await,
        0,
        "期限切れは消える"
    );
    assert_eq!(count_auth_session(&env, &live).await, 1, "期限内は残る");
}

/// `auth_sessions` に 1 行入れて、その `id_hash` を返す（`expires_at` は現在から `offset_secs` 秒後）。
async fn insert_auth_session(env: &support::TestEnv, client_id: &str, offset_secs: i64) -> String {
    let id_hash = idp_api::domain::auth_session::id_hash(&format!(
        "purge-test-{}-{offset_secs}",
        uuid::Uuid::now_v7()
    ));
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
