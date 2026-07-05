//! マイグレーション整合の統合テスト。
//!
//! `TEST_DATABASE_URL` が設定されているときのみ実行する（未設定なら早期リターンで PASS）。
//! ローカルでは docker-compose の MariaDB を使い、例えば次のように実行する:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test schema

use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

const EXPECTED_TABLES: &[&str] = &[
    "users",
    "clients",
    "auth_sessions",
    "sso_sessions",
    "authorization_codes",
    "signing_keys",
    "audit_log",
];

#[tokio::test]
async fn migrations_apply_and_all_tables_exist() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping schema integration test");
        return;
    };

    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");

    MIGRATOR.run(&pool).await.expect("run migrations");

    for table in EXPECTED_TABLES {
        let row = sqlx::query(
            "SELECT COUNT(*) AS c FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("query information_schema");
        let count: i64 = row.get("c");
        assert_eq!(count, 1, "table `{table}` must exist after migration");
    }
}
