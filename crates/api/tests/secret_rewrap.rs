//! Integration test for rewrapping `KEY_ENCRYPTION_KEY` (`infrastructure::secret_rewrap`, task #618).
//!
//! The shared test DB holds "non-ciphertext values" placed by other tests (`test-ciphertext` etc.), and
//! running a tool that rewraps everything there would break other tests. So each test creates **a throwaway DB**
//! (`CREATE DATABASE` as root on the `TEST_DATABASE_URL` host; CI has `MARIADB_ROOT_PASSWORD`).
//!
//! What is pinned:
//! 1. If it fails midway, everything is as before the run (= same as the backup taken before; all open with the old key)
//! 2. After rewrapping, everything opens with the new key and the plain text is unchanged. Unwrapped values (passkey JSON,
//!    recovery code hashes) are not touched
//! 3. No double application (the second run writes nothing and reports "done")
//! 4. Writing back the backup values restores the state where everything opens with the old key, and it can run again
//! 5. If a value opens with neither key, or old-key and new-key values are mixed, it stops without writing anything

use assay_api::infrastructure::crypto;
use assay_api::infrastructure::secret_rewrap::{
    rewrap_secrets, rewrap_secrets_with_faults, RewrapFaults, RewrapMode, RewrapOutcome,
};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Executor as _, MySqlPool, Row as _};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const OLD_KEY: [u8; 32] = *b"rewrap-test-old-key-0123456789!!";
const NEW_KEY: [u8; 32] = *b"rewrap-test-new-key-0123456789!!";
const OTHER_KEY: [u8; 32] = *b"rewrap-test-other-key-012345678!";

/// Per-test throwaway DB. Cleaned up with `drop_database`.
struct ThrowawayDb {
    admin: MySqlPool,
    pool: MySqlPool,
    name: String,
}

impl ThrowawayDb {
    async fn create(test_name: &str) -> Option<Self> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            if std::env::var("IDP_ALLOW_DB_TEST_SKIP").ok().as_deref() == Some("1") {
                eprintln!("TEST_DATABASE_URL not set; intentionally skipping {test_name}");
                return None;
            }
            panic!("TEST_DATABASE_URL is required for {test_name}");
        };
        // When a DB host is given but root is not, fail instead of skipping (skipping silently would look green
        // in CI without having run).
        let root_password = std::env::var("MARIADB_ROOT_PASSWORD").unwrap_or_else(|_| {
            panic!("MARIADB_ROOT_PASSWORD is required for {test_name} (it creates a throwaway database)")
        });
        let mut admin_url = url::Url::parse(&url).expect("TEST_DATABASE_URL");
        admin_url.set_username("root").expect("set user");
        admin_url
            .set_password(Some(&root_password))
            .expect("set password");
        admin_url.set_path("/");
        let admin = MySqlPoolOptions::new()
            .max_connections(2)
            .connect(admin_url.as_str())
            .await
            .expect("connect as root");

        let name = format!("idp_rewrap_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE `{name}`")))
            .execute(&admin)
            .await
            .expect("create throwaway database");
        let mut db_url = admin_url.clone();
        db_url.set_path(&format!("/{name}"));
        let pool = MySqlPoolOptions::new()
            .max_connections(4)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("SET time_zone = '+00:00'").await?;
                    Ok(())
                })
            })
            .connect(db_url.as_str())
            .await
            .expect("connect to throwaway database");
        MIGRATOR.run(&pool).await.expect("run migrations");
        Some(Self { admin, pool, name })
    }

    async fn drop_database(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS `{}`",
            self.name
        )))
        .execute(&self.admin)
        .await
        .expect("drop throwaway database");
    }
}

/// Places one of each wrapped value and unwrapped value (a different kind in the same column).
/// Returns the list of wrapped plain texts (key -> plain text).
async fn seed(pool: &MySqlPool) -> Vec<(String, Vec<u8>)> {
    let root: String = sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
        .fetch_one(pool)
        .await
        .expect("root tenant");
    let user: String =
        sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = ? ORDER BY created_at LIMIT 1")
            .bind(&root)
            .fetch_one(pool)
            .await
            .expect("seeded user");
    let mut plaintexts = Vec::new();
    let mut wrap = |id: &str, plain: &[u8]| {
        plaintexts.push((id.to_string(), plain.to_vec()));
        crypto::encrypt(plain, &OLD_KEY).expect("encrypt")
    };

    for (kid, status) in [("rewrap-active", "ACTIVE"), ("rewrap-retired", "RETIRED")] {
        sqlx::query(
            "INSERT INTO signing_keys \
             (kid, algorithm, public_key, private_key_encrypted, status, not_before, not_after) \
             VALUES (?, 'RS256', 'public', ?, ?, UTC_TIMESTAMP(6), \
                     UTC_TIMESTAMP(6) + INTERVAL 90 DAY)",
        )
        .bind(kid)
        .bind(wrap(kid, format!("private key of {kid}").as_bytes()))
        .bind(status)
        .execute(pool)
        .await
        .expect("insert signing key");
    }

    for status in ["active", "revoked"] {
        let id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO user_authenticators \
             (id, user_id, authenticator_type, status, secret_encrypted, created_at) \
             VALUES (?, ?, 'totp', ?, ?, UTC_TIMESTAMP(6))",
        )
        .bind(&id)
        .bind(&user)
        .bind(status)
        .bind(wrap(&id, format!("totp secret {status}").as_bytes()))
        .execute(pool)
        .await
        .expect("insert totp");
    }
    // Unwrapped values: passkey JSON and recovery code hashes.
    sqlx::query(
        "INSERT INTO user_authenticators \
         (id, user_id, authenticator_type, status, secret_encrypted, credential_id, created_at) \
         VALUES (?, ?, 'webauthn', 'active', '{\"passkey\":true}', 'cred-rewrap', UTC_TIMESTAMP(6))",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&user)
    .execute(pool)
    .await
    .expect("insert passkey");
    sqlx::query(
        "INSERT INTO user_authenticators \
         (id, user_id, authenticator_type, status, secret_encrypted, created_at) \
         VALUES (?, ?, 'recovery_code', 'active', SHA2('recovery', 256), UTC_TIMESTAMP(6))",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&user)
    .execute(pool)
    .await
    .expect("insert recovery code");

    let provider = uuid::Uuid::now_v7().to_string();
    for (id, code, secret) in [
        (provider.clone(), "with-secret", true),
        (uuid::Uuid::now_v7().to_string(), "without-secret", false),
    ] {
        sqlx::query(
            "INSERT INTO external_identity_providers \
             (id, tenant_id, provider_code, display_name, issuer, authorization_endpoint, \
              token_endpoint, jwks_uri, client_id, client_secret_encrypted, scopes) \
             VALUES (?, ?, ?, ?, 'https://idp.example', 'https://idp.example/a', \
                     'https://idp.example/t', 'https://idp.example/j', 'client', ?, '[\"openid\"]')",
        )
        .bind(&id)
        .bind(&root)
        .bind(code)
        .bind(code)
        .bind(secret.then(|| wrap(&id, b"external client secret")))
        .execute(pool)
        .await
        .expect("insert external idp");
    }
    sqlx::query(
        "INSERT INTO external_login_requests \
         (id, tenant_id, provider_id, state_hash, nonce, code_verifier_encrypted, expires_at) \
         VALUES (?, ?, ?, SHA2('state', 256), 'nonce', ?, UTC_TIMESTAMP(6) + INTERVAL 5 MINUTE)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&root)
    .bind(&provider)
    .bind(crypto::encrypt(b"verifier", &OLD_KEY).expect("encrypt"))
    .execute(pool)
    .await
    .expect("insert external login request");

    for (key, value, is_secret) in [
        ("smtp.password", Some(b"smtp password".as_slice()), 1),
        ("sms.auth_token", None, 1),
        ("smtp.host", None, 0),
    ] {
        let stored = match value {
            Some(plain) => wrap(key, plain),
            None if is_secret == 1 => String::new(),
            None => "smtp.example".to_string(),
        };
        sqlx::query(
            "INSERT INTO system_settings (setting_key, setting_value, is_secret) VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), \
                                     is_secret = VALUES(is_secret)",
        )
        .bind(key)
        .bind(stored)
        .bind(is_secret)
        .execute(pool)
        .await
        .expect("insert system setting");
    }
    let tenant_key = format!("{root}/smtp.password");
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
         VALUES (?, 'smtp.password', ?, 1)",
    )
    .bind(&root)
    .bind(wrap(&tenant_key, b"tenant smtp password"))
    .execute(pool)
    .await
    .expect("insert tenant setting");

    plaintexts
}

/// Copies every column that holds wrapped values (in place of the "backup" taken before the run). Rows are `(table, key, value)`.
async fn snapshot(pool: &MySqlPool) -> Vec<(String, String, Option<String>)> {
    let queries = [
        ("signing_keys", "SELECT kid AS k, private_key_encrypted AS v FROM signing_keys"),
        ("user_authenticators", "SELECT id AS k, secret_encrypted AS v FROM user_authenticators"),
        (
            "external_identity_providers",
            "SELECT id AS k, client_secret_encrypted AS v FROM external_identity_providers",
        ),
        ("system_settings", "SELECT setting_key AS k, setting_value AS v FROM system_settings"),
        (
            "tenant_settings",
            "SELECT CONCAT(tenant_id, '/', setting_key) AS k, setting_value AS v FROM tenant_settings",
        ),
    ];
    let mut out = Vec::new();
    for (table, sql) in queries {
        for row in sqlx::query(sql).fetch_all(pool).await.expect("snapshot") {
            out.push((
                table.to_string(),
                row.get::<String, _>("k"),
                row.get::<Option<String>, _>("v"),
            ));
        }
    }
    out.sort();
    out
}

/// Writes back the backup values (in production, restore the dump; here restoring only the wrapped columns suffices).
async fn restore(pool: &MySqlPool, backup: &[(String, String, Option<String>)]) {
    for (table, key, value) in backup {
        let sql = match table.as_str() {
            "signing_keys" => "UPDATE signing_keys SET private_key_encrypted = ? WHERE kid = ?",
            "user_authenticators" => {
                "UPDATE user_authenticators SET secret_encrypted = ? WHERE id = ?"
            }
            "external_identity_providers" => {
                "UPDATE external_identity_providers SET client_secret_encrypted = ? WHERE id = ?"
            }
            "system_settings" => {
                "UPDATE system_settings SET setting_value = ? WHERE setting_key = ?"
            }
            "tenant_settings" => {
                "UPDATE tenant_settings SET setting_value = ? \
                 WHERE CONCAT(tenant_id, '/', setting_key) = ?"
            }
            other => panic!("unknown table {other}"),
        };
        sqlx::query(sql)
            .bind(value)
            .bind(key)
            .execute(pool)
            .await
            .expect("restore");
    }
}

/// Whether every value `seed` wrapped opens with `key` and the plain text is unchanged.
fn all_open_with(
    snap: &[(String, String, Option<String>)],
    plaintexts: &[(String, Vec<u8>)],
    key: &[u8; 32],
) -> bool {
    plaintexts.iter().all(|(id, plain)| {
        snap.iter()
            .find(|(_, k, _)| k == id)
            .and_then(|(_, _, v)| v.as_deref())
            .and_then(|v| crypto::decrypt(v, key).ok())
            .as_deref()
            == Some(plain.as_slice())
    })
}

/// Extracts only the unwrapped values (rows not in `seed`'s plain-text list).
fn untouched_rows(
    snap: &[(String, String, Option<String>)],
    plaintexts: &[(String, Vec<u8>)],
) -> Vec<(String, String, Option<String>)> {
    snap.iter()
        .filter(|(_, k, _)| !plaintexts.iter().any(|(id, _)| id == k))
        .cloned()
        .collect()
}

async fn login_requests(pool: &MySqlPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM external_login_requests")
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn an_interrupted_rewrap_leaves_everything_as_it_was_before() {
    let Some(db) = ThrowawayDb::create("rewrap interrupted").await else {
        return;
    };
    let plaintexts = seed(&db.pool).await;
    let backup = snapshot(&db.pool).await;

    for written in [0, 1, 4] {
        let err = rewrap_secrets_with_faults(
            &db.pool,
            &OLD_KEY,
            &NEW_KEY,
            RewrapMode::Apply,
            RewrapFaults {
                fail_after_writes: Some(written),
            },
        )
        .await
        .expect_err("the fault must stop the rewrap");
        assert!(err.to_string().contains("interrupted"), "{err}");

        let after = snapshot(&db.pool).await;
        assert_eq!(
            after, backup,
            "nothing may be written when interrupted after {written}"
        );
        assert!(all_open_with(&after, &plaintexts, &OLD_KEY));
        assert_eq!(login_requests(&db.pool).await, 1);
    }

    // Even after a failure, simply running it again rewraps.
    let outcome = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect("rewrap after the interruption");
    assert!(matches!(outcome, RewrapOutcome::Rewrapped { .. }));
    assert!(all_open_with(
        &snapshot(&db.pool).await,
        &plaintexts,
        &NEW_KEY
    ));

    db.drop_database().await;
}

#[tokio::test]
async fn rewrap_moves_every_secret_to_the_new_key_once() {
    let Some(db) = ThrowawayDb::create("rewrap once").await else {
        return;
    };
    let plaintexts = seed(&db.pool).await;
    let before = snapshot(&db.pool).await;

    // Counting alone writes nothing.
    let checked = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Check)
        .await
        .expect("check");
    assert_eq!(snapshot(&db.pool).await, before);
    assert_eq!(login_requests(&db.pool).await, 1);

    let applied = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect("apply");
    assert_eq!(checked, applied, "check reports exactly what apply does");
    let RewrapOutcome::Rewrapped {
        columns,
        discarded_login_requests,
    } = applied
    else {
        panic!("expected a rewrap, got {applied:?}");
    };
    let counts: Vec<(&str, usize, usize)> = columns
        .iter()
        .map(|c| (c.label, c.under_old_key, c.under_new_key))
        .collect();
    assert_eq!(
        counts,
        vec![
            ("signing_keys.private_key_encrypted", 2, 0),
            ("user_authenticators.secret_encrypted (totp)", 2, 0),
            ("external_identity_providers.client_secret_encrypted", 1, 0),
            ("system_settings.setting_value (is_secret)", 1, 0),
            ("tenant_settings.setting_value (is_secret)", 1, 0),
        ]
    );
    assert_eq!(discarded_login_requests, 1);
    assert_eq!(login_requests(&db.pool).await, 0);

    let after = snapshot(&db.pool).await;
    assert!(all_open_with(&after, &plaintexts, &NEW_KEY));
    assert!(!all_open_with(&after, &plaintexts, &OLD_KEY));
    assert_eq!(
        untouched_rows(&after, &plaintexts),
        untouched_rows(&before, &plaintexts),
        "values that are not wrapped by the key (passkey JSON, hashes, plain settings) stay as they were"
    );

    // No double application: the second run writes nothing.
    let again = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect("second run");
    assert!(
        matches!(again, RewrapOutcome::AlreadyRewrapped { .. }),
        "{again:?}"
    );
    assert_eq!(snapshot(&db.pool).await, after);

    db.drop_database().await;
}

#[tokio::test]
async fn restoring_the_backup_brings_back_the_old_key_state() {
    let Some(db) = ThrowawayDb::create("rewrap restore").await else {
        return;
    };
    let plaintexts = seed(&db.pool).await;
    let backup = snapshot(&db.pool).await;

    rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect("apply");
    assert_ne!(snapshot(&db.pool).await, backup);

    // The check found a problem: restoring the backup returns to the original state where all open with the old key.
    restore(&db.pool, &backup).await;
    let restored = snapshot(&db.pool).await;
    assert_eq!(restored, backup);
    assert!(all_open_with(&restored, &plaintexts, &OLD_KEY));

    // After restoring, it can be run again.
    let outcome = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect("rewrap again");
    assert!(matches!(outcome, RewrapOutcome::Rewrapped { .. }));
    assert!(all_open_with(
        &snapshot(&db.pool).await,
        &plaintexts,
        &NEW_KEY
    ));

    db.drop_database().await;
}

#[tokio::test]
async fn unreadable_or_mixed_secrets_stop_without_writing() {
    let Some(db) = ThrowawayDb::create("rewrap refuses").await else {
        return;
    };
    seed(&db.pool).await;

    // Do not run with the same key.
    let err = rewrap_secrets(&db.pool, &OLD_KEY, &OLD_KEY, RewrapMode::Apply)
        .await
        .expect_err("same key");
    assert!(err.to_string().contains("same"), "{err}");

    // There is a value that opens with neither key.
    sqlx::query(
        "INSERT INTO system_settings (setting_key, setting_value, is_secret) \
         VALUES ('rewrap.unknown', ?, 1)",
    )
    .bind(crypto::encrypt(b"x", &OTHER_KEY).expect("encrypt"))
    .execute(&db.pool)
    .await
    .expect("insert unreadable");
    let before = snapshot(&db.pool).await;
    let err = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect_err("unreadable");
    assert!(err.to_string().contains("neither"), "{err}");
    assert_eq!(snapshot(&db.pool).await, before);
    assert_eq!(login_requests(&db.pool).await, 1);

    // Old-key values and new-key values are mixed.
    sqlx::query(
        "UPDATE system_settings SET setting_value = ? WHERE setting_key = 'rewrap.unknown'",
    )
    .bind(crypto::encrypt(b"x", &NEW_KEY).expect("encrypt"))
    .execute(&db.pool)
    .await
    .expect("make it mixed");
    let before = snapshot(&db.pool).await;
    let err = rewrap_secrets(&db.pool, &OLD_KEY, &NEW_KEY, RewrapMode::Apply)
        .await
        .expect_err("mixed");
    assert!(err.to_string().contains("mixed"), "{err}");
    assert_eq!(snapshot(&db.pool).await, before);

    db.drop_database().await;
}
