//! Re-wraps secrets stored encrypted in the DB from the old `KEY_ENCRYPTION_KEY` value to the new one
//! (a one-off job run when the key is recreated; the binary is `assay-rewrap-secrets`).
//!
//! There is no mechanism to keep reading with the old key. While the api is stopped, this re-wraps everything,
//! and the api is restarted with the new key (task #618).
//!
//! - **Everything is written in one transaction.** It rolls back if any row can't be opened with the old key, a written
//!   value can't be opened with the new key, or it crashes midway (the DB stays as before; backups open with the old key)
//! - **Never applied twice.** If everything already opens with the new key, nothing is written and "done" is returned. If rows
//!   with the old key and the new key are mixed, it stops without leaning either way (a state a human should look at)
//! - Values are never output. Only per-field counts are returned
//! - In-progress external IdP login state (`external_login_requests`, expires in minutes) is deleted rather than re-wrapped

use crate::domain::crypto;
use anyhow::{bail, Context};
use sqlx::{MySqlPool, Row as _};

/// One encrypted field. Table and column names are fixed constants (no user input mixed in).
struct EncryptedColumn {
    /// Name shown in the report (`table.column`).
    label: &'static str,
    table: &'static str,
    value_column: &'static str,
    /// Column identifying the row (primary key).
    key_columns: &'static [&'static str],
    /// Condition selecting only wrapped rows.
    filter: &'static str,
}

/// All fields wrapped with `KEY_ENCRYPTION_KEY`. When adding a writer of `crypto::encrypt(.., key_encryption_key)`,
/// add it here too.
const ENCRYPTED_COLUMNS: &[EncryptedColumn] = &[
    // Signing private keys (including RETIRED; they must open when rolling back or reviewing).
    EncryptedColumn {
        label: "signing_keys.private_key_encrypted",
        table: "signing_keys",
        value_column: "private_key_encrypted",
        key_columns: &["kid"],
        filter: "1 = 1",
    },
    // TOTP shared keys. In the same column passkeys are plaintext JSON and recovery codes / email OTP are hashes, so
    // filter by type.
    EncryptedColumn {
        label: "user_authenticators.secret_encrypted (totp)",
        table: "user_authenticators",
        value_column: "secret_encrypted",
        key_columns: &["id"],
        filter: "authenticator_type = 'totp' AND secret_encrypted IS NOT NULL",
    },
    EncryptedColumn {
        label: "external_identity_providers.client_secret_encrypted",
        table: "external_identity_providers",
        value_column: "client_secret_encrypted",
        key_columns: &["id"],
        filter: "client_secret_encrypted IS NOT NULL AND client_secret_encrypted <> ''",
    },
    // SMTP password, SMS token. An empty string means "unset", not ciphertext.
    EncryptedColumn {
        label: "system_settings.setting_value (is_secret)",
        table: "system_settings",
        value_column: "setting_value",
        key_columns: &["setting_key"],
        filter: "is_secret = 1 AND setting_value <> ''",
    },
    EncryptedColumn {
        label: "tenant_settings.setting_value (is_secret)",
        table: "tenant_settings",
        value_column: "setting_value",
        key_columns: &["tenant_id", "setting_key"],
        filter: "is_secret = 1 AND setting_value <> ''",
    },
];

/// How to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewrapMode {
    /// Only counts whether rows can be opened. Writes nothing (the transaction is rolled back).
    Check,
    /// Re-wraps and commits.
    Apply,
}

/// Per-field counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnCount {
    pub label: &'static str,
    /// Number opened with the old key (= number to re-wrap / re-wrapped).
    pub under_old_key: usize,
    /// Number that already open with the new key.
    pub under_new_key: usize,
}

/// Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewrapOutcome {
    /// Rows with the old key were re-wrapped with the new key (with `Check`: "can be re-wrapped").
    Rewrapped {
        columns: Vec<ColumnCount>,
        /// Number of in-progress external IdP login states deleted (with `Check`: deletable).
        discarded_login_requests: u64,
    },
    /// Everything already opens with the new key. Nothing was written.
    AlreadyRewrapped { columns: Vec<ColumnCount> },
}

/// Hook for tests. The production tool calls with the default (does nothing).
#[derive(Debug, Clone, Copy, Default)]
pub struct RewrapFaults {
    /// Fail after writing this many (shows in tests that a mid-run crash rolls back the whole transaction).
    pub fail_after_writes: Option<usize>,
}

/// One row read.
struct StoredSecret {
    key_values: Vec<String>,
    plaintext: Vec<u8>,
}

/// Re-wraps every secret wrapped with the old key (`old_key`) with the new key (`new_key`).
pub async fn rewrap_secrets(
    pool: &MySqlPool,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    mode: RewrapMode,
) -> anyhow::Result<RewrapOutcome> {
    rewrap_secrets_with_faults(pool, old_key, new_key, mode, RewrapFaults::default()).await
}

/// Version of [`rewrap_secrets`] that can inject a failure for tests.
pub async fn rewrap_secrets_with_faults(
    pool: &MySqlPool,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    mode: RewrapMode,
    faults: RewrapFaults,
) -> anyhow::Result<RewrapOutcome> {
    if old_key == new_key {
        bail!("the old and new key encryption keys are the same; nothing to rewrap");
    }

    let mut tx = pool.begin().await.context("begin transaction")?;

    // 1. Read everything and count which key opens each (rows stay locked until the end of the transaction).
    let mut counts = Vec::with_capacity(ENCRYPTED_COLUMNS.len());
    let mut to_rewrap: Vec<(&EncryptedColumn, Vec<StoredSecret>)> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for column in ENCRYPTED_COLUMNS {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {keys}, {value} AS stored FROM {table} WHERE {filter} FOR UPDATE",
            keys = column.key_columns.join(", "),
            value = column.value_column,
            table = column.table,
            filter = column.filter,
        )))
        .fetch_all(&mut *tx)
        .await
        .with_context(|| format!("read {}", column.label))?;

        let mut count = ColumnCount {
            label: column.label,
            under_old_key: 0,
            under_new_key: 0,
        };
        let mut secrets = Vec::new();
        let mut not_opened = 0usize;
        for row in &rows {
            let stored: String = row.try_get("stored")?;
            if let Ok(plaintext) = crypto::decrypt(&stored, old_key) {
                let key_values = column
                    .key_columns
                    .iter()
                    .map(|k| row.try_get::<String, _>(*k))
                    .collect::<Result<Vec<_>, _>>()?;
                secrets.push(StoredSecret {
                    key_values,
                    plaintext,
                });
                count.under_old_key += 1;
            } else if crypto::decrypt(&stored, new_key).is_ok() {
                count.under_new_key += 1;
            } else {
                not_opened += 1;
            }
        }
        if not_opened > 0 {
            unreadable.push(format!("{}: {not_opened}", column.label));
        }
        counts.push(count);
        to_rewrap.push((column, secrets));
    }

    if !unreadable.is_empty() {
        bail!(
            "some stored secrets open with neither the old nor the new key; nothing was written ({})",
            unreadable.join(", ")
        );
    }
    let under_old: usize = counts.iter().map(|c| c.under_old_key).sum();
    let under_new: usize = counts.iter().map(|c| c.under_new_key).sum();
    if under_old > 0 && under_new > 0 {
        bail!(
            "stored secrets are mixed: {under_old} open with the old key and {under_new} with the new key; \
             nothing was written (was the api started with the new key before rewrapping?)"
        );
    }
    if under_old == 0 && under_new > 0 {
        // Never applied twice: if already done, write nothing.
        return Ok(RewrapOutcome::AlreadyRewrapped { columns: counts });
    }

    // 2. Re-wrap with the new key and write, then open the written value with the new key and check it matches the original plaintext.
    let mut written = 0usize;
    for (column, secrets) in &to_rewrap {
        let where_keys = column
            .key_columns
            .iter()
            .map(|k| format!("{k} = ?"))
            .collect::<Vec<_>>()
            .join(" AND ");
        let update_sql = format!(
            "UPDATE {table} SET {value} = ? WHERE {where_keys}",
            table = column.table,
            value = column.value_column,
        );
        let select_sql = format!(
            "SELECT {value} AS stored FROM {table} WHERE {where_keys}",
            table = column.table,
            value = column.value_column,
        );
        for secret in secrets {
            if faults.fail_after_writes == Some(written) {
                bail!(
                    "interrupted after {written} writes (test fault); the transaction is rolled back"
                );
            }
            let rewrapped = crypto::encrypt(&secret.plaintext, new_key)
                .with_context(|| format!("encrypt {}", column.label))?;
            let mut update = sqlx::query(sqlx::AssertSqlSafe(update_sql.clone())).bind(rewrapped);
            for v in &secret.key_values {
                update = update.bind(v);
            }
            let result = update
                .execute(&mut *tx)
                .await
                .with_context(|| format!("write {}", column.label))?;
            if result.rows_affected() != 1 {
                bail!(
                    "{}: expected to update 1 row, updated {}; nothing was written",
                    column.label,
                    result.rows_affected()
                );
            }
            written += 1;

            let mut select = sqlx::query(sqlx::AssertSqlSafe(select_sql.clone()));
            for v in &secret.key_values {
                select = select.bind(v);
            }
            let stored: String = select
                .fetch_one(&mut *tx)
                .await
                .with_context(|| format!("re-read {}", column.label))?
                .try_get("stored")?;
            let reopened = crypto::decrypt(&stored, new_key)
                .with_context(|| format!("{} does not open with the new key", column.label))?;
            if reopened != secret.plaintext {
                bail!(
                    "{}: the rewrapped value does not match the original; nothing was written",
                    column.label
                );
            }
        }
    }

    // 3. In-progress external IdP login state is deleted rather than re-wrapped (short-lived rows that expire while stopped).
    let discarded_login_requests = sqlx::query("DELETE FROM external_login_requests")
        .execute(&mut *tx)
        .await
        .context("discard external_login_requests")?
        .rows_affected();

    match mode {
        RewrapMode::Apply => tx.commit().await.context("commit")?,
        RewrapMode::Check => tx.rollback().await.context("rollback")?,
    }
    Ok(RewrapOutcome::Rewrapped {
        columns: counts,
        discarded_login_requests,
    })
}
