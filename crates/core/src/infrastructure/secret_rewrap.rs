//! DB に暗号化して保存している秘密を、`KEY_ENCRYPTION_KEY` の古い値から新しい値へ包み直す
//! （鍵を作り直すときに一度だけ流す作業。バイナリは `assay-rewrap-secrets`）。
//!
//! 古い鍵も読み続ける仕組みは持たない。api を止めた間にこれで全部を包み直し、新しい鍵で起こし直す
//! （task #618）。
//!
//! - **1 つの取引で全部を書く。** 1 件でも古い鍵で開けない・書いた値が新しい鍵で開けない・途中で
//!   落ちた、のどれでも取り消す（DB は流す前のまま。退避も古い鍵で開ける）
//! - **二重に掛けない。** 全部が既に新しい鍵で開けるなら何も書かずに「済み」を返す。古い鍵の行と
//!   新しい鍵の行が混ざっていたら、どちらにも寄せずに止める（人が見るべき状態）
//! - 値は出さない。返すのは欄ごとの件数だけ
//! - 外部 IdP ログインの途中の状態（`external_login_requests`、数分で切れる）は包み直さずに消す

use crate::domain::crypto;
use anyhow::{bail, Context};
use sqlx::{MySqlPool, Row as _};

/// 暗号化して保存している 1 つの欄。表と列の名前は固定の定数（利用者の入力は混ざらない）。
struct EncryptedColumn {
    /// 報告に出す名前（`表.列`）。
    label: &'static str,
    table: &'static str,
    value_column: &'static str,
    /// 行を特定する列（主キー）。
    key_columns: &'static [&'static str],
    /// 包んでいる行だけを選ぶ条件。
    filter: &'static str,
}

/// `KEY_ENCRYPTION_KEY` で包んでいる欄の全部。`crypto::encrypt(.., key_encryption_key)` の
/// 書き手を足したら、ここにも足す。
const ENCRYPTED_COLUMNS: &[EncryptedColumn] = &[
    // 署名の秘密鍵（RETIRED も含む。戻す・見直すときに開ける必要がある）。
    EncryptedColumn {
        label: "signing_keys.private_key_encrypted",
        table: "signing_keys",
        value_column: "private_key_encrypted",
        key_columns: &["kid"],
        filter: "1 = 1",
    },
    // TOTP の共有鍵。同じ列でもパスキーは平文の JSON、リカバリーコードと email OTP はハッシュなので
    // 種別で絞る。
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
    // SMTP のパスワード・SMS のトークン。空文字は「未設定」で暗号文ではない。
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

/// 流し方。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewrapMode {
    /// 開けるかを数えるだけ。何も書かない（取引は取り消す）。
    Check,
    /// 包み直して確定する。
    Apply,
}

/// 欄ごとの件数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnCount {
    pub label: &'static str,
    /// 古い鍵で開けた件数（＝包み直す・包み直した件数）。
    pub under_old_key: usize,
    /// 既に新しい鍵で開ける件数。
    pub under_new_key: usize,
}

/// 結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewrapOutcome {
    /// 古い鍵の行を新しい鍵で包み直した（`Check` では「包み直せる」）。
    Rewrapped {
        columns: Vec<ColumnCount>,
        /// 消した（`Check` では消せる）外部 IdP ログインの途中の状態の件数。
        discarded_login_requests: u64,
    },
    /// 全部が既に新しい鍵で開ける。何も書いていない。
    AlreadyRewrapped { columns: Vec<ColumnCount> },
}

/// 試験用の差し込み口。本番の道具は既定値（何もしない）で呼ぶ。
#[derive(Debug, Clone, Copy, Default)]
pub struct RewrapFaults {
    /// この件数を書いたところで失敗させる（途中で落ちても取引ごと戻ることを試験で示す）。
    pub fail_after_writes: Option<usize>,
}

/// 読んだ 1 行。
struct StoredSecret {
    key_values: Vec<String>,
    plaintext: Vec<u8>,
}

/// 古い鍵（`old_key`）で包んだ秘密を全部、新しい鍵（`new_key`）で包み直す。
pub async fn rewrap_secrets(
    pool: &MySqlPool,
    old_key: &[u8; 32],
    new_key: &[u8; 32],
    mode: RewrapMode,
) -> anyhow::Result<RewrapOutcome> {
    rewrap_secrets_with_faults(pool, old_key, new_key, mode, RewrapFaults::default()).await
}

/// [`rewrap_secrets`] に試験用の失敗を差し込める版。
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

    // 1. 全部を読み、どちらの鍵で開くかを数える（行は取引の終わりまで押さえる）。
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
        // 二重に掛けない: 済んでいるなら何も書かない。
        return Ok(RewrapOutcome::AlreadyRewrapped { columns: counts });
    }

    // 2. 新しい鍵で包み直して書き、書いた値を新しい鍵で開いて元の平文と一致するかを確かめる。
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

    // 3. 外部 IdP ログインの途中の状態は包み直さずに消す（止めている間に切れる短命の行）。
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
