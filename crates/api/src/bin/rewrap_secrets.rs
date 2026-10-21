//! `assay-rewrap-secrets`: DB に暗号化して保存している秘密を、`KEY_ENCRYPTION_KEY`（今の鍵）から
//! `NEW_KEY_ENCRYPTION_KEY`（新しい鍵）へ包み直す。鍵を作り直すときに **api を止めて一度だけ** 流す。
//!
//! ```text
//! assay-rewrap-secrets --check   # 数えるだけ（何も書かない）
//! assay-rewrap-secrets --apply   # 包み直して確定する
//! ```
//!
//! 設定は api と同じ環境変数（`DATABASE_URL`・`KEY_ENCRYPTION_KEY` など）から読む。値は出さず、
//! 欄ごとの件数だけを出す。手順は docs/OPERATIONS.md「KEY_ENCRYPTION_KEY を作り直したいとき」。

use anyhow::{bail, Context};
use assay_api::config::{self, Config};
use assay_api::infrastructure::db;
use assay_api::infrastructure::secret_rewrap::{
    rewrap_secrets, ColumnCount, RewrapMode, RewrapOutcome,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("--check") => RewrapMode::Check,
        Some("--apply") => RewrapMode::Apply,
        _ => bail!("usage: assay-rewrap-secrets --check | --apply"),
    };

    let config = Config::from_env().context("failed to load configuration")?;
    if config.key_encryption_key_is_dev() {
        bail!(
            "KEY_ENCRYPTION_KEY is not set; refusing to rewrap from the built-in development key"
        );
    }
    let new_key =
        config::load_new_key_encryption_key()?.context("NEW_KEY_ENCRYPTION_KEY is not set")?;

    let pool = db::connect(&config)
        .await
        .context("failed to connect to database")?;
    let outcome = rewrap_secrets(&pool, config.key_encryption_key(), &new_key, mode).await?;

    match outcome {
        RewrapOutcome::Rewrapped {
            columns,
            discarded_login_requests,
        } => {
            let verb = match mode {
                RewrapMode::Check => "would rewrap",
                RewrapMode::Apply => "rewrapped",
            };
            print_counts(&columns);
            println!("external_login_requests discarded: {discarded_login_requests}");
            let total: usize = columns.iter().map(|c| c.under_old_key).sum();
            println!("{verb} {total} stored secrets from the old key to the new key");
        }
        RewrapOutcome::AlreadyRewrapped { columns } => {
            print_counts(&columns);
            println!("already rewrapped: every stored secret opens with the new key; nothing was written");
        }
    }
    Ok(())
}

fn print_counts(columns: &[ColumnCount]) {
    for c in columns {
        println!(
            "{}: old key {}, new key {}",
            c.label, c.under_old_key, c.under_new_key
        );
    }
}
