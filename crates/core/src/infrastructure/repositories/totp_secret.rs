//! `TotpSecretRepository` の sqlx 実装。
//!
//! # 秘密の置き場所（AP11 の移行中）
//!
//! 秘密の単一の出所は**認証器の登録簿**（`user_authenticators.secret_encrypted`）である。
//! ただし移行の途中なので、次の 2 つを同時に満たす:
//!
//! - **読み**: 登録簿を先に見て、無ければ `user_totp_secrets` へ落ちる。移送（migration 0035）
//!   より前に登録された行と、ローリングデプロイ中に古いプロセスが書いた行を拾うため。
//! - **書き**: 両方へ書く。古いプロセスが元の表しか読まないので、片方だけに書くと、その
//!   プロセスから見て「登録したのに設定されていない」状態になる。
//!
//! 元の表を落とすのは**次のリリース**（このリリースが全ノードへ行き渡った後）。同じリリースで
//! 落とすと、まだ古いコードを動かしているプロセスが MFA を通せなくなる。
//!
//! トレイト（DIP 境界）は変えていない。秘密がどの表にあるかは infrastructure の都合であり、
//! 呼び出し側（ログイン・step-up・登録）が知る必要は無い。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TotpSecretRepository;
use crate::domain::totp_secret::TotpSecret;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxTotpSecretRepository {
    pool: Db,
}

impl SqlxTotpSecretRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// 登録簿から読む（失効した行は見ない。再登録で古い行が `revoked` になるため）。
    async fn find_in_registry(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
        let row = sqlx::query(
            "SELECT user_id, secret_encrypted, confirmed_at, created_at, updated_at \
             FROM user_authenticators \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' \
               AND secret_encrypted IS NOT NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// 元の表から読む（移送前の行・古いプロセスが書いた行のフォールバック）。
    async fn find_in_legacy_table(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
        let row = sqlx::query(
            "SELECT user_id, secret_encrypted, confirmed_at, created_at, updated_at \
             FROM user_totp_secrets WHERE user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<TotpSecret> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let confirmed_at: Option<NaiveDateTime> = row.try_get("confirmed_at").map_err(repo_err)?;
    Ok(TotpSecret {
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        secret_encrypted: row.try_get("secret_encrypted").map_err(repo_err)?,
        confirmed_at: confirmed_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl TotpSecretRepository for SqlxTotpSecretRepository {
    async fn upsert(&self, secret: &TotpSecret) -> Result<()> {
        // 元の表（移行中は古いプロセスもここを読む）。
        sqlx::query(
            "INSERT INTO user_totp_secrets (user_id, secret_encrypted, confirmed_at) \
             VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE secret_encrypted = VALUES(secret_encrypted), \
                                     confirmed_at = VALUES(confirmed_at)",
        )
        .bind(secret.user_id.to_string())
        .bind(&secret.secret_encrypted)
        .bind(secret.confirmed_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        // 登録簿（新しい単一の出所）。行そのものは
        // `AuthenticatorManagementService::register_totp_pending` が作るので、ここは秘密を載せる
        // だけにする。行がまだ無いときは何も更新されないが、その場合は読みが元の表へ落ちるので
        // 認証は通る（登録簿の行は次の登録操作で作られる）。
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, confirmed_at = COALESCE(confirmed_at, ?) \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked'",
        )
        .bind(&secret.secret_encrypted)
        .bind(secret.confirmed_at.map(|d| d.naive_utc()))
        .bind(secret.user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
        match self.find_in_registry(user_id).await? {
            Some(found) => Ok(Some(found)),
            None => self.find_in_legacy_table(user_id).await,
        }
    }

    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE user_totp_secrets SET confirmed_at = ? WHERE user_id = ? AND confirmed_at IS NULL",
        )
        .bind(confirmed_at.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        // 登録簿側の `confirmed_at` は `AuthenticatorManagementService::confirm_totp` が
        // `status` と併せて更新する。ここでは秘密を持つ行の時刻だけ揃えておく（登録簿を
        // 単一の出所にしたとき、確認済み判定がこの列で決まるため）。
        sqlx::query(
            "UPDATE user_authenticators SET confirmed_at = ? \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' \
               AND confirmed_at IS NULL",
        )
        .bind(confirmed_at.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM user_totp_secrets WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;

        // 登録簿の行は状態管理のため残す（失効は
        // `AuthenticatorManagementService::revoke_totp` が行う）。**秘密だけ**を消す。
        // 消し忘れると、失効させたはずの共有鍵が DB に残り続ける。
        sqlx::query(
            "UPDATE user_authenticators SET secret_encrypted = NULL \
             WHERE user_id = ? AND authenticator_type = 'totp'",
        )
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
