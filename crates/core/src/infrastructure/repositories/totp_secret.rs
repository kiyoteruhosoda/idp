//! `TotpSecretRepository` の sqlx 実装。
//!
//! # 秘密の置き場所
//!
//! 共有鍵は**認証器の登録簿**（`user_authenticators.secret_encrypted`）にだけ在る（AP11b。
//! 元の表 `user_totp_secrets` は migration 0038 で削除した）。
//!
//! 対象にするのは「失効していない TOTP の行」である。再登録すると古い行は `revoked` になるため、
//! 失効した行まで見ると**取り消したはずの共有鍵で認証が通る**。
//!
//! トレイト（DIP 境界）は移行の前後で変えていない。秘密がどの表にあるかは infrastructure の
//! 都合であり、呼び出し側（ログイン・step-up・登録）が知る必要は無い。

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
    /// 共有鍵を登録簿の行へ載せる。
    ///
    /// 行そのものは `AuthenticatorManagementService::register_totp_pending` が先に作る。
    /// **1 行も更新できなかったら失敗させる**——秘密の置き場所が登録簿だけになった以上、
    /// 黙って何もしないと「登録できたのに設定されていない」利用者ができる。
    async fn upsert(&self, secret: &TotpSecret) -> Result<()> {
        let result = sqlx::query(
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
        if result.rows_affected() == 0 {
            return Err(DomainError::Repository(
                "no active totp authenticator row to store the shared secret on".to_string(),
            ));
        }
        Ok(())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
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

    /// 確認時刻を記録する。`status` の遷移（`pending` → `active`）は
    /// `AuthenticatorManagementService::activate_totp` が行う。
    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()> {
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

    /// 共有鍵を消す。**行は残す**（失効は `AuthenticatorManagementService::revoke_totp` が
    /// `status` で表す）。消し忘れると、失効させたはずの共有鍵が DB に残り続ける。
    async fn delete(&self, user_id: Uuid) -> Result<()> {
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
