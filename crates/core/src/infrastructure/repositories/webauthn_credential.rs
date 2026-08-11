//! `WebAuthnCredentialRepository` の sqlx 実装。
//!
//! # 秘密の置き場所
//!
//! 公開鍵・署名カウンタ（`passkey_json` 全体）は**認証器の登録簿**
//! （`user_authenticators.secret_encrypted`）にだけ在る（AP11b。元の表
//! `user_webauthn_credentials` は migration 0038 で削除した）。
//!
//! **パスキー 1 本 = 登録簿の 1 行**である。`WebAuthnCredential::id` は登録簿の行 id で、
//! 移行中にあった「元の表の id か登録簿の id か」という曖昧さは無くなった
//! （`credential_ref` も 0038 で落としている）。
//!
//! 行を作るのはこのリポジトリで、状態（`status`）を動かすのは
//! [`crate::application::authenticator_management`] である。秘密を持つ側が行を作らないと、
//! 「行はあるが鍵が載っていない」瞬間が生まれる。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::WebAuthnCredentialRepository;
use crate::domain::webauthn_credential::WebAuthnCredential;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxWebAuthnCredentialRepository {
    pool: Db,
}

impl SqlxWebAuthnCredentialRepository {
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

fn map_row(row: &MySqlRow) -> Result<WebAuthnCredential> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let last_used_at: Option<NaiveDateTime> = row.try_get("last_used_at").map_err(repo_err)?;
    Ok(WebAuthnCredential {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        credential_id: row.try_get("credential_id").map_err(repo_err)?,
        passkey_json: row.try_get("passkey_json").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        last_used_at: last_used_at.map(to_utc),
    })
}

/// 登録簿の列を `WebAuthnCredential` の語彙へ揃える別名。
const COLUMNS: &str = "id, user_id, credential_id, secret_encrypted AS passkey_json, \
     label AS name, created_at, last_used_at";

/// 「使えるパスキーの行」を絞る条件。失効した行と鍵の載っていない行は見ない。
const USABLE: &str =
    "authenticator_type = 'webauthn' AND status <> 'revoked' AND secret_encrypted IS NOT NULL";

#[async_trait]
impl WebAuthnCredentialRepository for SqlxWebAuthnCredentialRepository {
    /// 登録簿へパスキーの行を作る。**登録した瞬間から使える**ので `active`／`confirmed_at` 入りで
    /// 作る（WebAuthn の登録は attestation の検証まで済んでいて、TOTP のような確認手順が無い）。
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_authenticators \
             (id, user_id, authenticator_type, status, label, secret_encrypted, credential_id, \
              confirmed_at, last_used_at, created_at) \
             VALUES (?, ?, 'webauthn', 'active', ?, ?, ?, ?, ?, ?)",
        )
        .bind(cred.id.to_string())
        .bind(cred.user_id.to_string())
        .bind(&cred.name)
        .bind(&cred.passkey_json)
        .bind(&cred.credential_id)
        .bind(cred.created_at.naive_utc())
        .bind(cred.last_used_at.map(|d| d.naive_utc()))
        .bind(cred.created_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // credential ID の一意制約。同じ認証器を二重登録しようとしたときに当たる。
            if matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000")) {
                DomainError::Conflict("credential is already registered".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>> {
        let sql =
            format!("SELECT {COLUMNS} FROM user_authenticators WHERE id = ? AND {USABLE} LIMIT 1");
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebAuthnCredential>> {
        let sql = format!(
            "SELECT {COLUMNS} FROM user_authenticators \
             WHERE credential_id = ? AND {USABLE} LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>> {
        let sql = format!(
            "SELECT {COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND {USABLE} ORDER BY created_at ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    /// 署名カウンタを進める。**必ず進めなければならない**（進めないとクローン検知が効かない）。
    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, last_used_at = ? \
             WHERE id = ? AND authenticator_type = 'webauthn'",
        )
        .bind(passkey_json)
        .bind(last_used_at.naive_utc())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// パスキーを 1 本消す。**行は残す**（失効は
    /// `AuthenticatorManagementService::revoke_webauthn` が `status` で表す）。credential ID も
    /// 外す: 残すと、消したはずのパスキーが逆引きに当たり続ける。
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE id = ? AND user_id = ? AND authenticator_type = 'webauthn'",
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// 管理者による MFA 解除（MT21）。消し残しは復旧の失敗になるので、鍵をまとめて落とす。
    /// 返すのは**外した本数**（呼び出し側が表示する）。
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE user_id = ? AND authenticator_type = 'webauthn' \
               AND secret_encrypted IS NOT NULL",
        )
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
