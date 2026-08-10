//! `WebAuthnCredentialRepository` の sqlx 実装。
//!
//! # 秘密の置き場所（AP11 の移行中）
//!
//! 公開鍵・署名カウンタ（`passkey_json` 全体）の単一の出所は**認証器の登録簿**
//! （`user_authenticators.secret_encrypted`）である。ただし移行の途中なので、
//! [`crate::infrastructure::repositories::totp_secret`] と同じ形をとる:
//!
//! - **読み**: 登録簿を先に見て、無ければ `user_webauthn_credentials` へ落ちる。
//! - **書き**: 両方へ書く（古いプロセスは元の表しか読まないため）。
//!
//! 元の表を落とすのは**次のリリース**。同じリリースで落とすと、まだ古いコードを動かしている
//! プロセスがパスキーを検証できなくなる。
//!
//! 登録簿から読んだ行の `id` は**登録簿の行 id**（元の表の id ではない）。更新・削除は同じ
//! リポジトリを通るので一貫する。登録簿の `credential_ref` との突き合わせは
//! [`crate::application::authenticator_management`] が両方の id を受け付ける形にしてある。

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

/// 登録簿から読むときの列の別名（元の表と同じ名前に揃えて `map_row` を共用する）。
const REGISTRY_COLUMNS: &str = "id, user_id, credential_id, secret_encrypted AS passkey_json, \
     label AS name, created_at, last_used_at";

const LEGACY_COLUMNS: &str =
    "id, user_id, credential_id, passkey_json, name, created_at, last_used_at";

/// 登録簿の「使えるパスキーの行」を絞る条件。失効した行と秘密の載っていない行は見ない。
const REGISTRY_FILTER: &str =
    "authenticator_type = 'webauthn' AND status <> 'revoked' AND secret_encrypted IS NOT NULL";

#[async_trait]
impl WebAuthnCredentialRepository for SqlxWebAuthnCredentialRepository {
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_webauthn_credentials \
             (id, user_id, credential_id, passkey_json, name, created_at, last_used_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(cred.id.to_string())
        .bind(cred.user_id.to_string())
        .bind(&cred.credential_id)
        .bind(&cred.passkey_json)
        .bind(&cred.name)
        .bind(cred.created_at.naive_utc())
        .bind(cred.last_used_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        // 登録簿側の行は `AuthenticatorManagementService::register_webauthn` が作る。
        // ここでは秘密と credential ID を載せるだけにする（行がまだ無ければ何も更新されず、
        // 読みは元の表へ落ちる ＝ 認証は通る）。
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, credential_id = ? \
             WHERE credential_ref = ?",
        )
        .bind(&cred.passkey_json)
        .bind(&cred.credential_id)
        .bind(cred.id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>> {
        // 登録簿の行 id でも、元の表の行 id（`credential_ref`）でも引けるようにする。
        // 移行中は呼び出し側が持っている id がどちらかに定まらないため。
        let sql = format!(
            "SELECT {REGISTRY_COLUMNS} FROM user_authenticators \
             WHERE (id = ? OR credential_ref = ?) AND {REGISTRY_FILTER} LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        if let Some(row) = row.as_ref() {
            return map_row(row).map(Some);
        }

        let sql = format!("SELECT {LEGACY_COLUMNS} FROM user_webauthn_credentials WHERE id = ?");
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
            "SELECT {REGISTRY_COLUMNS} FROM user_authenticators \
             WHERE credential_id = ? AND {REGISTRY_FILTER} LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        if let Some(row) = row.as_ref() {
            return map_row(row).map(Some);
        }

        let sql = format!(
            "SELECT {LEGACY_COLUMNS} FROM user_webauthn_credentials WHERE credential_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>> {
        // 一覧は登録簿だけを見る。元の表を足して重複させると、画面に同じパスキーが 2 行並ぶ。
        // 登録簿に載っていない行は 0035 が取り込んであり、以後の登録も両方へ書く。
        let sql = format!(
            "SELECT {REGISTRY_COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND {REGISTRY_FILTER} ORDER BY created_at ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        if !rows.is_empty() {
            return rows.iter().map(map_row).collect();
        }

        let sql = format!(
            "SELECT {LEGACY_COLUMNS} FROM user_webauthn_credentials \
             WHERE user_id = ? ORDER BY created_at ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()> {
        // 署名カウンタは**必ず**進めなければならない（進めないとクローン検知が効かない）ので、
        // 両方の置き場所を同じ値で更新する。id は登録簿・元の表のどちらのものでも受ける。
        sqlx::query(
            "UPDATE user_webauthn_credentials \
             SET passkey_json = ?, last_used_at = ? \
             WHERE id = ? OR id = (SELECT credential_ref FROM user_authenticators WHERE id = ?)",
        )
        .bind(passkey_json)
        .bind(last_used_at.naive_utc())
        .bind(id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, last_used_at = ? \
             WHERE (id = ? OR credential_ref = ?) AND authenticator_type = 'webauthn'",
        )
        .bind(passkey_json)
        .bind(last_used_at.naive_utc())
        .bind(id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "DELETE FROM user_webauthn_credentials \
             WHERE user_id = ? \
               AND (id = ? OR id = (SELECT credential_ref FROM user_authenticators WHERE id = ?))",
        )
        .bind(user_id.to_string())
        .bind(id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        // 登録簿の行は状態管理のため残す（失効は
        // `AuthenticatorManagementService::revoke_webauthn` が行う）。**秘密だけ**を消す。
        // credential ID も外す: 残すと、消したはずのパスキーが逆引きに当たり続ける。
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE user_id = ? AND authenticator_type = 'webauthn' \
               AND (id = ? OR credential_ref = ?)",
        )
        .bind(user_id.to_string())
        .bind(id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM user_webauthn_credentials WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;

        // 管理者による MFA 解除（MT21）。消し残しは復旧の失敗になるので、登録簿側の秘密も
        // まとめて落とす（件数は元の表のものを返す —— 呼び出し側は「何本外したか」を表示する）。
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE user_id = ? AND authenticator_type = 'webauthn'",
        )
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
