//! 署名鍵のユースケース: ブートストラップ（ACTIVE 鍵の確保）、署名材料の取得、JWKS 構築、管理操作。
#![allow(dead_code)]

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::SigningKeyRepository;
use crate::domain::signing_key::SigningKey;
use crate::domain::values::{SigningAlgorithm, SigningKeyStatus};
use crate::infrastructure::{crypto, jwt};
use chrono::Duration;
use std::sync::Arc;

/// 鍵の有効期間（新規生成時の not_after までの日数）。
const KEY_VALIDITY_DAYS: i64 = 365;

/// 署名に使う ACTIVE 鍵の材料（復号済み秘密鍵 PEM・kid・アルゴリズム）。
pub struct ActiveSigningKey {
    pub kid: String,
    pub algorithm: String,
    pub private_pem: String,
}

/// 署名鍵管理エラー。
#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct KeyService {
    repo: Arc<dyn SigningKeyRepository>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
}

impl KeyService {
    pub fn new(
        repo: Arc<dyn SigningKeyRepository>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
    ) -> Self {
        Self {
            repo,
            clock,
            key_encryption_key,
        }
    }

    /// ACTIVE 鍵が無ければ RSA 鍵ペアを生成し、秘密鍵を暗号化して永続化する（冪等）。
    ///
    /// 挿入は `insert_if_no_active`（repository の排他区間）で行い、複数インスタンスの同時起動
    /// （ローリングデプロイ・並列テスト）でも ACTIVE 鍵が重複生成されない（SEC5）。
    /// 排他区間で負けた側は生成済みの鍵材料を破棄して成功扱いにする。
    pub async fn ensure_active_key(&self) -> anyhow::Result<()> {
        if self.find_active_key().await?.is_some() {
            return Ok(());
        }
        let key = self.new_key_material(SigningAlgorithm::Rs256)?;
        let inserted = self
            .repo
            .insert_if_no_active(&key)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap signing key: {e}"))?;
        if inserted {
            tracing::info!(kid = %key.kid, "bootstrapped the active signing key");
        } else {
            tracing::info!("active signing key already bootstrapped by another instance");
        }
        Ok(())
    }

    /// 署名に使う ACTIVE 鍵（秘密鍵を復号して返す）。
    pub async fn active_signing_key(&self) -> anyhow::Result<ActiveSigningKey> {
        let key = self
            .find_active_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no active signing key"))?;
        let private_bytes = crypto::decrypt(&key.private_key_encrypted, &self.key_encryption_key)?;
        let private_pem = String::from_utf8(private_bytes)
            .map_err(|e| anyhow::anyhow!("decrypted private key is not valid UTF-8: {e}"))?;
        Ok(ActiveSigningKey {
            kid: key.kid,
            algorithm: key.algorithm,
            private_pem,
        })
    }

    /// JWKS（ACTIVE + RETIRED のうち not_after が未来のもの）を構築する。
    pub async fn jwks(&self) -> anyhow::Result<jwt::Jwks> {
        let keys = self
            .repo
            .list_published()
            .await
            .map_err(|e| anyhow::anyhow!("list published keys: {e}"))?;
        let mut jwk_list = Vec::with_capacity(keys.len());
        for key in keys {
            jwk_list.push(jwt::public_jwk(&key.kid, &key.algorithm, &key.public_key)?);
        }
        Ok(jwt::Jwks { keys: jwk_list })
    }

    // ── 自動ローテーション（K2）─────────────────────────────────────────────────

    /// 現行 ACTIVE 鍵の `not_after` まで `lead_days` 日を切っていれば新鍵を生成して旧鍵を退役させる。
    ///
    /// バックグラウンドタスクから定期的に呼び出す。冪等。
    /// - ACTIVE 鍵が無い場合は `ensure_active_key()` を呼んで鍵を補充する。
    /// - ACTIVE 鍵の残余期間が `lead_days` 以上あれば何もしない。
    /// - `lead_days` 日を切っていれば新鍵（ACTIVE）を生成し、旧鍵を RETIRED に変更する。
    pub async fn rotate_if_needed(&self, lead_days: u32) -> anyhow::Result<()> {
        let now = self.clock.now();
        let Some(active) = self.find_active_key().await? else {
            tracing::warn!("no active signing key found during rotation check; bootstrapping");
            self.generate_key_internal(SigningAlgorithm::Rs256).await?;
            return Ok(());
        };

        let remaining = active.not_after - now;
        let lead = chrono::Duration::days(lead_days as i64);
        if remaining > lead {
            return Ok(());
        }

        tracing::info!(
            kid = %active.kid,
            not_after = %active.not_after,
            remaining_hours = remaining.num_hours(),
            "signing key approaching expiry; rotating"
        );

        // 同じアルゴリズムで新鍵を生成する。
        let algorithm = SigningAlgorithm::parse(&active.algorithm)
            .map_err(|e| anyhow::anyhow!("unknown algorithm on active key: {e}"))?;
        self.generate_key_internal(algorithm).await?;

        // 旧鍵を RETIRED に変更する（新鍵生成後に行うことで signing 空白期間を排除）。
        self.repo
            .update_status(&active.kid, SigningKeyStatus::Retired)
            .await
            .map_err(|e| anyhow::anyhow!("retire old key {}: {e}", active.kid))?;
        tracing::info!(kid = %active.kid, "retired old signing key after rotation");

        Ok(())
    }

    // ── 管理操作 ──────────────────────────────────────────────────────────────

    /// 全署名鍵を作成日時の降順で返す（管理画面用）。
    pub async fn list_keys(&self) -> Result<Vec<SigningKey>, KeyManagementError> {
        self.repo
            .list_all()
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// 指定アルゴリズムの新規鍵を生成して ACTIVE で登録する。
    pub async fn generate_key(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<SigningKey, KeyManagementError> {
        self.generate_key_internal(algorithm)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// 指定 kid の ACTIVE 鍵を RETIRED に変更する。
    /// ACTIVE 鍵が他に存在しなくなる場合でも呼び出し側の責任で行う（管理者操作）。
    pub async fn retire_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let key = self
            .repo
            .find_by_kid(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Retired {
            return Err(KeyManagementError::Validation(format!(
                "key {kid} is already RETIRED"
            )));
        }

        self.repo
            .update_status(kid, SigningKeyStatus::Retired)
            .await
            .map_err(|e| match e {
                DomainError::NotFound => KeyManagementError::NotFound(kid.to_string()),
                other => KeyManagementError::Internal(other.to_string()),
            })
    }

    /// 指定 kid の鍵を削除する。ACTIVE 鍵の削除は禁止する（先に退役させること）。
    pub async fn delete_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let key = self
            .repo
            .find_by_kid(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Active {
            return Err(KeyManagementError::Validation(
                "cannot delete an ACTIVE key; retire it first".to_string(),
            ));
        }

        self.repo
            .delete(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    // ── プライベートヘルパー ───────────────────────────────────────────────────

    async fn find_active_key(&self) -> anyhow::Result<Option<SigningKey>> {
        self.repo
            .find_active()
            .await
            .map_err(|e| anyhow::anyhow!("find active key: {e}"))
    }

    async fn generate_key_internal(
        &self,
        algorithm: SigningAlgorithm,
    ) -> anyhow::Result<SigningKey> {
        let key = self.new_key_material(algorithm)?;
        self.repo
            .insert(&key)
            .await
            .map_err(|e| anyhow::anyhow!("insert signing key: {e}"))?;
        tracing::info!(kid = %key.kid, algorithm = %algorithm.as_str(), "generated new signing key");
        Ok(key)
    }

    /// 新しい ACTIVE 鍵の材料（鍵ペア生成・秘密鍵暗号化・kid 採番）を組み立てる（永続化しない）。
    fn new_key_material(&self, algorithm: SigningAlgorithm) -> anyhow::Result<SigningKey> {
        let (private_pem, public_pem) = match algorithm {
            SigningAlgorithm::Rs256 => jwt::generate_rsa_keypair()?,
            SigningAlgorithm::Es256 => jwt::generate_ec_keypair()?,
        };
        let now = self.clock.now();
        let alg_tag = algorithm.as_str().to_lowercase().replace("256", "");
        let kid = format!(
            "{}-{}-{}",
            now.format("%Y%m%d"),
            alg_tag,
            crypto::random_token(6)
        );
        let private_key_encrypted =
            crypto::encrypt(private_pem.as_bytes(), &self.key_encryption_key)?;

        Ok(SigningKey {
            kid,
            algorithm: algorithm.as_str().to_string(),
            public_key: public_pem,
            private_key_encrypted,
            status: SigningKeyStatus::Active,
            not_before: now,
            not_after: now + Duration::days(KEY_VALIDITY_DAYS),
            created_at: now,
            updated_at: now,
        })
    }
}
