//! 署名鍵のユースケース: ブートストラップ（ACTIVE 鍵の確保）、署名材料の取得、JWKS 構築。
#![allow(dead_code)]

use crate::domain::clock::Clock;
use crate::domain::repositories::SigningKeyRepository;
use crate::domain::signing_key::SigningKey;
use crate::domain::values::SigningKeyStatus;
use crate::infrastructure::{crypto, jwt};
use chrono::Duration;
use std::sync::Arc;

/// 鍵の有効期間（新規生成時の not_after までの日数）。
const KEY_VALIDITY_DAYS: i64 = 365;

/// 署名に使う ACTIVE 鍵の材料（復号済み秘密鍵 PEM と kid）。
pub struct ActiveSigningKey {
    pub kid: String,
    pub private_pem: String,
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
    pub async fn ensure_active_key(&self) -> anyhow::Result<()> {
        if self.find_active_key().await?.is_some() {
            return Ok(());
        }

        let (private_pem, public_pem) = jwt::generate_rsa_keypair()?;
        let now = self.clock.now();
        let kid = format!("{}-rs256-{}", now.format("%Y%m%d"), crypto::random_token(6));
        let private_key_encrypted =
            crypto::encrypt(private_pem.as_bytes(), &self.key_encryption_key)?;

        let key = SigningKey {
            kid: kid.clone(),
            algorithm: "RS256".to_string(),
            public_key: public_pem,
            private_key_encrypted,
            status: SigningKeyStatus::Active,
            not_before: now,
            not_after: now + Duration::days(KEY_VALIDITY_DAYS),
            created_at: now,
            updated_at: now,
        };

        self.repo
            .insert(&key)
            .await
            .map_err(|e| anyhow::anyhow!("insert signing key: {e}"))?;
        tracing::info!(kid = %kid, "generated new active signing key");
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
            private_pem,
        })
    }

    /// JWKS（ACTIVE + RETIRED の公開鍵）を構築する。
    pub async fn jwks(&self) -> anyhow::Result<jwt::Jwks> {
        let keys = self
            .repo
            .list_published()
            .await
            .map_err(|e| anyhow::anyhow!("list published keys: {e}"))?;
        let mut jwk_list = Vec::with_capacity(keys.len());
        for key in keys {
            jwk_list.push(jwt::rsa_public_jwk(&key.kid, &key.public_key)?);
        }
        Ok(jwt::Jwks { keys: jwk_list })
    }

    async fn find_active_key(&self) -> anyhow::Result<Option<SigningKey>> {
        self.repo
            .find_active()
            .await
            .map_err(|e| anyhow::anyhow!("find active key: {e}"))
    }
}
