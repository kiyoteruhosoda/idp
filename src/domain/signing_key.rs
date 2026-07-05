//! SigningKeys エンティティ（設計仕様 §3.6）。
#![allow(dead_code)]

use crate::domain::values::SigningKeyStatus;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub kid: String,
    /// 署名アルゴリズム。MVP は `RS256` のみ。
    pub algorithm: String,
    /// 公開鍵（JWKS 公開用）。
    pub public_key: String,
    /// DB 外の鍵で暗号化した秘密鍵。
    pub private_key_encrypted: String,
    pub status: SigningKeyStatus,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SigningKey {
    /// 新規署名に使える鍵か（ACTIVE かつ有効期間内）。
    pub fn is_usable_for_signing_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SigningKeyStatus::Active && self.not_before <= now && now < self.not_after
    }
}
