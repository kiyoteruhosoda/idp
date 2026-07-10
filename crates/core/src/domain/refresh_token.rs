//! RefreshTokens エンティティ（設計仕様 §9.1）。
//! DB には平文ではなく `token_hash = SHA-256(refresh_token)` を保存する。
//! `parent_hash` は rotation / reuse detection に使う。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub token_hash: String,
    /// rotation で発行する際に設定する（チェーンの前トークンの hash）。
    pub parent_hash: Option<String>,
    /// トークンを発行したテナント（ADR-0009 §8。使用・失効は同一テナントに限る）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub client_id: String,
    pub scope: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RefreshToken {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        !self.is_revoked() && !self.is_expired_at(now)
    }
}
