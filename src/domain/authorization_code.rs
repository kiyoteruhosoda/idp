//! AuthorizationCodes エンティティ（設計仕様 §3.5）。
//! DB には平文ではなく `code_hash = SHA-256(authorization_code)` を保存する。
#![allow(dead_code)]

use crate::domain::values::CodeChallengeMethod;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub code_hash: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub auth_time: DateTime<Utc>,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthorizationCode {
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}
