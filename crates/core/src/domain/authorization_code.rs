//! AuthorizationCodes エンティティ（設計仕様 §3.5）。
//! DB には平文ではなく `code_hash = SHA-256(authorization_code)` を保存する。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::{AuthenticationMethod, CodeChallengeMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub code_hash: String,
    /// code を発行したテナント（ADR-0009 §8。トークン交換は同一テナントに限る）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub auth_time: DateTime<Utc>,
    /// ID Token へ載せる SSO セッション識別子（G5）。`None` = セッション不明（本列の導入前の code）。
    pub sid: Option<String>,
    /// この認可を与えた認証で実際に検証された方式（ADR-0043）。ID Token の `acr` / `amr` は
    /// ここから導く。`/token` は Cookie もセッションも読めないため、発行時に引き継ぐ。
    /// `None` = 記録なし（本列の導入前の code）。このとき `acr` / `amr` は**載せない**
    /// ——分からないものを単一要素と名乗ると嘘になる。
    pub authentication_methods: Option<Vec<AuthenticationMethod>>,
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
