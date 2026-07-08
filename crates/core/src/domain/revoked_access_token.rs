//! RevokedAccessTokens エンティティ（F5: Token 管理 §9.4）。
//! JWT Access Token のリボーク済み jti を記録し、/userinfo・/introspect で即時失効を実現する。
#![allow(dead_code)]

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct RevokedAccessToken {
    pub jti: String,
    pub revoked_at: DateTime<Utc>,
    /// 元の Access Token の exp。expires_at を過ぎたエントリは cleanup 可能。
    pub expires_at: DateTime<Utc>,
}
