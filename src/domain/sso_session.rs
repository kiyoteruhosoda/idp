//! SsoSessions エンティティ（設計仕様 §3.4）。
//! Cookie には `session_id`、DB には `session_hash = SHA-256(session_id)` のみ保存する。
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SsoSession {
    pub session_hash: String,
    pub user_id: Uuid,
    /// 初回ログイン時刻。SSO 復元時も ID Token の `auth_time` にコピーする（設計仕様 §5.1）。
    pub auth_time: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SsoSession {
    /// 指定時刻時点で有効か（idle・absolute の双方が未超過）。
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.idle_expires_at > now && self.absolute_expires_at > now
    }
}
