//! Users エンティティ（設計仕様 §3.1）。
#![allow(dead_code)]

use crate::domain::values::UserStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    /// 内部識別子。
    pub id: Uuid,
    /// 外部公開用のサブジェクト識別子（ID Token の `sub` 元）。
    pub sub: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// argon2 のパスワードハッシュ（PHC 文字列）。
    pub password_hash: String,
    pub status: UserStatus,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// アカウントが有効（トークン発行・ログイン可能）か。
    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }

    /// 指定時刻時点でロック中か。
    pub fn is_locked_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.locked_until, Some(until) if until > now)
    }
}
