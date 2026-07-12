//! Users エンティティ（設計仕様 §3.1 + ADR-0009 §2・§5）。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::UserStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct User {
    /// 内部識別子。
    pub id: Uuid,
    /// 所属元（ホーム）テナント。常に 1 つ・変更不可（ADR-0009 §2）。
    pub tenant_id: TenantId,
    /// 外部公開用のサブジェクト識別子（ID Token の `sub` 元）。
    pub sub: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// 表示言語設定（`ja` / `en`。NULL = 未設定。i18n 仕様書 §4 の優先度2。MT20）。
    pub language: Option<String>,
    /// argon2 のパスワードハッシュ（PHC 文字列）。
    pub password_hash: String,
    /// 自動生成パスワードで作成されたユーザーは初回ログイン時に変更を強制する（ADR-0009 §5）。
    pub must_change_password: bool,
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
