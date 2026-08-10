//! Users エンティティ（設計仕様 §3.1 + ADR-0009 §2・§5）。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::UserStatus;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// ログイン失敗を 1 件記録した**後**の状態（[`crate::domain::repositories::UserRepository::record_login_failure`]）。
///
/// 加算とロック判定は 1 文の UPDATE で行われるため、呼び出し側はこの結果を見るだけでよい。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginFailureRecord {
    /// 記録後の連続失敗回数。
    pub failed_login_count: i32,
    /// ロックが掛かっているならその期限（掛かっていなければ `None`）。
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl LoginFailureRecord {
    /// この失敗でアカウントがロック状態になったか。
    pub fn is_locked(&self) -> bool {
        self.locked_until.is_some()
    }
}

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
    /// 現行パスワードを設定した時刻（AP7 の有効期限が測る起点）。`None` は未記録
    /// （列を足す前から在る利用者・旧プロセスが作った行）。[`User::password_set_at`] で読む。
    pub password_changed_at: Option<DateTime<Utc>>,
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

    /// 現行パスワードを設定した時刻。未記録なら**アカウント作成時刻**とみなす（AP7）。
    ///
    /// 未記録を「無期限」に丸めないのは、それだと列を足す前から在る利用者だけが有効期限の
    /// 外に出てしまうためである。最も古いパスワードほど期限の対象にしたいので、判定は
    /// 「少なくともこの時刻には存在した」という最古の根拠（作成時刻）に寄せる。
    pub fn password_set_at(&self) -> DateTime<Utc> {
        self.password_changed_at.unwrap_or(self.created_at)
    }
}
