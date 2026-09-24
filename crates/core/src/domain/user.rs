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
    /// 配色設定（`light` / `dark` / `system`。NULL = 未設定）。`system` は「OS に合わせると
    /// 選んだ」であり、NULL の「まだ選んでいない」とは区別する（前者は端末をまたいで貫く）。
    pub theme: Option<String>,
    /// argon2 のパスワードハッシュ（PHC 文字列）。
    pub password_hash: String,
    /// 自動生成パスワードで作成されたユーザーは初回ログイン時に変更を強制する（ADR-0009 §5）。
    pub must_change_password: bool,
    /// 現行パスワードを設定した時刻（AP7 の有効期限が測る起点）。`None` は未記録
    /// （列を足す前から在る利用者・旧プロセスが作った行）。[`User::password_set_at`] で読む。
    pub password_changed_at: Option<DateTime<Utc>>,
    pub status: UserStatus,
    /// 仮登録（ADR-0064）。管理者が作ってから、本人が設定リンクで資格情報を決めるまで `true`。
    ///
    /// `status` と**直交する**。仮登録のまま無効にし、また有効に戻せる（戻しても仮登録のまま）。
    pub pending_setup: bool,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// アカウントが有効（トークン発行・ログイン可能）か。
    ///
    /// ⚠ **仮登録は有効ではない**（ADR-0064）。ログイン・トークン・管理コンソール・名簿の
    /// どの門もここを通るので、仮登録の人はどこからも入れない。本人が設定を終える経路だけは
    /// [`Self::can_finish_setup`] で通す。
    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active && !self.pending_setup
    }

    /// 設定リンクで資格情報を決めてよいか（ADR-0062 / ADR-0064）。
    ///
    /// 無効にされた利用者は仮登録でも通さない（止めた人が、手元のリンクで入り直せてしまう）。
    pub fn can_finish_setup(&self) -> bool {
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

#[cfg(test)]
mod pending_setup_tests {
    use super::*;

    fn user(status: UserStatus, pending_setup: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::nil(),
            tenant_id: Uuid::nil().into(),
            sub: Uuid::nil(),
            email: "a@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: String::new(),
            must_change_password: false,
            password_changed_at: None,
            status,
            pending_setup,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// ADR-0064: 仮登録は有効ではない。本人が設定を終える経路だけが通す。
    #[test]
    fn a_pending_user_is_not_active_but_may_finish_setup() {
        let pending = user(UserStatus::Active, true);
        assert!(!pending.is_active());
        assert!(pending.can_finish_setup());

        let done = user(UserStatus::Active, false);
        assert!(done.is_active());
        assert!(done.can_finish_setup());
    }

    /// 無効にされた人は、仮登録でも設定を終えられない。
    #[test]
    fn a_disabled_user_may_not_finish_setup() {
        assert!(!user(UserStatus::Disabled, true).can_finish_setup());
        assert!(!user(UserStatus::Disabled, false).is_active());
    }
}
