//! ログイン欄の入力から「このテナントで認証してよい利用者」を解決する（ADR-0009 §8）。
//!
//! パスワードを受け付ける経路は 3 つある（OIDC ログイン [`crate::application::login`]・ポータル
//! ログイン [`crate::application::portal_login`]・管理ログイン [`crate::application::admin_login`]。
//! 強制パスワード変更の再検証を数えると 5 か所）。どれも「ログイン画面に入力された値は誰を指すか」
//! という同じ問いを解くので、規則をここに 1 本化する。各経路に書くと、一つ書き忘れた経路だけが
//! 別の集合を認証してしまう。
//!
//! # 対象は「当該テナントの ACTIVE なメンバー」
//!
//! 認証してよいのは、そのテナントに **ACTIVE なメンバーシップを持つ利用者**（HOME または GUEST）
//! である。所属元（HOME）だけに限らないのは、ゲストが参加先テナントのログイン画面から入れないと
//! 詰まるため —— 参加先の画面には「所属元はどこか」を尋ねる手がかりが無く、利用者は自分の所属元
//! テナント ID を URL に打ち込まない限りどこからも入れない。パスキー認証は既にこの規則で動いており
//! （[`crate::application::passkey_authentication`] の `ensure_active_member`）、パスワードだけが
//! 所属元限定に残っていた。
//!
//! # 解決の順序（所属元 → 参加先のゲスト）
//!
//! 1. 要求テナントの登録簿（[`UserRepository::find_by_login_identifier`]）。
//! 2. 空振りなら、要求テナントに ACTIVE な GUEST メンバーシップを持つ利用者を、その利用者の
//!    所属元テナントの登録簿で解決する
//!    （[`UserRepository::find_active_guest_by_login_identifier`]）。
//!
//! **順序に意味がある。** 1 と 2 をまとめて 1 回で引くと、同じユーザー名のゲストが参加してきた
//! だけで「曖昧な入力」になり、そのテナントの HOME 利用者まで締め出される。所属元を先に決めれば、
//! 参加先で名前が衝突しても割を食うのはゲスト側だけで済む（ゲストは所属元テナントの画面から
//! 従来どおり入れる）。
//!
//! # ここで決めないこと
//!
//! 認証ポリシー（AP2）・ロック・パスワードポリシーの評価対象は変わらない。ポリシーは
//! **要求テナント**のものを引き（`list_enabled_for_tenant`）、ロックとパスワードは利用者の属性
//! （`users` の列）である。ゲストが参加先の画面から入るときも、その画面のテナントのポリシーが
//! 掛かる —— パスキー認証・認可フローの復元判定
//! （[`crate::application::authorize`]）と同じ扱いで、参加先の管理者が自テナントのログインに
//! 掛けた条件が、ゲストにだけ素通りすることはない。

use crate::domain::error::Result;
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::User;

/// ログイン欄の入力から、`tenant_id` で認証してよい利用者を解決する。該当なし・曖昧はいずれも
/// `None`（呼び出し側は資格情報エラーに倒し、不存在と区別させない）。
pub async fn resolve_login_user(
    users: &dyn UserRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<Option<User>> {
    if let Some(user) = users.find_by_login_identifier(tenant_id, input).await? {
        return Ok(Some(user));
    }
    users
        .find_active_guest_by_login_identifier(tenant_id, input)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use crate::domain::user::LoginFailureRecord;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 20, 0, 0, 0).unwrap()
    }

    fn user(tenant_id: TenantId) -> User {
        User {
            id: Uuid::now_v7(),
            tenant_id,
            sub: Uuid::now_v7(),
            email: "member@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("member".to_string()),
            name: None,
            language: None,
            password_hash: "hash".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    /// 所属元での解決とゲストでの解決を独立に差し替えられるフェイク。`home_fails` は
    /// リポジトリ障害の再現に使う。
    #[derive(Default)]
    struct FakeUsers {
        home: Option<User>,
        guest: Option<User>,
        home_fails: bool,
        guest_calls: AtomicUsize,
    }

    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn find_by_username(&self, _t: TenantId, _name: &str) -> Result<Option<User>> {
            if self.home_fails {
                return Err(DomainError::Repository("db down".to_string()));
            }
            Ok(self.home.clone())
        }
        async fn find_active_guest_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _input: &str,
        ) -> Result<Option<User>> {
            self.guest_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.guest.clone())
        }
        async fn create(&self, _u: &User) -> Result<()> {
            unreachable!()
        }
        async fn find_by_id(&self, _id: Uuid) -> Result<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> Result<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> Result<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _count: i32,
            _locked_until: Option<DateTime<Utc>>,
        ) -> Result<()> {
            unreachable!()
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
        ) -> Result<LoginFailureRecord> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _e: &str, _h: &str) -> Result<bool> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _e: &str, _h: &str) -> Result<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> Result<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> Result<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> Result<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> Result<()> {
            unreachable!()
        }
    }

    /// 所属元で解決できた利用者は従来どおり返り、ゲストの検索は行われない（参加してきた同名の
    /// ゲストが HOME 利用者を「曖昧」にしないための順序）。
    #[tokio::test]
    async fn resolves_home_member_without_consulting_guests() {
        let tenant: TenantId = Uuid::now_v7().into();
        let home = user(tenant);
        let repo = FakeUsers {
            home: Some(home.clone()),
            guest: Some(user(Uuid::now_v7().into())),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert_eq!(resolved.map(|u| u.id), Some(home.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// 所属元が空振りなら、当該テナントの ACTIVE な GUEST として解決する（本修正の主眼）。
    #[tokio::test]
    async fn falls_back_to_active_guest_of_the_requested_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let guest = user(Uuid::now_v7().into());
        let repo = FakeUsers {
            guest: Some(guest.clone()),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert_eq!(resolved.map(|u| u.id), Some(guest.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 1);
    }

    /// どちらでも解決できなければ `None`（呼び出し側は資格情報エラーに倒す）。
    #[tokio::test]
    async fn returns_none_when_neither_resolves() {
        let tenant: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers::default();
        assert!(resolve_login_user(&repo, tenant, "member")
            .await
            .unwrap()
            .is_none());
    }

    /// リポジトリ障害は握り潰さずそのまま伝える（`None` に丸めると障害が「利用者不在」に化け、
    /// ゲスト検索という余計な問い合わせまで走る）。
    #[tokio::test]
    async fn propagates_repository_errors_without_falling_back() {
        let repo = FakeUsers {
            home_fails: true,
            ..FakeUsers::default()
        };
        let err = resolve_login_user(&repo, Uuid::now_v7().into(), "member")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Repository(_)));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }
}
