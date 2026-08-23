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
//!    （[`UserRepository::find_active_guest_by_login_identifier`]）。**所属元テナントが `DISABLED`
//!    なら解決しない** —— 所属元の無効化はその組織の利用者を止める操作であって、参加先テナント
//!    経由の裏口を残す意味ではない（ADR-0009 §8。同じ規則をメンバーシップ側から見たものが
//!    [`crate::domain::repositories::TenantMembershipRepository::is_active_member`] で、パスキー
//!    認証・SSO 復元・管理コンソールのアクセス判定はそちらを通る）。
//!
//! **順序に意味がある。** 1 と 2 をまとめて 1 回で引くと、同じユーザー名のゲストが参加してきた
//! だけで「曖昧な入力」になり、そのテナントの HOME 利用者まで締め出される。所属元を先に決めれば、
//! 参加先で名前が衝突しても割を食うのはゲスト側だけで済む（ゲストは所属元テナントの画面から
//! 従来どおり入れる）。
//!
//! # 曖昧な入力はそこで止める（MT25）
//!
//! 1 が**曖昧**（複数人に当たった）だったときに 2 へ進んではいけない。ここは以前
//! `Option<User>` を返しており、「不在」と「曖昧」がどちらも `None` に潰れていたため、所属元で
//! 曖昧だった入力がそのままゲスト解決へ落ちていた。なりすましは起きない（ゲストは自分の
//! パスワードで自分として入る）が、「曖昧なら通さない」「所属元がテナント内の名前の取り合いに
//! 勝つ」という 2 つの決めごとが、まさにそれが要る場面で破れていた。
//!
//! [`LoginIdentifierMatch`] が 2 つを型で分けるので、`Unresolved(NotFound)` のときだけ 2 へ進む。
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
use crate::domain::login_identifier::{LoginIdentifierMatch, UnresolvedReason};
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;

/// ログイン欄の入力から、`tenant_id` で認証してよい利用者を解決する。
///
/// 解決できなかったときの応答は呼び出し側で一律に資格情報エラーへ倒すが（不存在を露呈させない）、
/// 理由は [`UnresolvedReason`] として返す —— 監査に残す値が違う。
pub async fn resolve_login_user(
    users: &dyn UserRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<LoginIdentifierMatch> {
    match users.find_by_login_identifier(tenant_id, input).await? {
        // 所属元で曖昧なら、そこで止める（ゲスト解決へ落とさない）。
        found @ (LoginIdentifierMatch::Resolved(_)
        | LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)) => Ok(found),
        LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound) => {
            users
                .find_active_guest_by_login_identifier(tenant_id, input)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use crate::domain::user::LoginFailureRecord;
    use crate::domain::user::User;
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
    ///
    /// `find_by_login_identifier` の既定実装（`find_by_username` へ委譲）は「不在」しか表せない
    /// ので、曖昧を試す回のためにこちらを直接上書きする。
    struct FakeUsers {
        home: LoginIdentifierMatch,
        guest: LoginIdentifierMatch,
        home_fails: bool,
        guest_calls: AtomicUsize,
    }

    impl Default for FakeUsers {
        fn default() -> Self {
            Self {
                home: LoginIdentifierMatch::not_found(),
                guest: LoginIdentifierMatch::not_found(),
                home_fails: false,
                guest_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn find_by_username(&self, _t: TenantId, _name: &str) -> Result<Option<User>> {
            unreachable!("解決は find_by_login_identifier を通る")
        }
        async fn find_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _input: &str,
        ) -> Result<LoginIdentifierMatch> {
            if self.home_fails {
                return Err(DomainError::Repository("db down".to_string()));
            }
            Ok(self.home.clone())
        }
        async fn find_active_guest_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _input: &str,
        ) -> Result<LoginIdentifierMatch> {
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

    /// 解決された利用者 id を取り出す（曖昧・不在は `None`）。
    fn resolved_id(m: LoginIdentifierMatch) -> Option<Uuid> {
        m.into_user().map(|u| u.id)
    }

    /// 所属元で解決できた利用者は従来どおり返り、ゲストの検索は行われない（参加してきた同名の
    /// ゲストが HOME 利用者を「曖昧」にしないための順序）。
    #[tokio::test]
    async fn resolves_home_member_without_consulting_guests() {
        let tenant: TenantId = Uuid::now_v7().into();
        let home = user(tenant);
        let repo = FakeUsers {
            home: LoginIdentifierMatch::Resolved(home.clone()),
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert_eq!(resolved_id(resolved), Some(home.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// 所属元が空振りなら、当該テナントの ACTIVE な GUEST として解決する。
    #[tokio::test]
    async fn falls_back_to_active_guest_of_the_requested_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let guest = user(Uuid::now_v7().into());
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(guest.clone()),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert_eq!(resolved_id(resolved), Some(guest.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 1);
    }

    /// **所属元で曖昧なら、そこで止める**（MT25 の本体）。ゲスト解決へ落ちると、同じ値を持つ
    /// ゲストが入れてしまい、「曖昧なら通さない」「所属元が名前の取り合いに勝つ」の両方が破れる。
    #[tokio::test]
    async fn ambiguous_home_identifier_does_not_fall_through_to_guests() {
        let tenant: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers {
            home: LoginIdentifierMatch::ambiguous(),
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// ゲスト側で曖昧だった場合も理由を保ったまま返す（同じ値を持つゲストが 2 人参加している
    /// 状態。どちらかを選ばず拒否する）。
    #[tokio::test]
    async fn ambiguous_guest_identifier_is_reported_as_ambiguous() {
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::ambiguous(),
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, Uuid::now_v7().into(), "member")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
    }

    /// どちらでも解決できなければ `NotFound`（呼び出し側は資格情報エラーに倒す）。
    #[tokio::test]
    async fn returns_not_found_when_neither_resolves() {
        let tenant: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers::default();
        let resolved = resolve_login_user(&repo, tenant, "member").await.unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
        ));
    }

    /// リポジトリ障害は握り潰さずそのまま伝える（`NotFound` に丸めると障害が「利用者不在」に
    /// 化け、ゲスト検索という余計な問い合わせまで走る）。
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
