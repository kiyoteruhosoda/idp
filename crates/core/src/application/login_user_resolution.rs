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
//! # 解決の順序（所属元 → ドメインで決まった所属元 → 参加先のゲスト）
//!
//! 1. 要求テナントの登録簿（[`UserRepository::find_by_login_identifier`]）。
//! 2. 空振りで、入力が `local@domain` の形をしていてそのドメインが 1 つのテナントに割り当てられて
//!    いるなら、**そのテナントの登録簿だけ**を引く（ADR-0029 の home realm discovery。
//!    [`UserRepository::find_member_by_login_identifier`]）。
//! 3. なお空振りなら、要求テナントに ACTIVE な GUEST メンバーシップを持つ利用者を、その利用者の
//!    所属元テナントの登録簿で解決する
//!    （[`UserRepository::find_active_guest_by_login_identifier`]）。**所属元テナントが `DISABLED`
//!    なら解決しない** —— 所属元の無効化はその組織の利用者を止める操作であって、参加先テナント
//!    経由の裏口を残す意味ではない（ADR-0009 §8。同じ規則をメンバーシップ側から見たものが
//!    [`crate::domain::repositories::TenantMembershipRepository::is_active_member`] で、パスキー
//!    認証・SSO 復元・管理コンソールのアクセス判定はそちらを通る）。
//!
//! **順序に意味がある。** 1 と 3 をまとめて 1 回で引くと、同じユーザー名のゲストが参加してきた
//! だけで「曖昧な入力」になり、そのテナントの HOME 利用者まで締め出される。所属元を先に決めれば、
//! 参加先で名前が衝突しても割を食うのはゲスト側だけで済む（ゲストは所属元テナントの画面から
//! 従来どおり入れる）。
//!
//! 2 が 3 より先なのは、ドメイン修飾された入力が「どの組織の誰か」まで言い切っているためである。
//! 言い切っていない入力（裸のユーザー名）のための走査より precise で、しかも**曖昧さが原理的に
//! 起きない**（引くのは 1 テナントの登録簿だけで、その中では 1 正規化値が 1 人のもの）。
//! 3 を残すのは、裸のユーザー名と未割り当てのドメイン（`gmail.com` 等）が 2 に掛からないためで、
//! 落とすとゲストの多くが参加先の画面から入れなくなる。**2 は加算であって置き換えではない。**
//!
//! # 曖昧な入力はそこで止める（MT25）
//!
//! 1 が**曖昧**（複数人に当たった）だったときに 2 へ進んではいけない。ここは以前
//! `Option<User>` を返しており、「不在」と「曖昧」がどちらも `None` に潰れていたため、所属元で
//! 曖昧だった入力がそのままゲスト解決へ落ちていた。なりすましは起きない（ゲストは自分の
//! パスワードで自分として入る）が、「曖昧なら通さない」「所属元がテナント内の名前の取り合いに
//! 勝つ」という 2 つの決めごとが、まさにそれが要る場面で破れていた。
//!
//! [`LoginIdentifierMatch`] が 2 つを型で分けるので、`Unresolved(NotFound)` のときだけ次の段へ進む。
//! これは 2 段目（ドメイン経路）についても同じで、決まった所属元テナントの中で曖昧なら走査へは
//! 落とさない。
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
use crate::domain::repositories::{TenantDomainRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_domain::split_qualified_identifier;

/// 次の段へ進んでよいか（＝「不在」だったか）。解決できた場合も曖昧だった場合も、そこで打ち切る。
fn should_continue(m: &LoginIdentifierMatch) -> bool {
    matches!(
        m,
        LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
    )
}

/// ログイン欄の入力から、`tenant_id` で認証してよい利用者を解決する。
///
/// 解決できなかったときの応答は呼び出し側で一律に資格情報エラーへ倒すが（不存在を露呈させない）、
/// 理由は [`UnresolvedReason`] として返す —— 監査に残す値が違う。
pub async fn resolve_login_user(
    users: &dyn UserRepository,
    tenant_domains: &dyn TenantDomainRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<LoginIdentifierMatch> {
    // 1. 要求テナントの登録簿。
    let found = users.find_by_login_identifier(tenant_id, input).await?;
    if !should_continue(&found) {
        return Ok(found);
    }

    // 2. ドメインで所属元テナントが決まるなら、そのテナントだけを引く。
    if let Some(found) = resolve_by_domain(users, tenant_domains, tenant_id, input).await? {
        return Ok(found);
    }

    // 3. 参加中のゲストを横断走査する。
    users
        .find_active_guest_by_login_identifier(tenant_id, input)
        .await
}

/// ドメインから所属元テナントを決めて解決する（ADR-0029）。掛からなければ `None` を返し、
/// 呼び出し側は次の段へ進む。
///
/// 決まったテナントの中を **2 通りの読み方**で引く。順序に意味がある:
///
/// 1. **入力そのまま**（`alice@corp.example`）。メール種別の識別子を明示的に登録している利用者に
///    当たる。
/// 2. **ローカル部**（`alice`）。UPN 形式の解釈で、ドメインを割り当てたこと自体が
///    「`<識別子>@corp.example` はこのテナントの利用者を指す」という宣言にあたる。
///
/// 1 を先に引くのは、メール種別の識別子を持っている利用者を UPN 解釈で**別人へ振り替えない**
/// ため。テナントの中で `alice@corp.example` を持つ人と `alice` を持つ人は別人であり得る。
///
/// ただし**所属元が要求テナント自身**（ADR-0029 §4）のときは 1 を省く。この段へ来た時点で
/// 1 段目（同じ登録簿を、メンバーシップ条件無しで引く＝ここより広い範囲）が入力そのままで
/// 空振りしているので、同じ問い合わせは必ず空振りする。ホットパスに無駄な往復を足さない。
///
/// 2 は「メールでのログインはテナントが明示的に有効化したときだけ」（ADR-0025 §5）と矛盾しない。
/// `alice@corp.example` はそのアドレスにメールが届くことを意味せず、`users.email` も引かない。
/// 引くのは登録簿だけで、増えるのは principal ではなく**綴り方**である（パスワードは従来どおり要る）。
async fn resolve_by_domain(
    users: &dyn UserRepository,
    tenant_domains: &dyn TenantDomainRepository,
    tenant_id: TenantId,
    input: &str,
) -> Result<Option<LoginIdentifierMatch>> {
    // 形が合わない入力では DB を引きすらしない（裸のユーザー名がホットパスを増やさない）。
    let Some((local_part, domain)) = split_qualified_identifier(input) else {
        return Ok(None);
    };
    let Some(home_tenant_id) = tenant_domains.find_tenant_by_domain(&domain).await? else {
        return Ok(None);
    };

    // 上の doc コメント参照。所属元＝要求テナントなら入力そのままは引き直さない。
    let candidates: &[&str] = if home_tenant_id == tenant_id {
        &[local_part]
    } else {
        &[input, local_part]
    };
    for candidate in candidates.iter().copied() {
        let found = users
            .find_member_by_login_identifier(tenant_id, home_tenant_id, candidate)
            .await?;
        if !should_continue(&found) {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use crate::domain::repositories::TenantDomainRepository;
    use crate::domain::user::LoginFailureRecord;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
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
    ///
    /// `by_home_tenant` はドメイン経路（ADR-0029）用で、「所属元テナントを固定して引いた入力 →
    /// 結果」の対応表。入力そのままとローカル部の 2 通りで引かれることを、この表で観測できる。
    struct FakeUsers {
        home: LoginIdentifierMatch,
        guest: LoginIdentifierMatch,
        by_home_tenant: Vec<(String, LoginIdentifierMatch)>,
        home_fails: bool,
        guest_calls: AtomicUsize,
        member_lookups: Mutex<Vec<String>>,
    }

    impl Default for FakeUsers {
        fn default() -> Self {
            Self {
                home: LoginIdentifierMatch::not_found(),
                guest: LoginIdentifierMatch::not_found(),
                by_home_tenant: Vec::new(),
                home_fails: false,
                guest_calls: AtomicUsize::new(0),
                member_lookups: Mutex::new(Vec::new()),
            }
        }
    }

    /// ドメインを 1 つだけ割り当てているフェイク。
    struct FakeDomains {
        domain: String,
        tenant_id: TenantId,
    }

    #[async_trait]
    impl TenantDomainRepository for FakeDomains {
        async fn find_tenant_by_domain(&self, domain: &str) -> Result<Option<TenantId>> {
            Ok((domain == self.domain).then_some(self.tenant_id))
        }
    }

    /// ドメインを 1 つも割り当てていないフェイク（既定実装のまま）。
    struct NoDomains;

    #[async_trait]
    impl TenantDomainRepository for NoDomains {}

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
        async fn find_member_by_login_identifier(
            &self,
            _tenant_id: TenantId,
            _home_tenant_id: TenantId,
            input: &str,
        ) -> Result<LoginIdentifierMatch> {
            self.member_lookups.lock().unwrap().push(input.to_string());
            Ok(self
                .by_home_tenant
                .iter()
                .find(|(key, _)| key == input)
                .map(|(_, m)| m.clone())
                .unwrap_or_else(LoginIdentifierMatch::not_found))
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

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
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

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
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

        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
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

        let resolved = resolve_login_user(&repo, &NoDomains, Uuid::now_v7().into(), "member")
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
        let resolved = resolve_login_user(&repo, &NoDomains, tenant, "member")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
        ));
    }

    // ── ドメイン経路（ADR-0029）─────────────────────────────────────────────

    fn domains(tenant_id: TenantId) -> FakeDomains {
        FakeDomains {
            domain: "corp.example".to_string(),
            tenant_id,
        }
    }

    /// ドメイン修飾された入力は、**ゲストの横断走査を通らずに**解決される（本 ADR の主眼）。
    /// 走査を通らないので、同名のゲストが何人参加していても互いに干渉しない。
    #[tokio::test]
    async fn a_domain_qualified_identifier_resolves_without_scanning_guests() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let member = user(home);
        let repo = FakeUsers {
            // 走査側には別人が居る。ドメイン経路が先に決めるので、こちらは参照されない。
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// 決まったテナントの中は「入力そのまま → ローカル部」の順で引く。メール種別の識別子を
    /// 明示的に登録している利用者を、UPN 解釈で別人へ振り替えないための順序。
    #[tokio::test]
    async fn the_full_input_wins_over_the_local_part() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let by_email = user(home);
        let by_username = user(home);
        let repo = FakeUsers {
            by_home_tenant: vec![
                (
                    "alice@corp.example".to_string(),
                    LoginIdentifierMatch::Resolved(by_email.clone()),
                ),
                (
                    "alice".to_string(),
                    LoginIdentifierMatch::Resolved(by_username.clone()),
                ),
            ],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(by_email.id));
        // ローカル部までは引きに行かない。
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice@corp.example".to_string()]
        );
    }

    /// 入力そのままが空振りならローカル部で引く（UPN 形式。`alice@corp.example` → `alice`）。
    #[tokio::test]
    async fn falls_back_to_the_local_part_as_a_upn() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let member = user(home);
        let repo = FakeUsers {
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice@corp.example".to_string(), "alice".to_string()]
        );
    }

    /// 割り当てられていないドメイン（`gmail.com` 等）は経路に掛からず、従来の走査へ落ちる。
    /// **ドメイン経路は加算であって置き換えではない。**
    #[tokio::test]
    async fn an_unassigned_domain_falls_through_to_the_guest_scan() {
        let host: TenantId = Uuid::now_v7().into();
        let guest = user(Uuid::now_v7().into());
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(guest.clone()),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@other.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(guest.id));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 1);
        assert!(repo.member_lookups.lock().unwrap().is_empty());
    }

    /// 裸のユーザー名ではドメインを引きすらしない（認証のホットパスを増やさない）。
    #[tokio::test]
    async fn a_bare_identifier_never_consults_the_domain_registry() {
        let host: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers::default();
        struct ExplodingDomains;
        #[async_trait]
        impl TenantDomainRepository for ExplodingDomains {
            async fn find_tenant_by_domain(&self, _domain: &str) -> Result<Option<TenantId>> {
                panic!("裸の入力でドメインを引いてはいけない");
            }
        }

        let resolved = resolve_login_user(&repo, &ExplodingDomains, host, "alice")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::NotFound)
        ));
    }

    /// 決まったテナントの中で曖昧なら、そこで打ち切る（走査へ落とさない。MT25 と同じ規則）。
    #[tokio::test]
    async fn an_ambiguous_result_in_the_resolved_home_tenant_stops_the_chain() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let repo = FakeUsers {
            guest: LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            by_home_tenant: vec![(
                "alice@corp.example".to_string(),
                LoginIdentifierMatch::ambiguous(),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(home), host, "alice@corp.example")
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            LoginIdentifierMatch::Unresolved(UnresolvedReason::Ambiguous)
        ));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// 要求テナントの登録簿で解決できるなら、ドメイン経路は走らない（段の順序）。
    #[tokio::test]
    async fn the_requested_tenants_registry_still_wins() {
        let host: TenantId = Uuid::now_v7().into();
        let home_user = user(host);
        let repo = FakeUsers {
            home: LoginIdentifierMatch::Resolved(home_user.clone()),
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(user(Uuid::now_v7().into())),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(home_user.id));
        assert!(repo.member_lookups.lock().unwrap().is_empty());
    }

    /// 要求テナント自身がドメインを持つ場合（ADR-0029 §4）。`alice@x.example` は 1 段目で
    /// 空振りしたあと、ローカル部の解釈で拾われる。**入力そのままは引き直さない** —— 1 段目が
    /// 同じ登録簿をより広い条件で引いて空振りしている以上、必ず空振りするためである。
    #[tokio::test]
    async fn the_requesting_tenants_own_domain_only_looks_up_the_local_part() {
        let host: TenantId = Uuid::now_v7().into();
        let member = user(host);
        let repo = FakeUsers {
            by_home_tenant: vec![(
                "alice".to_string(),
                LoginIdentifierMatch::Resolved(member.clone()),
            )],
            ..FakeUsers::default()
        };

        let resolved = resolve_login_user(&repo, &domains(host), host, "alice@corp.example")
            .await
            .unwrap();
        assert_eq!(resolved_id(resolved), Some(member.id));
        assert_eq!(
            *repo.member_lookups.lock().unwrap(),
            vec!["alice".to_string()]
        );
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }

    /// リポジトリ障害は握り潰さずそのまま伝える（`NotFound` に丸めると障害が「利用者不在」に
    /// 化け、ゲスト検索という余計な問い合わせまで走る）。
    #[tokio::test]
    async fn propagates_repository_errors_without_falling_back() {
        let repo = FakeUsers {
            home_fails: true,
            ..FakeUsers::default()
        };
        let err = resolve_login_user(&repo, &NoDomains, Uuid::now_v7().into(), "member")
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Repository(_)));
        assert_eq!(repo.guest_calls.load(Ordering::SeqCst), 0);
    }
}
