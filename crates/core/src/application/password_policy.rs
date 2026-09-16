//! パスワードポリシーの適用（AP7。ユーザー認証・認証ポリシー仕様書 §11.2）。
//!
//! 「新しいパスワードを受け付けてよいか」を判定し、受け付けたときに履歴を更新する。パスワードを
//! 設定する経路は 7 つある（自己登録・強制変更・管理コンソールの強制変更・ポータルの強制変更・
//! セルフサービス変更・パスワードリセット・管理者による再発行）ので、判定と記録を各経路に書くと
//! **一つ書き忘れた経路がポリシーの抜け穴**になる。ここに 1 本化して各経路はこのサービスを呼ぶ。
//!
//! # 判定の順序
//!
//! 1. 長さ（同期・材料不要）
//! 2. 漏えい済みか（外部 API。設定で無効化可）
//! 3. 過去パスワードの再利用（argon2 照合）
//!
//! 安いものから順に見る。3 の照合は履歴の件数だけ argon2 を回すため、長さ不足のような
//! 明らかな入力でメモリハード関数を走らせない。
//!
//! # どのテナントのポリシーか（ADR-0058）
//!
//! ポリシーは参照のたびに [`TenantSettingsService`] から引く。渡すのは**利用者の所属元テナント**
//! である ——パスワードは利用者の行にあり、所属元だけが管理する（ADR-0009 §2）。ゲストが参加先の
//! 画面からパスワードを変えても、効くのは所属元のポリシーである。

use crate::application::tenant_settings::TenantSettingsService;
use crate::domain::clock::Clock;
use crate::domain::error::Result;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{BreachedPasswordChecker, PasswordPolicy, PasswordRejection};
use crate::domain::repositories::PasswordHistoryRepository;
use crate::domain::tenant::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 履歴を保持しない実装（`PASSWORD_HISTORY_COUNT=0` の構成と、履歴を持たないテストで使う）。
pub struct NoPasswordHistory;

#[async_trait]
impl PasswordHistoryRepository for NoPasswordHistory {
    async fn push(
        &self,
        _user_id: Uuid,
        _password_hash: &str,
        _retired_at: DateTime<Utc>,
        _retain: u32,
    ) -> Result<()> {
        Ok(())
    }

    async fn recent(&self, _user_id: Uuid, _limit: u32) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}

pub struct PasswordPolicyService {
    settings: Arc<TenantSettingsService>,
    history: Arc<dyn PasswordHistoryRepository>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
}

impl PasswordPolicyService {
    pub fn new(
        settings: Arc<TenantSettingsService>,
        history: Arc<dyn PasswordHistoryRepository>,
        breach_checker: Arc<dyn BreachedPasswordChecker>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            settings,
            history,
            breach_checker,
            hasher,
            clock,
        }
    }

    /// 履歴・漏えい確認を持たない構成（他のサービスの試験の土台）。長さなどの値は `settings` から引く。
    #[cfg(test)]
    pub fn without_history(
        settings: Arc<TenantSettingsService>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::new(
            settings,
            Arc::new(NoPasswordHistory),
            Arc::new(crate::domain::password_policy::NoBreachCheck),
            hasher,
            clock,
        )
    }

    /// テナントのパスワードポリシー（有効期限の判定など、検証以外で値が要る経路が使う）。
    /// `tenant_id` は利用者の**所属元**。
    pub async fn policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy> {
        self.settings.password_policy(tenant_id).await
    }

    /// 新しいパスワードを検証する。
    ///
    /// `current_hash` は再利用判定に使う現行パスワードのハッシュ（自己登録のように現行が存在
    /// しない経路では `None`）。`user_id` が `None` のときは履歴を引かない（同上）。
    ///
    /// 判定材料の取得に失敗した場合（DB エラー）は `Err` を返す。**ここは fail-open にしない**:
    /// 履歴は自前の DB にあり、読めない状態は外部サービスの不調と違って IdP 自身の異常だからである
    /// （黙って再利用を通すより、変更を失敗させて異常を見せる）。
    pub async fn validate(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        current_hash: Option<&str>,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        let policy = self.policy(tenant_id).await?;
        if let Err(rejection) = self.check_input(&policy, new_password).await? {
            return Ok(Err(rejection));
        }
        self.check_reuse(&policy, user_id, current_hash, new_password)
            .await
    }

    /// 利用者が誰かに依らない要件だけを見る（長さ・漏えい済み）。
    ///
    /// パスワードリセットのように、**利用者を解決する前**に入力の妥当性を見たい経路が使う
    /// （単回トークンを入力ミスで消費させないため）。解決後に
    /// [`Self::validate_reuse`] を続けて呼ぶ。
    pub async fn validate_input(
        &self,
        tenant_id: TenantId,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        let policy = self.policy(tenant_id).await?;
        self.check_input(&policy, new_password).await
    }

    async fn check_input(
        &self,
        policy: &PasswordPolicy,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        if let Err(rejection) = policy.validate_length(new_password) {
            return Ok(Err(rejection));
        }
        if policy.reject_breached && self.breach_checker.is_breached(new_password).await? {
            return Ok(Err(PasswordRejection::Breached));
        }
        Ok(Ok(()))
    }

    /// 現行・過去のパスワードの再利用だけを見る。
    pub async fn validate_reuse(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        current_hash: Option<&str>,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        let policy = self.policy(tenant_id).await?;
        self.check_reuse(&policy, user_id, current_hash, new_password)
            .await
    }

    async fn check_reuse(
        &self,
        policy: &PasswordPolicy,
        user_id: Option<Uuid>,
        current_hash: Option<&str>,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        if !policy.checks_history() {
            return Ok(Ok(()));
        }
        if let Some(hash) = current_hash {
            if self.hasher.verify(new_password, hash)? {
                return Ok(Err(PasswordRejection::Reused));
            }
        }
        let retired_to_check = policy.retired_hashes_to_check();
        if retired_to_check > 0 {
            if let Some(user_id) = user_id {
                for hash in self.history.recent(user_id, retired_to_check).await? {
                    if self.hasher.verify(new_password, &hash)? {
                        return Ok(Err(PasswordRejection::Reused));
                    }
                }
            }
        }
        Ok(Ok(()))
    }

    /// パスワードの置き換えを履歴へ記録する（**保存が成功した後**に呼ぶ）。
    ///
    /// `retired_hash` は置き換えられた（＝これまでの）ハッシュ。履歴を見ない設定では、
    /// 残す件数が 0 になるので積んだ行はその場で剪定される。
    ///
    /// 履歴の記録に失敗してもパスワード変更自体は成立している。ここでエラーを返して呼び出し側に
    /// 失敗を伝えると「変わったのに失敗と表示される」ことになるため、警告を残して握る。
    pub async fn record_change(&self, tenant_id: TenantId, user_id: Uuid, retired_hash: &str) {
        let policy = match self.policy(tenant_id).await {
            Ok(policy) => policy,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to resolve the password policy; password history was not recorded"
                );
                return;
            }
        };
        if let Err(e) = self
            .history
            .push(
                user_id,
                retired_hash,
                self.clock.now(),
                policy.retained_history_len(),
            )
            .await
        {
            tracing::warn!(error = %e, "failed to record password history");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::tenant_settings::testing::tenant_settings;
    use crate::domain::password_policy::NoBreachCheck;

    /// 行を入れない限り全体に従うテナント。
    fn home() -> TenantId {
        Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0001).into()
    }
    use crate::domain::error::DomainError;
    use std::sync::Mutex;

    /// 平文をそのまま「ハッシュ」として扱う検証用実装（照合の呼び分けだけを見る）。
    struct EchoHasher;

    impl PasswordHasher for EchoHasher {
        fn hash(&self, password: &str) -> std::result::Result<String, DomainError> {
            Ok(format!("hashed:{password}"))
        }

        fn verify(&self, password: &str, hash: &str) -> std::result::Result<bool, DomainError> {
            Ok(hash == format!("hashed:{password}"))
        }
    }

    #[derive(Default)]
    struct FakeHistory {
        rows: Mutex<Vec<(Uuid, String)>>,
    }

    #[async_trait]
    impl PasswordHistoryRepository for FakeHistory {
        async fn push(
            &self,
            user_id: Uuid,
            password_hash: &str,
            _retired_at: DateTime<Utc>,
            retain: u32,
        ) -> Result<()> {
            let mut rows = self.rows.lock().unwrap();
            rows.push((user_id, password_hash.to_string()));
            // 当該利用者の行を古い順に数え、`retain` 件を超える先頭側（古い側）を落とす。
            let mut excess = rows
                .iter()
                .filter(|(u, _)| *u == user_id)
                .count()
                .saturating_sub(retain as usize);
            rows.retain(|(u, _)| {
                if *u == user_id && excess > 0 {
                    excess -= 1;
                    return false;
                }
                true
            });
            Ok(())
        }

        async fn recent(&self, user_id: Uuid, limit: u32) -> Result<Vec<String>> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .rev()
                .filter(|(u, _)| *u == user_id)
                .map(|(_, h)| h.clone())
                .take(limit as usize)
                .collect())
        }
    }

    struct AlwaysBreached;

    #[async_trait]
    impl BreachedPasswordChecker for AlwaysBreached {
        async fn is_breached(&self, _password: &str) -> Result<bool> {
            Ok(true)
        }
    }

    /// 全体の値を `values` にした解決器で組む。指定の無いキーは履歴なし（`PasswordPolicy::default()`
    /// と同じ）から始める。
    fn build(values: &[(&str, &str)], breached: bool) -> (PasswordPolicyService, Arc<FakeHistory>) {
        let fixture = tenant_settings();
        fixture.set_global("PASSWORD_HISTORY_COUNT", "0");
        for (key, value) in values {
            fixture.set_global(key, value);
        }
        build_with(fixture.service, breached)
    }

    fn build_with(
        settings: Arc<TenantSettingsService>,
        breached: bool,
    ) -> (PasswordPolicyService, Arc<FakeHistory>) {
        let history = Arc::new(FakeHistory::default());
        let breach_checker: Arc<dyn BreachedPasswordChecker> = if breached {
            Arc::new(AlwaysBreached)
        } else {
            Arc::new(NoBreachCheck)
        };
        let service = PasswordPolicyService::new(
            settings,
            history.clone(),
            breach_checker,
            Arc::new(EchoHasher),
            Arc::new(crate::infrastructure::clock::SystemClock),
        );
        (service, history)
    }

    #[tokio::test]
    async fn rejects_a_password_that_is_too_short() {
        let (service, _) = build(&[], false);
        let result = service.validate(home(), None, None, "short").await.unwrap();
        assert!(matches!(result, Err(PasswordRejection::Strength(_))));
    }

    #[tokio::test]
    async fn rejects_a_breached_password_only_when_the_policy_asks_for_it() {
        let (service, _) = build(&[], true);
        assert!(service
            .validate(home(), None, None, "correct horse battery")
            .await
            .unwrap()
            .is_ok());

        let (service, _) = build(&[("PASSWORD_BREACH_CHECK_ENABLED", "true")], true);
        assert_eq!(
            service
                .validate(home(), None, None, "correct horse battery")
                .await
                .unwrap(),
            Err(PasswordRejection::Breached)
        );
    }

    #[tokio::test]
    async fn rejects_the_current_password_when_history_is_enabled() {
        let (service, _) = build(&[("PASSWORD_HISTORY_COUNT", "1")], false);
        assert_eq!(
            service
                .validate(
                    home(),
                    None,
                    Some("hashed:currentpassword"),
                    "currentpassword"
                )
                .await
                .unwrap(),
            Err(PasswordRejection::Reused)
        );
        assert!(service
            .validate(
                home(),
                None,
                Some("hashed:currentpassword"),
                "anotherpassword"
            )
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn history_count_one_does_not_look_at_retired_hashes() {
        let (service, history) = build(&[("PASSWORD_HISTORY_COUNT", "1")], false);
        let user_id = Uuid::now_v7();
        history
            .push(user_id, "hashed:oldpassword", Utc::now(), 4)
            .await
            .unwrap();
        assert!(service
            .validate(home(), Some(user_id), Some("hashed:current"), "oldpassword")
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn rejects_a_retired_password_within_the_configured_depth() {
        let (service, history) = build(&[("PASSWORD_HISTORY_COUNT", "3")], false);
        let user_id = Uuid::now_v7();
        // 新しい順に retired2, retired1（履歴の深さは 3 - 現行 1 = 2 件）。
        history
            .push(user_id, "hashed:retired1", Utc::now(), 2)
            .await
            .unwrap();
        history
            .push(user_id, "hashed:retired2", Utc::now(), 2)
            .await
            .unwrap();

        assert_eq!(
            service
                .validate(home(), Some(user_id), Some("hashed:current"), "retired1")
                .await
                .unwrap(),
            Err(PasswordRejection::Reused)
        );
        assert!(service
            .validate(home(), Some(user_id), Some("hashed:current"), "neverused")
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn another_users_history_does_not_block_a_password() {
        let (service, history) = build(&[("PASSWORD_HISTORY_COUNT", "3")], false);
        let other = Uuid::now_v7();
        history
            .push(other, "hashed:sharedpassword", Utc::now(), 2)
            .await
            .unwrap();
        assert!(service
            .validate(
                home(),
                Some(Uuid::now_v7()),
                Some("hashed:current"),
                "sharedpassword"
            )
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn record_change_prunes_to_the_configured_depth() {
        let (service, history) = build(&[("PASSWORD_HISTORY_COUNT", "3")], false);
        let user_id = Uuid::now_v7();
        for old in ["p1", "p2", "p3", "p4"] {
            service
                .record_change(home(), user_id, &format!("hashed:{old}"))
                .await;
        }
        // 深さ 3（現行 1 + 退役 2）なので、退役側に残るのは新しい 2 件だけ。
        let kept = history.recent(user_id, 10).await.unwrap();
        assert_eq!(kept, vec!["hashed:p4".to_string(), "hashed:p3".to_string()]);
    }

    /// ⚠ 2 テナントで違う値を入れる（1 テナントだけだと、全体の値を読んでいても通ってしまう）。
    /// 行の無いテナントは全体に従う。
    #[tokio::test]
    async fn each_tenant_is_judged_by_its_own_policy() {
        let fixture = tenant_settings();
        let strict = TenantId::from(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_00a1));
        let lenient = TenantId::from(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_00a2));
        let follower = TenantId::from(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_00a3));
        fixture.set_global("PASSWORD_MIN_LENGTH", "10");
        fixture.set_tenant(strict, "PASSWORD_MIN_LENGTH", "16");
        fixture.set_tenant(lenient, "PASSWORD_MIN_LENGTH", "6");
        let (service, _) = build_with(fixture.service.clone(), false);

        // 12 文字: strict は短すぎ、lenient と全体（10）に従うテナントは通る。
        let password = "abcdefghijkl";
        assert!(matches!(
            service.validate_input(strict, password).await.unwrap(),
            Err(PasswordRejection::Strength(_))
        ));
        assert!(service
            .validate_input(lenient, password)
            .await
            .unwrap()
            .is_ok());
        assert!(service
            .validate_input(follower, password)
            .await
            .unwrap()
            .is_ok());
        // 8 文字: lenient だけが通る（全体に従うテナントは 10 未満で弾かれる）。
        let short = "abcdefgh";
        assert!(service
            .validate_input(lenient, short)
            .await
            .unwrap()
            .is_ok());
        assert!(matches!(
            service.validate_input(follower, short).await.unwrap(),
            Err(PasswordRejection::Strength(_))
        ));
    }

    /// 履歴の深さもテナントごと。記録の剪定と照合が同じテナントの値で動く。
    #[tokio::test]
    async fn history_depth_follows_the_users_home_tenant() {
        let fixture = tenant_settings();
        let keeps_history =
            TenantId::from(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_00b1));
        let no_history = TenantId::from(Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_00b2));
        fixture.set_tenant(keeps_history, "PASSWORD_HISTORY_COUNT", "3");
        fixture.set_tenant(no_history, "PASSWORD_HISTORY_COUNT", "0");
        let (service, _) = build_with(fixture.service.clone(), false);

        assert_eq!(
            service
                .validate(
                    keeps_history,
                    None,
                    Some("hashed:currentpassword"),
                    "currentpassword"
                )
                .await
                .unwrap(),
            Err(PasswordRejection::Reused)
        );
        assert!(service
            .validate(
                no_history,
                None,
                Some("hashed:currentpassword"),
                "currentpassword"
            )
            .await
            .unwrap()
            .is_ok());
    }
}
