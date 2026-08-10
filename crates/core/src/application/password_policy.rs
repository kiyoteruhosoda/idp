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

use crate::domain::clock::Clock;
use crate::domain::error::Result;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{
    BreachedPasswordChecker, NoBreachCheck, PasswordPolicy, PasswordRejection,
};
use crate::domain::repositories::PasswordHistoryRepository;
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
    policy: PasswordPolicy,
    history: Arc<dyn PasswordHistoryRepository>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
}

impl PasswordPolicyService {
    pub fn new(
        policy: PasswordPolicy,
        history: Arc<dyn PasswordHistoryRepository>,
        breach_checker: Arc<dyn BreachedPasswordChecker>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            policy,
            history,
            breach_checker,
            hasher,
            clock,
        }
    }

    /// 長さだけを見る構成（履歴・漏えい確認を持たない）。従来と同じ挙動で、テストの土台にも使う。
    pub fn length_only(hasher: Arc<dyn PasswordHasher>, clock: Arc<dyn Clock>) -> Self {
        Self::new(
            PasswordPolicy::default(),
            Arc::new(NoPasswordHistory),
            Arc::new(NoBreachCheck),
            hasher,
            clock,
        )
    }

    pub fn policy(&self) -> &PasswordPolicy {
        &self.policy
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
        user_id: Option<Uuid>,
        current_hash: Option<&str>,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        if let Err(rejection) = self.validate_input(new_password).await? {
            return Ok(Err(rejection));
        }
        self.validate_reuse(user_id, current_hash, new_password)
            .await
    }

    /// 利用者が誰かに依らない要件だけを見る（長さ・漏えい済み）。
    ///
    /// パスワードリセットのように、**利用者を解決する前**に入力の妥当性を見たい経路が使う
    /// （単回トークンを入力ミスで消費させないため）。解決後に
    /// [`Self::validate_reuse`] を続けて呼ぶ。
    pub async fn validate_input(
        &self,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        if let Err(rejection) = self.policy.validate_length(new_password) {
            return Ok(Err(rejection));
        }
        if self.policy.reject_breached && self.breach_checker.is_breached(new_password).await? {
            return Ok(Err(PasswordRejection::Breached));
        }
        Ok(Ok(()))
    }

    /// 現行・過去のパスワードの再利用だけを見る。
    pub async fn validate_reuse(
        &self,
        user_id: Option<Uuid>,
        current_hash: Option<&str>,
        new_password: &str,
    ) -> Result<std::result::Result<(), PasswordRejection>> {
        if !self.policy.checks_history() {
            return Ok(Ok(()));
        }
        if let Some(hash) = current_hash {
            if self.hasher.verify(new_password, hash)? {
                return Ok(Err(PasswordRejection::Reused));
            }
        }
        let retired_to_check = self.policy.retired_hashes_to_check();
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
    pub async fn record_change(&self, user_id: Uuid, retired_hash: &str) {
        if let Err(e) = self
            .history
            .push(
                user_id,
                retired_hash,
                self.clock.now(),
                self.policy.retained_history_len(),
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

    fn build(policy: PasswordPolicy, breached: bool) -> (PasswordPolicyService, Arc<FakeHistory>) {
        let history = Arc::new(FakeHistory::default());
        let breach_checker: Arc<dyn BreachedPasswordChecker> = if breached {
            Arc::new(AlwaysBreached)
        } else {
            Arc::new(NoBreachCheck)
        };
        let service = PasswordPolicyService::new(
            policy,
            history.clone(),
            breach_checker,
            Arc::new(EchoHasher),
            Arc::new(crate::infrastructure::clock::SystemClock),
        );
        (service, history)
    }

    #[tokio::test]
    async fn rejects_a_password_that_is_too_short() {
        let (service, _) = build(PasswordPolicy::default(), false);
        let result = service.validate(None, None, "short").await.unwrap();
        assert!(matches!(result, Err(PasswordRejection::Strength(_))));
    }

    #[tokio::test]
    async fn rejects_a_breached_password_only_when_the_policy_asks_for_it() {
        let off = PasswordPolicy::default();
        let (service, _) = build(off, true);
        assert!(service
            .validate(None, None, "correct horse battery")
            .await
            .unwrap()
            .is_ok());

        let on = PasswordPolicy {
            reject_breached: true,
            ..PasswordPolicy::default()
        };
        let (service, _) = build(on, true);
        assert_eq!(
            service
                .validate(None, None, "correct horse battery")
                .await
                .unwrap(),
            Err(PasswordRejection::Breached)
        );
    }

    #[tokio::test]
    async fn rejects_the_current_password_when_history_is_enabled() {
        let policy = PasswordPolicy {
            history_count: 1,
            ..PasswordPolicy::default()
        };
        let (service, _) = build(policy, false);
        assert_eq!(
            service
                .validate(None, Some("hashed:currentpassword"), "currentpassword")
                .await
                .unwrap(),
            Err(PasswordRejection::Reused)
        );
        assert!(service
            .validate(None, Some("hashed:currentpassword"), "anotherpassword")
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn history_count_one_does_not_look_at_retired_hashes() {
        let policy = PasswordPolicy {
            history_count: 1,
            ..PasswordPolicy::default()
        };
        let (service, history) = build(policy, false);
        let user_id = Uuid::now_v7();
        history
            .push(user_id, "hashed:oldpassword", Utc::now(), 4)
            .await
            .unwrap();
        assert!(service
            .validate(Some(user_id), Some("hashed:current"), "oldpassword")
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn rejects_a_retired_password_within_the_configured_depth() {
        let policy = PasswordPolicy {
            history_count: 3,
            ..PasswordPolicy::default()
        };
        let (service, history) = build(policy, false);
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
                .validate(Some(user_id), Some("hashed:current"), "retired1")
                .await
                .unwrap(),
            Err(PasswordRejection::Reused)
        );
        assert!(service
            .validate(Some(user_id), Some("hashed:current"), "neverused")
            .await
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn another_users_history_does_not_block_a_password() {
        let policy = PasswordPolicy {
            history_count: 3,
            ..PasswordPolicy::default()
        };
        let (service, history) = build(policy, false);
        let other = Uuid::now_v7();
        history
            .push(other, "hashed:sharedpassword", Utc::now(), 2)
            .await
            .unwrap();
        assert!(service
            .validate(
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
        let policy = PasswordPolicy {
            history_count: 3,
            ..PasswordPolicy::default()
        };
        let (service, history) = build(policy, false);
        let user_id = Uuid::now_v7();
        for old in ["p1", "p2", "p3", "p4"] {
            service
                .record_change(user_id, &format!("hashed:{old}"))
                .await;
        }
        // 深さ 3（現行 1 + 退役 2）なので、退役側に残るのは新しい 2 件だけ。
        let kept = history.recent(user_id, 10).await.unwrap();
        assert_eq!(kept, vec!["hashed:p4".to_string(), "hashed:p3".to_string()]);
    }
}
