//! Applying the password policy (AP7. User authentication & authentication policy spec §11.2).
//!
//! Decides "may this new password be accepted" and updates the history when it is. There are seven paths that set
//! a password (self-registration, forced change, forced change in the admin console, forced change in the portal,
//! self-service change, password reset, reissue by an admin), so writing the decision and recording in each path
//! makes **any one forgotten path a hole in the policy**. It is unified here and every path calls this service.
//!
//! # Order of checks
//!
//! 1. Length (synchronous, no inputs needed)
//! 2. Breached or not (external API; can be disabled in settings)
//! 3. Reuse of past passwords (argon2 comparison)
//!
//! Cheapest first. Check 3 runs argon2 once per history entry, so a memory-hard function isn't run
//! for obviously bad input such as being too short.
//!
//! # Whose tenant policy (ADR-0058)
//!
//! The policy is looked up from [`EffectiveTenantSettings`] every time. What is passed is **the user's home tenant**
//! ——the password is on the user row and only the home tenant manages it (ADR-0009 §2). Even if a guest changes
//! the password from the host tenant's screen, the home tenant's policy applies.

use crate::domain::clock::Clock;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::Result;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{BreachedPasswordChecker, PasswordPolicy, PasswordRejection};
use crate::domain::repositories::PasswordHistoryRepository;
use crate::domain::tenant::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// An implementation that keeps no history (used with `PASSWORD_HISTORY_COUNT=0` and by tests without history).
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
    settings: Arc<dyn EffectiveTenantSettings>,
    history: Arc<dyn PasswordHistoryRepository>,
    breach_checker: Arc<dyn BreachedPasswordChecker>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
}

impl PasswordPolicyService {
    pub fn new(
        settings: Arc<dyn EffectiveTenantSettings>,
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

    /// A configuration without history or breach checks (a base for testing other services). Values such as length come from `settings`.
    #[cfg(test)]
    pub fn without_history(
        settings: Arc<dyn EffectiveTenantSettings>,
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

    /// The tenant's password policy (used by paths that need the values outside validation, e.g. expiry checks).
    /// `tenant_id` is the user's **home tenant**.
    pub async fn policy(&self, tenant_id: TenantId) -> Result<PasswordPolicy> {
        self.settings.password_policy(tenant_id).await
    }

    /// Validates a new password.
    ///
    /// `current_hash` is the current password's hash used for the reuse check (`None` on paths with no current
    /// password, like self-registration). When `user_id` is `None`, history is not looked up (same).
    ///
    /// Returns `Err` if fetching the inputs fails (DB error). **This is not fail-open**:
    /// the history is in our own DB, and being unable to read it is a fault of the IdP itself, unlike an external service outage
    /// (better to fail the change and surface the fault than silently allow reuse).
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

    /// Checks only the requirements that don't depend on who the user is (length, breached).
    ///
    /// Used by paths like password reset that want to validate input **before resolving the user**
    /// (so a single-use token isn't consumed by a typo). After resolving, call
    /// [`Self::validate_reuse`] next.
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

    /// Checks only reuse of current and past passwords.
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

    /// Records a password replacement in the history (call **after saving succeeded**).
    ///
    /// `retired_hash` is the replaced (= previous) hash. With settings that don't look at history,
    /// the number to keep is 0, so the inserted row is pruned on the spot.
    ///
    /// Even if recording the history fails, the password change itself has succeeded. Returning an error here to tell
    /// the caller it failed would mean "it changed but shows as failed", so it logs a warning and swallows it.
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

    /// A tenant that follows the global value unless a row is inserted.
    fn home() -> TenantId {
        Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0001).into()
    }
    use crate::domain::error::DomainError;
    use std::sync::Mutex;

    /// A test implementation treating the plaintext as the "hash" as-is (only checks which comparison is called).
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
            // Count this user's rows oldest first and drop the leading (older) ones beyond `retain`.
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

    /// Builds with a resolver whose global values are `values`. Unspecified keys start from no history
    /// (same as `PasswordPolicy::default()`).
    fn build(values: &[(&str, &str)], breached: bool) -> (PasswordPolicyService, Arc<FakeHistory>) {
        let fixture = tenant_settings();
        fixture.set_global("PASSWORD_HISTORY_COUNT", "0");
        for (key, value) in values {
            fixture.set_global(key, value);
        }
        build_with(fixture.service, breached)
    }

    fn build_with(
        settings: Arc<dyn EffectiveTenantSettings>,
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
        // Newest first: retired2, retired1 (history depth is 3 - 1 current = 2 entries).
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
        // Depth 3 (1 current + 2 retired), so only the 2 newest remain on the retired side.
        let kept = history.recent(user_id, 10).await.unwrap();
        assert_eq!(kept, vec!["hashed:p4".to_string(), "hashed:p3".to_string()]);
    }

    /// ⚠ Put different values in 2 tenants (with only 1 tenant, it would pass even when reading the global value).
    /// A tenant without a row follows the global value.
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

        // 12 chars: too short for strict; passes for lenient and for the tenant following the global value (10).
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
        // 8 chars: only lenient passes (the tenant following the global value rejects anything under 10).
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

    /// History depth is also per tenant. Pruning and comparison run with the same tenant's value.
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
