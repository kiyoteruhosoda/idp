//! ユーザー登録ユースケース（設計仕様 §4.1）。
//!
//! MVP ではメール検証フロー対象外のため、登録時 `status = ACTIVE` / `email_verified = false`。
//! ユーザーは処理対象テナントを所属元（ホーム）として作成し、HOME メンバーシップを同時に
//! 生成する（ADR-0009 §2・§3）。
//!
//! 自己登録は**テナント設定 `self_registration_enabled` が有効なテナントでのみ**受け付ける
//! （既定は無効 = fail-closed。SEC6）。あわせて IP 単位のレート制限を掛け、409（メール重複）に
//! よるテナント内メールアドレスの列挙を試行回数の面から抑える（完全な秘匿はメール検証フローの
//! 導入まで行わない。無効テナントでは存在確認自体ができない）。

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{TenantMembershipRepository, TenantRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RegisterCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub password: String,
    pub name: Option<String>,
}

pub struct RegisteredUser {
    pub sub: Uuid,
    pub status: UserStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("validation error: {0}")]
    Validation(String),
    /// 当該テナントで自己登録が無効（SEC6。既定）。
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// IP 単位のレート制限超過（SEC6）。
    #[error("too many registration attempts")]
    RateLimited,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct RegisterService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    tenants: Arc<dyn TenantRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl RegisterService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        tenants: Arc<dyn TenantRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            tenants,
            hasher,
            rate_limiter,
            clock,
            ids,
        }
    }

    /// `ip_address` はレート制限のキー（取得できない場合も共通バケツで制限する）。
    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterCommand,
        ip_address: Option<&str>,
    ) -> Result<RegisteredUser, RegisterError> {
        // IP 単位のレート制限（SEC6）。検証より先に判定し、列挙・大量作成の試行回数を抑える。
        if !self
            .rate_limiter
            .check_and_record(ip_address.unwrap_or("unknown"), self.clock.now())
        {
            return Err(RegisterError::RateLimited);
        }

        // テナント設定で自己登録が有効であること（既定は無効 = fail-closed。SEC6）。
        // ResolvedTenant のキャッシュではなくリポジトリから読む（設定変更を即時反映する）。
        let self_registration_enabled = self
            .tenants
            .find_by_id(tenant.tenant_id())
            .await
            .map_err(internal)?
            .map(|t| t.self_registration_enabled)
            .unwrap_or(false);
        if !self_registration_enabled {
            return Err(RegisterError::Forbidden(
                "self-registration is disabled for this tenant".to_string(),
            ));
        }

        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        validate_password(&cmd.password)?;
        let preferred_username = normalize_optional(cmd.preferred_username);
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // 一意性の事前チェック（利用者向けの分かりやすいエラーのため）。一意キーは
        // `(tenant_id, email)` 等のテナント内一意（ADR-0009 §2）。最終的な一意性は
        // DB の UNIQUE 制約が保証し、競合時は create() が Conflict を返す。
        if self
            .users
            .find_by_email(tenant_id, &email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(RegisterError::Conflict(
                "email already registered".to_string(),
            ));
        }
        if let Some(username) = &preferred_username {
            if self
                .users
                .find_by_username(tenant_id, username)
                .await
                .map_err(internal)?
                .is_some()
            {
                return Err(RegisterError::Conflict(
                    "preferred_username already taken".to_string(),
                ));
            }
        }

        let password_hash = self.hasher.hash(&cmd.password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            email_verified: false,
            preferred_username,
            name,
            password_hash,
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        self.users.create(&user).await.map_err(|e| match e {
            DomainError::Conflict(m) => RegisterError::Conflict(m),
            other => RegisterError::Internal(other.to_string()),
        })?;

        // HOME メンバーシップ（所属元の単一の出所は users.tenant_id。この行はフロー判定用の
        // 投影として自動生成する。ADR-0009 §3）。
        self.memberships
            .create(&TenantMembership::new_home(tenant_id, user.id, now))
            .await
            .map_err(internal)?;

        Ok(RegisteredUser {
            sub: user.sub,
            status: user.status,
        })
    }
}

fn validate_email(email: &str) -> Result<(), RegisterError> {
    // 簡易チェック（MVP）: 空でなく、`@` を挟んで両側に文字がある。
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok(())
    } else {
        Err(RegisterError::Validation(
            "invalid email format".to_string(),
        ))
    }
}

fn validate_password(password: &str) -> Result<(), RegisterError> {
    validate_password_strength(password).map_err(RegisterError::Validation)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> RegisterError {
    RegisterError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::{Tenant, TenantId};
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::values::TenantStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct SeqIds(Mutex<u128>);
    impl IdGenerator for SeqIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    #[derive(Default)]
    struct FakeUsers {
        rows: Mutex<Vec<User>>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, u: &User) -> DomainResult<()> {
            self.rows.lock().unwrap().push(u.clone());
            Ok(())
        }
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, t: TenantId, e: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.email == e)
                .cloned())
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            Ok(None)
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeMemberships {
        rows: Mutex<Vec<TenantMembership>>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn create(&self, m: &TenantMembership) -> DomainResult<()> {
            self.rows.lock().unwrap().push(m.clone());
            Ok(())
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
        async fn find_by_invitation_token_hash(
            &self,
            _h: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn activate(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// 単一テナントのフェイク（`self_registration_enabled` を切り替えて使う）。
    struct FakeTenants {
        tenant: Tenant,
    }
    #[async_trait]
    impl crate::domain::repositories::TenantRepository for FakeTenants {
        async fn create(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(Some(self.tenant.clone()).filter(|t| t.id == id))
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            unreachable!()
        }
        async fn list_children(&self, _p: TenantId) -> DomainResult<Vec<Tenant>> {
            unreachable!()
        }
        async fn update(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: TenantId) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// 最初の `limit` 回だけ許可するレート制限フェイク。
    struct CountingLimiter {
        limit: usize,
        calls: AtomicUsize,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) < self.limit
        }
    }

    fn tenant(id: TenantId, self_registration_enabled: bool) -> Tenant {
        Tenant {
            id,
            parent_tenant_id: None,
            name: "Root".to_string(),
            status: TenantStatus::Active,
            self_registration_enabled,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn service(tenant: Tenant, limiter_allowance: usize) -> (RegisterService, Arc<FakeUsers>) {
        let users = Arc::new(FakeUsers::default());
        let svc = RegisterService::new(
            users.clone(),
            Arc::new(FakeMemberships::default()),
            Arc::new(FakeTenants { tenant }),
            Arc::new(PlainHasher),
            Arc::new(CountingLimiter {
                limit: limiter_allowance,
                calls: AtomicUsize::new(0),
            }),
            Arc::new(FixedClock),
            Arc::new(SeqIds(Mutex::new(0))),
        );
        (svc, users)
    }

    fn cmd() -> RegisterCommand {
        RegisterCommand {
            email: "new@example.com".to_string(),
            preferred_username: None,
            password: "longenough".to_string(),
            name: None,
        }
    }

    #[tokio::test]
    async fn register_is_forbidden_when_self_registration_disabled() {
        let t: TenantId = Uuid::now_v7().into();
        // 既定（無効）テナントでは登録できず、ユーザーも作られない（fail-closed。SEC6）。
        let (svc, users) = service(tenant(t, false), 100);
        assert!(matches!(
            svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1")).await,
            Err(RegisterError::Forbidden(_))
        ));
        assert!(users.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_succeeds_when_enabled() {
        let t: TenantId = Uuid::now_v7().into();
        let (svc, users) = service(tenant(t, true), 100);
        let registered = svc
            .register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
            .await
            .expect("registered");
        assert_eq!(registered.status, UserStatus::Active);
        assert_eq!(users.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn register_is_rate_limited_per_ip() {
        let t: TenantId = Uuid::now_v7().into();
        // 1 回だけ許可 → 2 回目は RateLimited（テナント判定より先に落とす）。
        let (svc, _) = service(tenant(t, true), 1);
        svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
            .await
            .expect("first attempt allowed");
        assert!(matches!(
            svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1")).await,
            Err(RegisterError::RateLimited)
        ));
    }

    #[test]
    fn rejects_invalid_email_and_short_password() {
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a@b").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("longenough").is_ok());
    }

    #[test]
    fn normalizes_empty_optional_to_none() {
        assert_eq!(normalize_optional(Some("  ".to_string())), None);
        assert_eq!(
            normalize_optional(Some("  bob ".to_string())),
            Some("bob".to_string())
        );
        assert_eq!(normalize_optional(None), None);
    }
}
