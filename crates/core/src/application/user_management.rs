//! 管理者による利用者作成ユースケース（ADR-0009 §5・§6）。
//!
//! テナント管理者（`idp.tenant.admin`）が、所属元が当該テナントの利用者を作成する
//! （`POST /{tenant_id}/admin/users`）。セルフ登録（[`crate::application::register`]）と異なり、
//! **パスワードを自動生成**し（32 文字以上のランダム文字列）、`must_change_password = true` を付与する。
//! 生成パスワードは**この一度だけ**平文でレスポンスに返し（管理者が本人へ別途通知する）、ログ・監査には
//! 出さない（`generated_password` / 招待トークンと同じパターン。ADR-0009 §5）。
//!
//! テナント作成フロー（[`crate::application::tenant_management`]）が生成する初期管理者ユーザーも
//! 本サービスを通す（作成ロジックの単一の出所）。判定・検証は本 Application 層で完結し、Presentation
//! には結果のみ返す（`CLAUDE.md`「権限管理」）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{TenantMembershipRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::{
    validate_email as domain_validate_email,
    validate_preferred_username as domain_validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

/// 自動生成パスワードのバイト長。base64url（パディング無し）で 43 文字となり、ADR-0009 §5 の
/// 「32 文字以上」を満たす。
const GENERATED_PASSWORD_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct CreateUserCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

/// 作成結果。`generated_password` は**この一度だけ**平文で返す（保存はハッシュのみ、ログ・監査には出さない）。
pub struct CreatedUser {
    pub user_id: Uuid,
    pub sub: Uuid,
    pub generated_password: String,
}

/// 構築済み（未永続化）の利用者。検証・自動生成パスワードのハッシュ化まで済んでおり、永続化だけが
/// 残っている状態。テナント開通（REF2）が、テナント行と同一トランザクションで管理者を永続化する
/// ために使う。`generated_password` の扱いは [`CreatedUser`] と同じ（一度だけ平文、ログに出さない）。
pub struct PreparedUser {
    pub user: User,
    pub generated_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UserManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct UserManagementService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl UserManagementService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            hasher,
            audit,
            clock,
            ids,
        }
    }

    /// 所属元が `tenant` の利用者を**構築だけ**する（永続化しない）。入力検証・一意性の事前チェック・
    /// パスワード自動生成とハッシュ化まで行う。永続化とセットで使う（`create_user`、またはテナント
    /// 開通トランザクション）。
    pub async fn prepare_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
    ) -> Result<PreparedUser, UserManagementError> {
        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        // ログイン識別子は preferred_username。未指定なら email を既定値として採用する（ADR-0009 §8）。
        let preferred_username =
            normalize_optional(cmd.preferred_username).unwrap_or_else(|| email.clone());
        // カラム長（VARCHAR(255)）超過を永続化前に弾く（email は VARCHAR(320) のため既定値化で超え得る）。
        domain_validate_preferred_username(&preferred_username)
            .map_err(|e| UserManagementError::Validation(e.to_string()))?;
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // 一意性の事前チェック（利用者向けの分かりやすいエラー）。最終的な一意性は DB の
        // `(tenant_id, email)` / `(tenant_id, preferred_username)` UNIQUE 制約が保証する。
        if self
            .users
            .find_by_email(tenant_id, &email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(UserManagementError::Conflict(
                "email already registered".to_string(),
            ));
        }
        if self
            .users
            .find_by_username(tenant_id, &preferred_username)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(UserManagementError::Conflict(
                "preferred_username already taken".to_string(),
            ));
        }

        let generated_password = crypto::random_token(GENERATED_PASSWORD_BYTES);
        let password_hash = self.hasher.hash(&generated_password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            // 管理者が作成するユーザーは管理者がメール所有を保証する扱いとし、検証済みで作る（SEC6b）。
            // これにより自己登録（未検証）のみがログイン時のメール検証ゲートに掛かる。テナント作成時の
            // 初期管理者（本サービス経由）もログイン可能なまま。
            email_verified: true,
            preferred_username: Some(preferred_username),
            name,
            language: None,
            password_hash,
            must_change_password: true,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        Ok(PreparedUser {
            user,
            generated_password,
        })
    }

    /// 所属元が `tenant` の利用者を、自動生成パスワード付きで作成する。HOME メンバーシップを同時に
    /// 生成し、`must_change_password = true` を付与する。生成パスワードを一度だけ返す。
    pub async fn create_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<CreatedUser, UserManagementError> {
        let tenant_id = tenant.tenant_id();
        let prepared = self.prepare_user(tenant, cmd).await?;
        let user = prepared.user;

        self.users.create(&user).await.map_err(|e| match e {
            DomainError::Conflict(m) => UserManagementError::Conflict(m),
            other => UserManagementError::Internal(other.to_string()),
        })?;

        // HOME メンバーシップ（所属元の単一の出所は users.tenant_id。この行はフロー判定用の投影。§3）。
        self.memberships
            .create(&TenantMembership::new_home(
                tenant_id,
                user.id,
                user.created_at,
            ))
            .await
            .map_err(internal)?;

        // 監査には内部 ID のみ記録する（生成パスワードは出さない。§5）。
        self.audit
            .record(
                AuditEventType::UserCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(actor),
                None,
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;

        Ok(CreatedUser {
            user_id: user.id,
            sub: user.sub,
            generated_password: prepared.generated_password,
        })
    }
}

fn validate_email(email: &str) -> Result<(), UserManagementError> {
    domain_validate_email(email).map_err(|e| UserManagementError::Validation(e.to_string()))
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> UserManagementError {
    UserManagementError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::password::PasswordHasher as PasswordHasherTrait;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 11, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct FixedIds(Mutex<u128>);
    impl IdGenerator for FixedIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    struct PlainHasher;
    impl PasswordHasherTrait for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
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
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.id == id)
                .cloned())
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
        async fn find_by_username(&self, t: TenantId, name: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.preferred_username.as_deref() == Some(name))
                .cloned())
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
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

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    fn service(
        users: Arc<FakeUsers>,
        memberships: Arc<FakeMemberships>,
        sink: Arc<CapturingSink>,
    ) -> UserManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(now()))));
        UserManagementService::new(
            users,
            memberships,
            Arc::new(PlainHasher),
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(FixedIds(Mutex::new(0))),
        )
    }

    #[tokio::test]
    async fn creates_user_with_generated_password_and_home_membership() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(users.clone(), memberships.clone(), sink.clone());

        let created = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "  new@example.com ".to_string(),
                    preferred_username: Some("newbie".to_string()),
                    name: None,
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .expect("created");

        // 生成パスワードは 32 文字以上。
        assert!(created.generated_password.len() >= 32);
        let stored = users.rows.lock().unwrap()[0].clone();
        // 保存されるのはハッシュのみ（平文は保持しない）。
        assert_eq!(
            stored.password_hash,
            format!("hash:{}", created.generated_password)
        );
        assert_ne!(stored.password_hash, created.generated_password);
        assert!(stored.must_change_password);
        assert_eq!(stored.email, "new@example.com");
        assert_eq!(stored.tenant_id, tenant);
        // HOME メンバーシップが作られる。
        let m = memberships.rows.lock().unwrap()[0].clone();
        assert!(m.is_home());
        assert_eq!(m.tenant_id, tenant);
        // 監査に生成パスワードが漏れていない。
        assert!(sink.events.lock().unwrap().iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&created.generated_password))
            .unwrap_or(true)));
        assert_eq!(
            sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserCreated
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let svc = service(
            users.clone(),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        let cmd = || CreateUserCommand {
            email: "dup@example.com".to_string(),
            preferred_username: None,
            name: None,
        };
        svc.create_user(TenantContext::new(tenant), cmd(), Uuid::new_v4(), &ctx())
            .await
            .expect("first ok");
        assert!(matches!(
            svc.create_user(TenantContext::new(tenant), cmd(), Uuid::new_v4(), &ctx())
                .await,
            Err(UserManagementError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "not-an-email".to_string(),
                    preferred_username: None,
                    name: None,
                },
                Uuid::new_v4(),
                &ctx()
            )
            .await,
            Err(UserManagementError::Validation(_))
        ));
    }
}
