//! テナント作成・管理ユースケース（ADR-0009 §4・§5・§6）。
//!
//! テナント作成は「あるテナント配下への子テナント作成」として一律に扱う。`idp.system.admin`（scope =
//! root のみ存在）を要求するため、**実質的にテナントを作成できるのは root だけ**になる（§4。判定は
//! Presentation の `RequirePerms<IdpSystemAdmin>` が担う）。
//!
//! 作成時に、新テナントを所属元とする管理者ユーザーを[`UserManagementService`]で生成し（自動生成
//! パスワード・`must_change_password`。§5）、新テナントを scope とする `idp.tenant.admin` を付与する。
//! 以後この管理者だけがテナント内部を管理でき、作成者（root の system.admin）は内部を操作できない
//! （テナント独立。§1）。生成パスワードは**この一度だけ**平文で返す（ログ・監査には出さない）。
//!
//! テナントの取得・更新・削除は**当該テナントの直下の子**のみを対象とする（`parent_tenant_id` 照合。
//! 他テナントの子は不存在として扱う）。root テナントはアプリ層で削除を禁止する（§1）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::user_management::{
    CreateUserCommand, UserManagementError, UserManagementService,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::{TenantRepository, UserPermissionRepository};
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::TenantStatus;
use std::sync::Arc;
use uuid::Uuid;

/// 新テナントの管理者へ付与する権限（scope = 新テナント。ADR-0009 §5）。
const TENANT_ADMIN_PERMISSION: &str = "idp.tenant.admin";

#[derive(Debug, Clone)]
pub struct CreateTenantCommand {
    pub name: String,
    /// 初期管理者のメールアドレス（新テナントを所属元とする管理者ユーザーを生成する）。
    pub admin_email: String,
}

/// 部分更新コマンド。`None` のフィールドは変更しない。
#[derive(Debug, Clone, Default)]
pub struct UpdateTenantCommand {
    pub name: Option<String>,
    pub status: Option<TenantStatus>,
}

/// テナント作成結果。`generated_password` は初期管理者の自動生成パスワードで、**この一度だけ**平文で
/// 返す（保存はハッシュのみ、ログ・監査には出さない。§5）。
pub struct CreatedTenant {
    pub tenant: Tenant,
    pub admin_user_id: Uuid,
    pub generated_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<UserManagementError> for TenantManagementError {
    fn from(e: UserManagementError) -> Self {
        match e {
            UserManagementError::Validation(m) => TenantManagementError::Validation(m),
            UserManagementError::Conflict(m) => TenantManagementError::Conflict(m),
            UserManagementError::Internal(m) => TenantManagementError::Internal(m),
        }
    }
}

pub struct TenantManagementService {
    tenants: Arc<dyn TenantRepository>,
    users: Arc<UserManagementService>,
    permissions: Arc<dyn UserPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl TenantManagementService {
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        users: Arc<UserManagementService>,
        permissions: Arc<dyn UserPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            tenants,
            users,
            permissions,
            audit,
            clock,
            ids,
        }
    }

    /// `requesting` テナント配下に子テナントを作成し、初期管理者ユーザー（自動生成パスワード・
    /// `must_change_password`）を生成して新テナント scope の `idp.tenant.admin` を付与する。
    /// 生成パスワードを一度だけ返す（§5）。
    pub async fn create_tenant(
        &self,
        requesting: TenantContext,
        cmd: CreateTenantCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<CreatedTenant, TenantManagementError> {
        let name = validate_name(cmd.name)?;
        // 初期管理者メールを先に検証し、不正なら**テナントを作る前に**失敗させる（孤立テナントの防止。
        // 一意性・最終検証は下の create_user が担う）。
        validate_email(&cmd.admin_email)?;

        let now = self.clock.now();
        let tenant = Tenant {
            id: TenantId::from(self.ids.new_id()),
            parent_tenant_id: Some(requesting.tenant_id()),
            name,
            status: TenantStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.tenants.create(&tenant).await.map_err(|e| match e {
            DomainError::Conflict(m) => TenantManagementError::Conflict(m),
            other => TenantManagementError::Internal(other.to_string()),
        })?;

        // 初期管理者は新テナントを所属元として生成する（自動生成パスワード・must_change_password）。
        let new_tenant_ctx = TenantContext::new(tenant.id);
        let created_user = self
            .users
            .create_user(
                new_tenant_ctx,
                CreateUserCommand {
                    email: cmd.admin_email,
                    preferred_username: None,
                    name: None,
                },
                actor,
                ctx,
            )
            .await?;

        // 新テナントを scope とする idp.tenant.admin を付与する（付与対象は当該テナントのメンバー。§4）。
        self.permissions
            .grant(
                tenant.id,
                created_user.user_id,
                TENANT_ADMIN_PERMISSION,
                now,
            )
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantCreated,
                AuditResult::Success,
                Some(tenant.id),
                Some(actor),
                None,
                Some(&format!("tenant={} admin={}", tenant.id, created_user.user_id)),
                ctx,
            )
            .await;

        Ok(CreatedTenant {
            tenant,
            admin_user_id: created_user.user_id,
            generated_password: created_user.generated_password,
        })
    }

    /// `requesting` テナントの直下の子テナントを一覧する（§6）。
    pub async fn list_children(
        &self,
        requesting: TenantContext,
    ) -> Result<Vec<Tenant>, TenantManagementError> {
        self.tenants
            .list_children(requesting.tenant_id())
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))
    }

    /// `requesting` テナントの直下の子テナント 1 件を取得する。他テナントの子・不存在は `NotFound`。
    pub async fn get_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        self.load_child(requesting, child_id).await
    }

    /// 子テナントの表示名・状態を更新する（`parent_tenant_id` は変更しない。§1）。
    pub async fn update_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        cmd: UpdateTenantCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let mut tenant = self.load_child(requesting, child_id).await?;
        if let Some(name) = cmd.name {
            tenant.name = validate_name(name)?;
        }
        if let Some(status) = cmd.status {
            tenant.status = status;
        }
        self.tenants
            .update(&tenant)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant.id),
                Some(actor),
                None,
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(tenant)
    }

    /// 子テナントを削除する。root は削除不可（§1）。配下に子が居る場合は `Conflict`。当該テナント自身に
    /// ユーザー/クライアントが存在する場合は DB の `ON DELETE RESTRICT` により `Conflict`（§1）。
    pub async fn delete_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), TenantManagementError> {
        let tenant = self.load_child(requesting, child_id).await?;
        // root は構造的に誰の子でもない（load_child で既に弾かれる）が、明示的に禁止して二重防御とする。
        if tenant.is_root() {
            return Err(TenantManagementError::Forbidden(
                "the root tenant cannot be deleted".to_string(),
            ));
        }
        // 配下に子テナントが存在しないこと（アプリ層の事前検証。§1）。
        let grandchildren = self
            .tenants
            .list_children(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        if !grandchildren.is_empty() {
            return Err(TenantManagementError::Conflict(
                "tenant has child tenants".to_string(),
            ));
        }

        // ユーザー/クライアントの残存は DB の FK（ON DELETE RESTRICT）が Conflict に倒す（§1）。
        self.tenants.delete(tenant.id).await.map_err(|e| match e {
            DomainError::Conflict(m) => TenantManagementError::Conflict(m),
            other => TenantManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::TenantDeleted,
                AuditResult::Success,
                Some(tenant.id),
                Some(actor),
                None,
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// `child_id` が `requesting` の直下の子テナントであることを確かめて取得する（他テナントの子・
    /// 不存在は `NotFound` に倒し、存在を漏らさない。§6）。
    async fn load_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        match self
            .tenants
            .find_by_id(child_id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
        {
            Some(tenant) if tenant.parent_tenant_id == Some(requesting.tenant_id()) => Ok(tenant),
            _ => Err(TenantManagementError::NotFound),
        }
    }
}

fn validate_name(name: String) -> Result<String, TenantManagementError> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(TenantManagementError::Validation(
            "tenant name must not be empty".to_string(),
        ));
    }
    Ok(trimmed)
}

/// 初期管理者メールの簡易検証（user_management と同一基準。孤立テナント防止の事前チェック）。
fn validate_email(email: &str) -> Result<(), TenantManagementError> {
    let parts: Vec<&str> = email.trim().split('@').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok(())
    } else {
        Err(TenantManagementError::Validation(
            "invalid email format".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::user_management::UserManagementService;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::password::PasswordHasher;
    use crate::domain::repositories::{
        AuditLogSink, TenantMembershipRepository, UserRepository,
    };
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::user::User;
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
            Ok(self.rows.lock().unwrap().iter().find(|u| u.id == id).cloned())
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
        async fn update_password(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
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

    #[derive(Default)]
    struct FakeTenants {
        rows: Mutex<Vec<Tenant>>,
    }
    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, t: &Tenant) -> DomainResult<()> {
            self.rows.lock().unwrap().push(t.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(self.rows.lock().unwrap().iter().find(|t| t.id == id).cloned())
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            Ok(self.rows.lock().unwrap().iter().find(|t| t.is_root()).cloned())
        }
        async fn list_children(&self, parent: TenantId) -> DomainResult<Vec<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|t| t.parent_tenant_id == Some(parent))
                .cloned()
                .collect())
        }
        async fn update(&self, t: &Tenant) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|r| r.id == t.id) {
                *row = t.clone();
            }
            Ok(())
        }
        async fn delete(&self, id: TenantId) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|t| t.id != id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakePermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            unreachable!()
        }
        async fn list_codes_for_user(&self, t: TenantId, u: Uuid) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(tt, uu, _)| *tt == t && *uu == u)
                .map(|(_, _, c)| c.clone())
                .collect())
        }
        async fn has_permission(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn grant(
            &self,
            t: TenantId,
            u: Uuid,
            c: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.granted.lock().unwrap().push((t, u, c.to_string()));
            Ok(())
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<()> {
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

    struct Harness {
        svc: TenantManagementService,
        tenants: Arc<FakeTenants>,
        permissions: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    }

    fn harness() -> Harness {
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let user_mgmt = Arc::new(UserManagementService::new(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            Arc::new(PlainHasher),
            audit.clone(),
            Arc::new(FixedClock(now())),
            Arc::new(SeqIds(Mutex::new(1000))),
        ));
        let tenants = Arc::new(FakeTenants::default());
        let permissions = Arc::new(FakePermissions::default());
        let svc = TenantManagementService::new(
            tenants.clone(),
            user_mgmt,
            permissions.clone(),
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(SeqIds(Mutex::new(0))),
        );
        Harness {
            svc,
            tenants,
            permissions,
            sink,
        }
    }

    fn root() -> TenantContext {
        // root として作成側テナントを表す（parent 照合には使わない）。
        TenantContext::new(TenantId::from(Uuid::from_u128(0xAAAA)))
    }

    #[tokio::test]
    async fn create_tenant_provisions_admin_and_grants_tenant_admin() {
        let h = harness();
        let created = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "  Acme  ".to_string(),
                    admin_email: "admin@acme.example.com".to_string(),
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .expect("created");

        assert_eq!(created.tenant.name, "Acme");
        assert_eq!(created.tenant.parent_tenant_id, Some(root().tenant_id()));
        assert!(created.generated_password.len() >= 32);
        // 新テナント scope で idp.tenant.admin が付与される。
        let granted = h.permissions.granted.lock().unwrap().clone();
        assert_eq!(
            granted,
            vec![(
                created.tenant.id,
                created.admin_user_id,
                "idp.tenant.admin".to_string()
            )]
        );
        // 監査に tenant.created + user.created が記録され、生成パスワードは漏れない。
        let events = h.sink.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.event_type == AuditEventType::TenantCreated));
        assert!(events.iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&created.generated_password))
            .unwrap_or(true)));
    }

    #[tokio::test]
    async fn create_tenant_rejects_empty_name() {
        let h = harness();
        assert!(matches!(
            h.svc
                .create_tenant(
                    root(),
                    CreateTenantCommand {
                        name: "   ".to_string(),
                        admin_email: "a@b.example.com".to_string(),
                    },
                    Uuid::new_v4(),
                    &ctx()
                )
                .await,
            Err(TenantManagementError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn create_tenant_rejects_invalid_admin_email_without_creating_tenant() {
        let h = harness();
        assert!(matches!(
            h.svc
                .create_tenant(
                    root(),
                    CreateTenantCommand {
                        name: "Acme".to_string(),
                        admin_email: "not-an-email".to_string(),
                    },
                    Uuid::new_v4(),
                    &ctx()
                )
                .await,
            Err(TenantManagementError::Validation(_))
        ));
        // 孤立テナントが作られていないこと（メール検証は作成前）。
        assert!(h.tenants.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_update_delete_scope_to_direct_children() {
        let h = harness();
        let created = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Child".to_string(),
                    admin_email: "a@child.example.com".to_string(),
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .unwrap();
        let child_id = created.tenant.id;

        // 別テナントからは見えない（NotFound）。
        let other = TenantContext::new(TenantId::from(Uuid::from_u128(0xBBBB)));
        assert!(matches!(
            h.svc.get_child(other, child_id).await,
            Err(TenantManagementError::NotFound)
        ));

        // 直下の子は取得できる。
        assert_eq!(h.svc.get_child(root(), child_id).await.unwrap().id, child_id);

        // 更新（表示名・状態）。
        let updated = h
            .svc
            .update_tenant(
                root(),
                child_id,
                UpdateTenantCommand {
                    name: Some("Renamed".to_string()),
                    status: Some(TenantStatus::Disabled),
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.status, TenantStatus::Disabled);

        // 削除できる（子・ユーザーは fake では検査しないが list_children は空）。
        h.svc
            .delete_tenant(root(), child_id, Uuid::new_v4(), &ctx())
            .await
            .expect("deleted");
        assert!(h.tenants.rows.lock().unwrap().iter().all(|t| t.id != child_id));
    }

    #[tokio::test]
    async fn delete_rejects_tenant_with_children() {
        let h = harness();
        let parent = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Parent".to_string(),
                    admin_email: "a@parent.example.com".to_string(),
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .unwrap();
        // parent の下に孫を作る（parent を requesting として）。
        h.svc
            .create_tenant(
                TenantContext::new(parent.tenant.id),
                CreateTenantCommand {
                    name: "Grandchild".to_string(),
                    admin_email: "a@grand.example.com".to_string(),
                },
                Uuid::new_v4(),
                &ctx(),
            )
            .await
            .unwrap();

        assert!(matches!(
            h.svc
                .delete_tenant(root(), parent.tenant.id, Uuid::new_v4(), &ctx())
                .await,
            Err(TenantManagementError::Conflict(_))
        ));
    }
}
