//! 利用者権限（permission code）の付与・剥奪ユースケース（ADR-0006、Progress A2）。
//!
//! テナント管理者（`idp.tenant.admin`。`idp.system.admin` は代替として許可）のみが実行する。判定・検証は本 Application 層で完結し、Presentation には
//! 結果のみ返す（CLAUDE.md「権限管理」）。全ての付与・剥奪は `audit_log` に記録する
//! （`user_permission.granted` / `.revoked`、設計仕様 §7）。
//!
//! 権限の**参照**（保護判定）は [`crate::application::admin_access::AdminAccessService`] が担う。
//! 本サービスは「権限の管理（変更）」という別責務（SRP）であり、`ClientManagementService` と同じ位置づけ。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::permission::PermissionCode;
use crate::domain::repositories::{UserPermissionRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum PermissionManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// `idp.system.admin` の付与・剥奪は保有者のみが行える（ADR-0009 §4）。
const SYSTEM_ADMIN_PERMISSION: &str = "idp.system.admin";

pub struct PermissionManagementService {
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PermissionManagementService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            permissions,
            audit,
            clock,
        }
    }

    /// 付与可能な権限コードの一覧（`permissions` マスタ）を返す。管理コンソール（A2）の
    /// 付与フォームで選択肢を提示するために使う。
    pub async fn available_codes(&self) -> Result<Vec<String>, PermissionManagementError> {
        self.permissions
            .list_available_codes()
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// 対象利用者を内部 ID で取得する（管理コンソールの表示用）。不存在、または所属元が
    /// 要求テナント以外（テナント越しの参照）は 404 相当。
    pub async fn get_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, PermissionManagementError> {
        match self.users.find_by_id(target).await {
            Ok(Some(user)) if user.tenant_id == tenant.tenant_id() => Ok(user),
            Ok(_) => Err(PermissionManagementError::NotFound),
            Err(e) => Err(PermissionManagementError::Internal(e.to_string())),
        }
    }

    /// 識別子（メールアドレスまたはユーザー名）で利用者を探す（管理コンソールの検索用）。
    /// `@` を含めばメール、そうでなければユーザー名として解決する。空文字列は None を返す。
    pub async fn find_user_by_identifier(
        &self,
        tenant: TenantContext,
        identifier: &str,
    ) -> Result<Option<User>, PermissionManagementError> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return Ok(None);
        }
        let tenant_id = tenant.tenant_id();
        let result = if identifier.contains('@') {
            self.users.find_by_email(tenant_id, identifier).await
        } else {
            self.users.find_by_username(tenant_id, identifier).await
        };
        result.map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// 対象利用者が要求テナントを scope として保有する権限コード一覧を返す（順序は不定）。
    pub async fn list(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<Vec<String>, PermissionManagementError> {
        self.ensure_user_in_tenant(tenant, target).await?;
        self.permissions
            .list_codes_for_user(tenant.tenant_id(), target)
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// 対象利用者へ、要求テナントを scope として権限コードを付与する（冪等）。
    /// 付与後の保有コード一覧を返す。`idp.system.admin` の付与は保有者のみが行える
    /// （ADR-0009 §4。scope = root の保証は DB の CHECK 制約と二重防御）。
    pub async fn grant(
        &self,
        tenant: TenantContext,
        target: Uuid,
        code: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code)
            .map_err(|e| PermissionManagementError::Validation(e.to_string()))?;
        self.ensure_user_in_tenant(tenant, target).await?;
        self.ensure_system_admin_change_allowed(tenant, &code, actor)
            .await?;

        self.permissions
            .grant(tenant.tenant_id(), target, code.as_str(), self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(tenant, target).await
    }

    /// 対象利用者から、要求テナントを scope とする権限コードを剥奪する（未保有でもエラーにしない）。
    /// 剥奪後の保有コード一覧を返す。`idp.system.admin` の剥奪は保有者のみが行える（ADR-0009 §4）。
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        target: Uuid,
        code: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code)
            .map_err(|e| PermissionManagementError::Validation(e.to_string()))?;
        self.ensure_user_in_tenant(tenant, target).await?;
        self.ensure_system_admin_change_allowed(tenant, &code, actor)
            .await?;

        self.permissions
            .revoke(tenant.tenant_id(), target, code.as_str())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(tenant, target).await
    }

    /// 対象利用者が現存し、所属元が要求テナントであることを確かめる（テナント越しの操作は
    /// 不存在と同じ 404 に倒す）。GUEST メンバーへの付与は招待ユースケース（MT8）以降で扱う。
    async fn ensure_user_in_tenant(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<(), PermissionManagementError> {
        match self.users.find_by_id(target).await {
            Ok(Some(user)) if user.tenant_id == tenant.tenant_id() => Ok(()),
            Ok(_) => Err(PermissionManagementError::NotFound),
            Err(e) => Err(PermissionManagementError::Internal(e.to_string())),
        }
    }

    /// `idp.system.admin` の付与・剥奪は `idp.system.admin` 保有者のみが実行できる（ADR-0009 §4）。
    async fn ensure_system_admin_change_allowed(
        &self,
        tenant: TenantContext,
        code: &PermissionCode,
        actor: Uuid,
    ) -> Result<(), PermissionManagementError> {
        if code.as_str() != SYSTEM_ADMIN_PERMISSION {
            return Ok(());
        }
        match self
            .permissions
            .has_permission(tenant.tenant_id(), actor, SYSTEM_ADMIN_PERMISSION)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(PermissionManagementError::Forbidden(
                "only idp.system.admin holders may grant or revoke idp.system.admin".to_string(),
            )),
            Err(e) => Err(PermissionManagementError::Internal(e.to_string())),
        }
    }
}

/// 監査ログの `reason`（PII を含めない。内部 UUID と権限コードのみ）。
fn audit_reason(code: &PermissionCode, target: Uuid) -> String {
    format!("permission={code} target={target}")
}

fn map_repo_error(e: DomainError) -> PermissionManagementError {
    match e {
        // 未知の権限コード（`permissions` マスタに無い）等は不正リクエスト扱い。
        DomainError::InvalidValue(m) => PermissionManagementError::Validation(m),
        other => PermissionManagementError::Internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant::TenantId;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap()
    }

    fn test_tenant() -> TenantId {
        // 各テストは service() へ渡すユーザーとテナントを揃える必要があるため固定値にする。
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn tenant_ctx() -> TenantContext {
        TenantContext::new(test_tenant())
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// 監査イベントを収集するだけのシンク（付与/剥奪が記録されることの検証用）。
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

    struct FakeUsers {
        user: Option<User>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.user.clone().filter(|u| u.id == id))
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(
            &self,
            tenant_id: TenantId,
            email: &str,
        ) -> DomainResult<Option<User>> {
            Ok(self
                .user
                .clone()
                .filter(|u| u.tenant_id == tenant_id && u.email == email))
        }
        async fn find_by_username(
            &self,
            tenant_id: TenantId,
            username: &str,
        ) -> DomainResult<Option<User>> {
            Ok(self
                .user
                .clone()
                .filter(|u| u.tenant_id == tenant_id)
                .filter(|u| u.preferred_username.as_deref() == Some(username)))
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

    /// 付与/剥奪の呼び出しを記録し、保有状態を保持するフェイク。
    #[derive(Default)]
    struct FakePermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        reject_unknown: bool,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec!["idp.tenant.admin".to_string()])
        }
        async fn list_codes_for_user(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, u, _)| *t == tenant_id && *u == user_id)
                .map(|(_, _, c)| c.clone())
                .collect())
        }
        async fn has_permission(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
        ) -> DomainResult<bool> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code))
        }
        async fn grant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            if self.reject_unknown {
                return Err(DomainError::InvalidValue(format!(
                    "unknown permission code or user: {code}"
                )));
            }
            let mut g = self.granted.lock().unwrap();
            if !g
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code)
            {
                g.push((tenant_id, user_id, code.to_string()));
            }
            Ok(())
        }
        async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> DomainResult<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(t, u, c)| !(*t == tenant_id && *u == user_id && c == code));
            Ok(())
        }
    }

    fn test_user(id: Uuid) -> User {
        User {
            id,
            tenant_id: test_tenant(),
            sub: Uuid::new_v4(),
            email: "target@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("target".to_string()),
            name: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: fixed_now(),
            updated_at: fixed_now(),
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
        user: Option<User>,
        perms: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> PermissionManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(fixed_now()))));
        PermissionManagementService::new(
            Arc::new(FakeUsers { user }),
            perms,
            audit,
            Arc::new(FixedClock(fixed_now())),
        )
    }

    #[tokio::test]
    async fn grant_persists_and_audits() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        let codes = svc
            .grant(tenant_ctx(), target, "idp.tenant.admin", actor, &ctx())
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.tenant.admin".to_string()]);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserPermissionGranted);
        assert_eq!(events[0].user_id, Some(actor));
        assert_eq!(events[0].tenant_id, Some(test_tenant()));
        assert!(events[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("idp.tenant.admin"));
    }

    #[tokio::test]
    async fn revoke_removes_and_audits() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        perms
            .granted
            .lock()
            .unwrap()
            .push((test_tenant(), target, "idp.tenant.admin".to_string()));
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        let codes = svc
            .revoke(tenant_ctx(), target, "idp.tenant.admin", actor, &ctx())
            .await
            .expect("revoke ok");
        assert!(codes.is_empty());

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserPermissionRevoked);
    }

    #[tokio::test]
    async fn grant_rejects_empty_code() {
        let target = Uuid::new_v4();
        let svc = service(
            Some(test_user(target)),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.grant(tenant_ctx(), target, "  ", Uuid::new_v4(), &ctx())
                .await,
            Err(PermissionManagementError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn grant_unknown_code_is_validation_error() {
        let target = Uuid::new_v4();
        let perms = Arc::new(FakePermissions {
            reject_unknown: true,
            ..Default::default()
        });
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms, sink.clone());

        assert!(matches!(
            svc.grant(tenant_ctx(), target, "idp.unknown", Uuid::new_v4(), &ctx())
                .await,
            Err(PermissionManagementError::Validation(_))
        ));
        // 失敗時は監査イベントを出さない。
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn find_user_by_identifier_resolves_email_and_username() {
        let target = Uuid::new_v4();
        let svc = service(
            Some(test_user(target)),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        // `@` を含めばメール、含まなければユーザー名で解決する。
        let by_email = svc
            .find_user_by_identifier(tenant_ctx(), "target@example.com")
            .await
            .expect("lookup ok");
        assert_eq!(by_email.map(|u| u.id), Some(target));
        let by_username = svc
            .find_user_by_identifier(tenant_ctx(), "  target  ")
            .await
            .expect("lookup ok");
        assert_eq!(by_username.map(|u| u.id), Some(target));
        // 未知の識別子・空文字列は None。
        assert!(svc
            .find_user_by_identifier(tenant_ctx(), "nobody@example.com")
            .await
            .expect("lookup ok")
            .is_none());
        assert!(svc
            .find_user_by_identifier(tenant_ctx(), "   ")
            .await
            .expect("lookup ok")
            .is_none());
        // 他テナントの scope では解決しない（テナント分離）。
        let other = TenantContext::new(TenantId::from(Uuid::now_v7()));
        assert!(svc
            .find_user_by_identifier(other, "target@example.com")
            .await
            .expect("lookup ok")
            .is_none());
    }

    #[tokio::test]
    async fn available_codes_come_from_master() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert_eq!(
            svc.available_codes().await.expect("ok"),
            vec!["idp.tenant.admin".to_string()]
        );
    }

    #[tokio::test]
    async fn get_user_returns_not_found_when_absent() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.get_user(tenant_ctx(), Uuid::new_v4()).await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    #[tokio::test]
    async fn missing_target_user_is_not_found() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                Uuid::new_v4(),
                "idp.tenant.admin",
                Uuid::new_v4(),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
        assert!(matches!(
            svc.list(tenant_ctx(), Uuid::new_v4()).await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    #[tokio::test]
    async fn system_admin_grant_requires_system_admin_actor() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        // actor が idp.system.admin を保有しない → Forbidden（ADR-0009 §4）。
        assert!(matches!(
            svc.grant(tenant_ctx(), target, "idp.system.admin", actor, &ctx())
                .await,
            Err(PermissionManagementError::Forbidden(_))
        ));
        assert!(sink.events.lock().unwrap().is_empty());

        // actor が保有していれば付与できる。
        perms
            .granted
            .lock()
            .unwrap()
            .push((test_tenant(), actor, "idp.system.admin".to_string()));
        let codes = svc
            .grant(tenant_ctx(), target, "idp.system.admin", actor, &ctx())
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.system.admin".to_string()]);
    }
}
