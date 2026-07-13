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
use crate::domain::permission::{self, PermissionCode};
use crate::domain::repositories::{
    TenantMembershipRepository, UserPermissionRepository, UserRepository,
};
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
pub struct PermissionManagementService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PermissionManagementService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            memberships,
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
        match self.find_user_by_id(target).await? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(PermissionManagementError::NotFound),
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

    /// 対象利用者が現存し、要求テナントで **ACTIVE なメンバーシップ**（HOME / GUEST）を持つことを
    /// 確かめる（ADR-0009 §4）。付与対象はアカウントの出自（HOME か GUEST か）では区別しない。
    /// `INVITED`（未承諾）ゲスト・テナント外ユーザーはメンバーシップが ACTIVE でないため、テナント越しの
    /// 存在推測を防ぐべく不存在と同じ 404 に倒す。
    async fn ensure_user_in_tenant(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<(), PermissionManagementError> {
        // ユーザーが現存すること（メンバーシップ行は FK でユーザーを含意するが、明示して意図を残す）。
        let exists = self.find_user_by_id(target).await?.is_some();
        // 要求テナントで ACTIVE なメンバーシップ（HOME / GUEST）を持つこと。
        let active_member = exists
            && self
                .memberships
                .is_active_member(tenant.tenant_id(), target)
                .await
                .map_err(|e| PermissionManagementError::Internal(e.to_string()))?;
        if active_member {
            Ok(())
        } else {
            Err(PermissionManagementError::NotFound)
        }
    }

    /// ユーザー ID で検索し、内部エラーを `PermissionManagementError::Internal` に変換する。
    async fn find_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<crate::domain::user::User>, PermissionManagementError> {
        self.users
            .find_by_id(id)
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// `idp.system.admin` の付与・剥奪は `idp.system.admin` 保有者のみが実行できる（ADR-0009 §4）。
    async fn ensure_system_admin_change_allowed(
        &self,
        tenant: TenantContext,
        code: &PermissionCode,
        actor: Uuid,
    ) -> Result<(), PermissionManagementError> {
        if code.as_str() != permission::SYSTEM_ADMIN {
            return Ok(());
        }
        match self
            .permissions
            .has_permission(tenant.tenant_id(), actor, permission::SYSTEM_ADMIN)
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
    use crate::domain::tenant_membership::TenantMembership;
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
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// 指定した (tenant, user) の組を ACTIVE メンバーとして扱うフェイク（他は非メンバー）。
    #[derive(Default)]
    struct FakeMemberships {
        active: Mutex<Vec<(TenantId, Uuid)>>,
    }
    impl FakeMemberships {
        fn with_active(pairs: Vec<(TenantId, Uuid)>) -> Self {
            Self {
                active: Mutex::new(pairs),
            }
        }
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<bool> {
            Ok(self
                .active
                .lock()
                .unwrap()
                .iter()
                .any(|(t, u)| *t == tenant_id && *u == user_id))
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
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
        ) -> DomainResult<Vec<String>> {
            unreachable!()
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
            language: None,
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

    fn service_with(
        user: Option<User>,
        memberships: Arc<FakeMemberships>,
        perms: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> PermissionManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(fixed_now()))));
        PermissionManagementService::new(
            Arc::new(FakeUsers { user }),
            memberships,
            perms,
            audit,
            Arc::new(FixedClock(fixed_now())),
        )
    }

    /// 既定では対象ユーザーを所属元テナントの ACTIVE メンバーとして登録する（正常系の HOME 相当）。
    fn service(
        user: Option<User>,
        perms: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> PermissionManagementService {
        let active = user
            .as_ref()
            .map(|u| vec![(u.tenant_id, u.id)])
            .unwrap_or_default();
        service_with(
            user,
            Arc::new(FakeMemberships::with_active(active)),
            perms,
            sink,
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

    /// INVITED（未承諾）ゲスト等、当該テナントで ACTIVE なメンバーシップを持たない対象への付与は
    /// 不存在（404）に倒す（ADR-0009 §4。テナント越しの存在推測を防ぐ）。
    #[tokio::test]
    async fn grant_rejects_non_active_member() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        // ユーザーは現存するが、要求テナントの ACTIVE メンバー登録は無い（INVITED 相当）。
        let svc = service_with(
            Some(test_user(target)),
            Arc::new(FakeMemberships::default()),
            perms.clone(),
            sink.clone(),
        );

        assert!(matches!(
            svc.grant(tenant_ctx(), target, "idp.tenant.admin", actor, &ctx())
                .await,
            Err(PermissionManagementError::NotFound)
        ));
        // 失敗時は付与も監査記録も行わない。
        assert!(perms.granted.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
        // list/revoke も同じく 404。
        assert!(matches!(
            svc.list(tenant_ctx(), target).await,
            Err(PermissionManagementError::NotFound)
        ));
        assert!(matches!(
            svc.revoke(tenant_ctx(), target, "idp.tenant.admin", actor, &ctx())
                .await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    /// 他テナント所属のユーザーが要求テナントの ACTIVE メンバーでなければ 404 を維持する
    /// （テナント外の識別子推測を防ぐ）。
    #[tokio::test]
    async fn grant_rejects_user_from_other_tenant_without_membership() {
        let target = Uuid::new_v4();
        // 所属元（HOME）は別テナント。
        let other_tenant =
            TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_00FF));
        let mut guest = test_user(target);
        guest.tenant_id = other_tenant;
        let svc = service_with(
            Some(guest),
            // 要求テナント（test_tenant）でのメンバーシップは無い。
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );

        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                Uuid::new_v4(),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    /// 所属元が別テナントの GUEST でも、要求テナントで ACTIVE なメンバーであれば付与できる
    /// （出自で区別しない。ADR-0009 §4）。付与 scope は要求テナント。
    #[tokio::test]
    async fn grant_succeeds_for_active_guest_from_other_tenant() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let other_tenant =
            TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_00FF));
        let mut guest = test_user(target);
        guest.tenant_id = other_tenant;
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        // 要求テナント（test_tenant）で ACTIVE な GUEST メンバーとして登録する。
        let svc = service_with(
            Some(guest),
            Arc::new(FakeMemberships::with_active(vec![(test_tenant(), target)])),
            perms.clone(),
            sink.clone(),
        );

        let codes = svc
            .grant(tenant_ctx(), target, "idp.tenant.admin", actor, &ctx())
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.tenant.admin".to_string()]);
        // 付与 scope は要求テナント（所属元テナントではない）。
        assert_eq!(
            perms.granted.lock().unwrap().clone(),
            vec![(test_tenant(), target, "idp.tenant.admin".to_string())]
        );
    }
}
