//! 利用者権限（permission code）の付与・剥奪ユースケース（ADR-0006、Progress A2）。
//!
//! 管理者（`idp.admin`）のみが実行する。判定・検証は本 Application 層で完結し、Presentation には
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
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum PermissionManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

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

    /// 対象利用者を内部 ID で取得する（管理コンソールの表示用）。不存在は 404 相当。
    pub async fn get_user(&self, target: Uuid) -> Result<User, PermissionManagementError> {
        match self.users.find_by_id(target).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(PermissionManagementError::NotFound),
            Err(e) => Err(PermissionManagementError::Internal(e.to_string())),
        }
    }

    /// 識別子（メールアドレスまたはユーザー名）で利用者を探す（管理コンソールの検索用）。
    /// `@` を含めばメール、そうでなければユーザー名として解決する。空文字列は None を返す。
    pub async fn find_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<User>, PermissionManagementError> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return Ok(None);
        }
        let result = if identifier.contains('@') {
            self.users.find_by_email(identifier).await
        } else {
            self.users.find_by_username(identifier).await
        };
        result.map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// 対象利用者が保有する権限コード一覧を返す（順序は不定）。
    pub async fn list(&self, target: Uuid) -> Result<Vec<String>, PermissionManagementError> {
        self.ensure_user_exists(target).await?;
        self.permissions
            .list_codes_for_user(target)
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// 対象利用者へ権限コードを付与する（冪等）。付与後の保有コード一覧を返す。
    pub async fn grant(
        &self,
        target: Uuid,
        code: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code)
            .map_err(|e| PermissionManagementError::Validation(e.to_string()))?;
        self.ensure_user_exists(target).await?;

        self.permissions
            .grant(target, code.as_str(), self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionGranted,
                AuditResult::Success,
                Some(actor),
                None,
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(target).await
    }

    /// 対象利用者から権限コードを剥奪する（未保有でもエラーにしない）。剥奪後の保有コード一覧を返す。
    pub async fn revoke(
        &self,
        target: Uuid,
        code: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code)
            .map_err(|e| PermissionManagementError::Validation(e.to_string()))?;
        self.ensure_user_exists(target).await?;

        self.permissions
            .revoke(target, code.as_str())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionRevoked,
                AuditResult::Success,
                Some(actor),
                None,
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(target).await
    }

    /// 対象利用者が現存することを確かめる（不存在は 404 相当）。
    async fn ensure_user_exists(&self, target: Uuid) -> Result<(), PermissionManagementError> {
        match self.users.find_by_id(target).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(PermissionManagementError::NotFound),
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
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap()
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
        async fn find_by_email(&self, email: &str) -> DomainResult<Option<User>> {
            Ok(self.user.clone().filter(|u| u.email == email))
        }
        async fn find_by_username(&self, username: &str) -> DomainResult<Option<User>> {
            Ok(self
                .user
                .clone()
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
    }

    /// 付与/剥奪の呼び出しを記録し、保有状態を保持するフェイク。
    #[derive(Default)]
    struct FakePermissions {
        granted: Mutex<Vec<(Uuid, String)>>,
        reject_unknown: bool,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec!["idp.admin".to_string()])
        }
        async fn list_codes_for_user(&self, user_id: Uuid) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(u, _)| *u == user_id)
                .map(|(_, c)| c.clone())
                .collect())
        }
        async fn has_permission(&self, _u: Uuid, _c: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn grant(&self, user_id: Uuid, code: &str, _g: DateTime<Utc>) -> DomainResult<()> {
            if self.reject_unknown {
                return Err(DomainError::InvalidValue(format!(
                    "unknown permission code or user: {code}"
                )));
            }
            let mut g = self.granted.lock().unwrap();
            if !g.iter().any(|(u, c)| *u == user_id && c == code) {
                g.push((user_id, code.to_string()));
            }
            Ok(())
        }
        async fn revoke(&self, user_id: Uuid, code: &str) -> DomainResult<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(u, c)| !(*u == user_id && c == code));
            Ok(())
        }
    }

    fn test_user(id: Uuid) -> User {
        User {
            id,
            sub: Uuid::new_v4(),
            email: "target@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("target".to_string()),
            name: None,
            password_hash: "x".to_string(),
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
            .grant(target, "idp.admin", actor, &ctx())
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.admin".to_string()]);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserPermissionGranted);
        assert_eq!(events[0].user_id, Some(actor));
        assert!(events[0].reason.as_deref().unwrap().contains("idp.admin"));
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
            .push((target, "idp.admin".to_string()));
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        let codes = svc
            .revoke(target, "idp.admin", actor, &ctx())
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
            svc.grant(target, "  ", Uuid::new_v4(), &ctx()).await,
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
            svc.grant(target, "idp.unknown", Uuid::new_v4(), &ctx())
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
            .find_user_by_identifier("target@example.com")
            .await
            .expect("lookup ok");
        assert_eq!(by_email.map(|u| u.id), Some(target));
        let by_username = svc
            .find_user_by_identifier("  target  ")
            .await
            .expect("lookup ok");
        assert_eq!(by_username.map(|u| u.id), Some(target));
        // 未知の識別子・空文字列は None。
        assert!(svc
            .find_user_by_identifier("nobody@example.com")
            .await
            .expect("lookup ok")
            .is_none());
        assert!(svc
            .find_user_by_identifier("   ")
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
            vec!["idp.admin".to_string()]
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
            svc.get_user(Uuid::new_v4()).await,
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
            svc.grant(Uuid::new_v4(), "idp.admin", Uuid::new_v4(), &ctx())
                .await,
            Err(PermissionManagementError::NotFound)
        ));
        assert!(matches!(
            svc.list(Uuid::new_v4()).await,
            Err(PermissionManagementError::NotFound)
        ));
    }
}
