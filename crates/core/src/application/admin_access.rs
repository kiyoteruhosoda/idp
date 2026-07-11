//! 管理機能のアクセス制御ユースケース（ADR-0006 §5）。
//!
//! SSO セッション Cookie の値から利用者を解決し、必要な**権限コード**を保有するかを判定する。
//! CLAUDE.md「権限管理」に従い、検証は本 Application 層で行い、Presentation には**結果（可否）のみ**
//! 渡す（Presentation は `RequirePerms` extractor で本サービスを呼ぶ）。
//!
//! 権限は「要求テナントを scope に持つか」の**完全一致**で判定する（ADR-0009 §4）。
//! `idp.system.admin` は root scope でしか存在できず（DB CHECK ＋アプリ層の二重防御）、
//! root テナント自身のテナント管理を含むため、要求権限に加えて常に代替として許可する。
//!
//! OIDC scope（claim 制御）とは別軸の判定であり、Discovery の `scopes_supported` には出さない。

use crate::domain::clock::Clock;
use crate::domain::repositories::{SsoSessionRepository, UserPermissionRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use std::sync::Arc;
use uuid::Uuid;

/// システム管理権限（scope = root のみ。ADR-0009 §4）。root テナント自身の管理を含む。
const SYSTEM_ADMIN_PERMISSION: &str = "idp.system.admin";

/// 管理機能へのアクセス判定結果。Presentation へは可否のみを渡す（内部理由は漏らさない）。
#[derive(Debug, PartialEq, Eq)]
pub enum AdminAccess {
    /// 認可済み。管理対象の操作を行ってよい。
    Granted(AuthorizedAdmin),
    /// 有効な SSO セッションが無い（未ログイン・期限切れ・不明セッション）→ 401 相当。
    Unauthenticated,
    /// ログイン済みだが必要権限を保有しない → 403 相当。
    Forbidden,
}

/// 認可された管理利用者（Presentation ハンドラへ注入される最小限の身元）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedAdmin {
    pub user_id: Uuid,
}

pub struct AdminAccessService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    clock: Arc<dyn Clock>,
}

impl AdminAccessService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            permissions,
            clock,
        }
    }

    /// SSO セッション Cookie の値（平文 session_id）と必要権限コードから可否を判定する。
    ///
    /// 権限は「要求テナント（`tenant`）を scope に持つか」の完全一致で判定する（ADR-0009 §4）。
    /// リポジトリ障害時は `Unauthenticated` に倒す（fail-closed）。認証・認可の失敗理由は
    /// 呼び出し側へ細分化して返さない（列挙は 401/403 の 2 値のみ）。
    pub async fn authorize(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
        required_permission: &str,
    ) -> AdminAccess {
        let Some(session_id) = sso_session_id.filter(|s| !s.is_empty()) else {
            return AdminAccess::Unauthenticated;
        };

        // Cookie は平文 session_id、DB にはその SHA-256 のみ（sso_session.rs と同じ導出）。
        let session_hash = crypto::sha256_hex(session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => session,
            Ok(None) => return AdminAccess::Unauthenticated,
            Err(e) => {
                tracing::error!(error = %e, "failed to load sso session for admin access");
                return AdminAccess::Unauthenticated;
            }
        };

        if !session.is_valid_at(self.clock.now()) {
            return AdminAccess::Unauthenticated;
        }

        // 利用者が現存し有効であること（無効化された管理者を締め出す）。
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => {}
            Ok(_) => return AdminAccess::Unauthenticated,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for admin access");
                return AdminAccess::Unauthenticated;
            }
        }

        // 要求権限、または idp.system.admin（root scope のみ存在。root 自身の管理を含む）の
        // いずれかを、要求テナントを scope として保有するか（完全一致）。
        let tenant_id = tenant.tenant_id();
        match self
            .permissions
            .has_permission(tenant_id, session.user_id, required_permission)
            .await
        {
            Ok(true) => {
                return AdminAccess::Granted(AuthorizedAdmin {
                    user_id: session.user_id,
                })
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(error = %e, "failed to check permission for admin access");
                return AdminAccess::Forbidden;
            }
        }
        if required_permission != SYSTEM_ADMIN_PERMISSION {
            match self
                .permissions
                .has_permission(tenant_id, session.user_id, SYSTEM_ADMIN_PERMISSION)
                .await
            {
                Ok(true) => {
                    return AdminAccess::Granted(AuthorizedAdmin {
                        user_id: session.user_id,
                    })
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(error = %e, "failed to check permission for admin access");
                }
            }
        }
        AdminAccess::Forbidden
    }

    /// SSO セッション Cookie から認証済み利用者の内部 ID を解決する（権限は問わない）。
    ///
    /// 招待の承諾（`POST /{tenant_id}/invitations/accept`。ADR-0009 §3）のように「ログイン済みである
    /// こと」だけを要求し、テナント権限を要求しないフローで使う。セッションが無効・利用者が無効・
    /// リポジトリ障害はいずれも `None`（未認証）に倒す（fail-closed）。本人性の最終確認（被招待者本人か）は
    /// 呼び出し側のユースケースがトークン照合で行う。
    pub async fn authenticated_user(&self, sso_session_id: Option<&str>) -> Option<Uuid> {
        let session_id = sso_session_id.filter(|s| !s.is_empty())?;
        let session_hash = crypto::sha256_hex(session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => session,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load sso session for authenticated user");
                return None;
            }
        };
        if !session.is_valid_at(self.clock.now()) {
            return None;
        }
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Some(session.user_id),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for authenticated user");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};

    const ADMIN_PERM: &str = "idp.tenant.admin";

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// テスト用に「Cookie 平文 → SHA-256 ハッシュ」を DB 保存相当に写した SSO セッション 1 件を保持する。
    struct FakeSsoSessions {
        session: Option<SsoSession>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, session_hash: &str) -> DomainResult<Option<SsoSession>> {
            Ok(self
                .session
                .clone()
                .filter(|s| s.session_hash == session_hash))
        }
        async fn extend_idle(&self, _h: &str, _e: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
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
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _u: &str) -> DomainResult<Option<User>> {
            unreachable!()
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

    struct FakePermissions {
        granted: Vec<(TenantId, Uuid, String)>,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec![ADMIN_PERM.to_string()])
        }
        async fn list_codes_for_user(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
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
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code))
        }
        async fn grant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn test_user(id: Uuid, tenant_id: TenantId, status: UserStatus) -> User {
        User {
            id,
            tenant_id,
            sub: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("admin".to_string()),
            name: Some("Administrator".to_string()),
            password_hash: "x".to_string(),
            must_change_password: false,
            status,
            failed_login_count: 0,
            locked_until: None,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn test_session(session_id: &str, user_id: Uuid, valid: bool) -> SsoSession {
        let now = fixed_now();
        let (idle, abs) = if valid {
            (now + Duration::minutes(30), now + Duration::hours(8))
        } else {
            (now - Duration::minutes(1), now + Duration::hours(8))
        };
        SsoSession {
            session_hash: crypto::sha256_hex(session_id),
            user_id,
            auth_time: now - Duration::minutes(5),
            idle_expires_at: idle,
            absolute_expires_at: abs,
            user_agent: None,
            ip_address: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn service(
        session: Option<SsoSession>,
        user: Option<User>,
        granted: Vec<(TenantId, Uuid, String)>,
    ) -> AdminAccessService {
        AdminAccessService::new(
            Arc::new(FakeSsoSessions { session }),
            Arc::new(FakeUsers { user }),
            Arc::new(FakePermissions { granted }),
            Arc::new(FixedClock(fixed_now())),
        )
    }

    #[tokio::test]
    async fn grants_when_session_valid_and_permission_held() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Granted(AuthorizedAdmin { user_id: uid })
        );
    }

    #[tokio::test]
    async fn grants_when_system_admin_held_for_the_tenant() {
        // idp.system.admin（scope = root）は root テナント自身の管理を含む（ADR-0009 §4）。
        let uid = Uuid::new_v4();
        let root: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, root, UserStatus::Active)),
            vec![(root, uid, SYSTEM_ADMIN_PERMISSION.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(root), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Granted(AuthorizedAdmin { user_id: uid })
        );
    }

    #[tokio::test]
    async fn unauthenticated_when_no_cookie() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(None, None, vec![]);
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), None, ADMIN_PERM)
                .await,
            AdminAccess::Unauthenticated
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some(""), ADMIN_PERM)
                .await,
            AdminAccess::Unauthenticated
        );
    }

    #[tokio::test]
    async fn unauthenticated_when_session_unknown_or_expired() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        // 別セッション ID（ハッシュ不一致）。
        let svc = service(
            Some(test_session("other", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Unauthenticated
        );

        // 期限切れセッション。
        let svc = service(
            Some(test_session("sid", uid, false)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Unauthenticated
        );
    }

    #[tokio::test]
    async fn unauthenticated_when_user_disabled() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Disabled)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Unauthenticated
        );
    }

    #[tokio::test]
    async fn forbidden_when_permission_missing_or_scoped_to_another_tenant() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![], // 権限なし
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Forbidden
        );

        // 他テナント scope の権限では完全一致せず 403（ADR-0009 §4）。
        let other: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, other, UserStatus::Active)),
            vec![(other, uid, ADMIN_PERM.to_string())],
        );
        assert_eq!(
            svc.authorize(TenantContext::new(tenant), Some("sid"), ADMIN_PERM)
                .await,
            AdminAccess::Forbidden
        );
    }
}
