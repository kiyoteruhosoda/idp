//! 管理機能のアクセス制御ユースケース（ADR-0006 §5 / ADR-0037）。
//!
//! SSO セッション Cookie の値から利用者を解決し、**要求テナントで保有する権限コード**を返す。
//! CLAUDE.md「権限管理」に従い、権限の解決は本 Application 層で行い、Presentation には結果のみ
//! 渡す。ADR-0037 以降、管理 API の認可判定そのものは管理トークン（`ManagementTokenService`）が
//! 担い、本サービスは**その原資となる権限コードの解決**を担当する。
//!
//! 解決は 2 段構えで、**要求テナントで `ACTIVE` なメンバーシップを持つこと**（MT24）と
//! **要求テナントを scope として保有する権限コード**の両方を見る。前者が必要なのは、ゲストの
//! 一時停止（`SUSPENDED`）が権限行を残す可逆な操作であり、権限だけを見る判定では停止が効かないため。
//! 停止中は「権限コード 0 件」として解決する（＝管理トークンは出るが何も通らない）。
//!
//! 権限は「要求テナントを scope に持つか」の**完全一致**で取得する（ADR-0009 §4）。コード同士の
//! 含意（`idp.tenant.admin` が細粒度コードを含む等）は `domain::permission` が単一の出所として持つ。
//!
//! OIDC scope（claim 制御）とは別軸の判定であり、Discovery の `scopes_supported` には出さない。

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, UserPermissionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

/// SSO セッションから解決した「主体 + 要求テナントで保有する権限コード」（ADR-0037）。
///
/// 管理トークンの発行原資。権限コードが空でも返る（＝ログイン済みだが権限が無い）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementGrant {
    pub user_id: Uuid,
    /// 表示名（未設定なら `None`）。管理コンソールのヘッダ表示に使う。
    pub name: Option<String>,
    /// ログイン識別子（未設定なら `None`）。
    pub preferred_username: Option<String>,
    /// 要求テナントを scope として保有する権限コード（順序は不定。不保有なら空）。
    pub permission_codes: Vec<String>,
}

pub struct AdminAccessService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    clock: Arc<dyn Clock>,
}

impl AdminAccessService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            permissions,
            memberships,
            clock,
        }
    }

    /// SSO セッション Cookie の値（平文 session_id）から、主体と要求テナントでの保有権限を解決する。
    ///
    /// セッションが無効・利用者が無効・リポジトリ障害はいずれも `None`（fail-closed = 未認証扱い）。
    /// **メンバーシップが `ACTIVE` でない場合や権限を 1 つも持たない場合は `Some`（権限コードは空）**
    /// を返す。「未認証」と「権限不足」は呼び出し側が 401 / 403 へ writeし分ける必要があり、
    /// ここで両者を潰すと管理コンソールがログイン画面へ戻す判断をできなくなる。
    pub async fn resolve_session_grant(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
    ) -> Option<ManagementGrant> {
        let user = self.resolve_session_user(sso_session_id).await?;
        let tenant_id = tenant.tenant_id();

        // 要求テナントで **ACTIVE なメンバーシップ**を持つこと（MT24）。権限行だけを見ると、
        // ゲストを一時停止（`SUSPENDED`）しても権限行が残るため管理操作が通ってしまう。
        // 一時停止は可逆であることが要件で権限行を消せないので、停止の実効性はこの判定が担う。
        let active_member = match self.memberships.is_active_member(tenant_id, user.id).await {
            Ok(active) => active,
            Err(e) => {
                tracing::error!(error = %e, "failed to check tenant membership for admin access");
                false
            }
        };

        let permission_codes = if active_member {
            match self
                .permissions
                .list_codes_for_user(tenant_id, user.id)
                .await
            {
                Ok(codes) => codes,
                Err(e) => {
                    tracing::error!(error = %e, "failed to load permissions for admin access");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        Some(ManagementGrant {
            user_id: user.id,
            name: user.name.clone(),
            preferred_username: user.preferred_username.clone(),
            permission_codes,
        })
    }

    /// SSO セッション Cookie から認証済み利用者の内部 ID を解決する（権限は問わない）。
    ///
    /// 招待の承諾（`POST /{tenant_id}/invitations/accept`。ADR-0009 §3）のように「ログイン済みである
    /// こと」だけを要求し、テナント権限を要求しないフローで使う。セッションが無効・利用者が無効・
    /// リポジトリ障害はいずれも `None`（未認証）に倒す（fail-closed）。本人性の最終確認（被招待者本人か）は
    /// 呼び出し側のユースケースがトークン照合で行う。
    pub async fn authenticated_user(&self, sso_session_id: Option<&str>) -> Option<Uuid> {
        self.resolve_session_user(sso_session_id)
            .await
            .map(|user| user.id)
    }

    /// Cookie 平文 session_id → SSO セッション取得 → 有効性検証 → ユーザー有効性確認 の
    /// 共通フロー（REF3）。いずれかの段階で失敗したら `None`（fail-closed）。有効なら
    /// 解決したユーザー行を返す（呼び出し側が id・表示名等を利用する。追加クエリを避けるため）。
    async fn resolve_session_user(&self, sso_session_id: Option<&str>) -> Option<User> {
        let session_id = sso_session_id.filter(|s| !s.is_empty())?;

        // Cookie は平文 session_id、DB にはその SHA-256 のみ（sso_session.rs と同じ導出）。
        let session_hash = crypto::sha256_hex(session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => session,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load sso session");
                return None;
            }
        };

        if !session.is_valid_at(self.clock.now()) {
            return None;
        }

        // 利用者が現存し有効であること（無効化された管理者を締め出す）。
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Some(user),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for sso session");
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
    use crate::domain::tenant_membership::TenantMembership;
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
        /// このテストはログイン失敗経路を通らない（SEC13 の検証は login / mfa_login にある）。
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
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
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
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
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
        ) -> DomainResult<Vec<String>> {
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
            language: None,
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
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
            authentication_methods: vec![crate::domain::values::AuthenticationMethod::Password],
            authentication_strength: crate::domain::values::AuthenticationStrength::SingleFactor,
            mfa_completed_at: None,
            step_up_at: Some(now),
            user_agent: None,
            ip_address: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// メンバーシップの有無を切り替えられるフェイク（MT24 の ACTIVE メンバーシップ要求の検証用）。
    struct FakeMemberships {
        active: bool,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            Ok(self.active)
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
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn service(
        session: Option<SsoSession>,
        user: Option<User>,
        granted: Vec<(TenantId, Uuid, String)>,
    ) -> AdminAccessService {
        service_with_membership(session, user, granted, true)
    }

    fn service_with_membership(
        session: Option<SsoSession>,
        user: Option<User>,
        granted: Vec<(TenantId, Uuid, String)>,
        active_member: bool,
    ) -> AdminAccessService {
        AdminAccessService::new(
            Arc::new(FakeSsoSessions { session }),
            Arc::new(FakeUsers { user }),
            Arc::new(FakePermissions { granted }),
            Arc::new(FakeMemberships {
                active: active_member,
            }),
            Arc::new(FixedClock(fixed_now())),
        )
    }

    /// MT24: 権限を持っていても、要求テナントで ACTIVE なメンバーシップが無ければ権限は 0 件。
    /// ゲストの一時停止（`SUSPENDED`）は権限行を残す可逆な操作なので、ここで落とさないと
    /// 停止したゲストが管理トークンで操作を続けられてしまう。
    #[tokio::test]
    async fn resolves_no_permissions_when_membership_is_not_active() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service_with_membership(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
            false,
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .expect("session is valid, so the principal resolves");
        assert_eq!(grant.user_id, uid);
        assert!(grant.permission_codes.is_empty());
    }

    #[tokio::test]
    async fn resolves_the_permissions_held_for_the_requested_tenant() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .unwrap();
        assert_eq!(
            grant,
            ManagementGrant {
                user_id: uid,
                name: Some("Administrator".to_string()),
                preferred_username: Some("admin".to_string()),
                permission_codes: vec![ADMIN_PERM.to_string()],
            }
        );
    }

    #[tokio::test]
    async fn unauthenticated_when_no_cookie() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(None, None, vec![]);
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), None)
            .await
            .is_none());
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some(""))
            .await
            .is_none());
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
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());

        // 期限切れセッション。
        let svc = service(
            Some(test_session("sid", uid, false)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());
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
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());
    }

    /// 他テナント scope の権限は要求テナントでは 1 件も解決しない（ADR-0009 §4 の完全一致）。
    #[tokio::test]
    async fn permissions_scoped_to_another_tenant_do_not_resolve() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, other, UserStatus::Active)),
            vec![(other, uid, ADMIN_PERM.to_string())],
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .unwrap();
        assert!(grant.permission_codes.is_empty());
    }
}
