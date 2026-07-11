//! 招待とメンバーシップのユースケース（ADR-0009 §3）。
//!
//! ユーザーが所属元以外のテナントに参加する唯一の経路は**招待**（Entra ID の B2B ゲストに相当）。
//! 参加先テナントの管理者が招待を作成すると、一度限りの**招待トークン**をレスポンスで返す
//! （`generated_password` と同じ「一度だけ返し、管理者が別途本人へ通知する」パターン。トークンは
//! ハッシュのみ保存し、ログ・監査ログに出力しない）。被招待者は**所属元テナントでログイン済みの
//! セッション**で承諾エンドポイントにトークンを提示し、メンバーシップが `ACTIVE` になる。本人性は
//! トークンの所持とログイン済みセッションで確認する。
//!
//! 参加先テナントの管理者がゲストに対して行えるのは「メンバーシップの解除」と「参加先テナントを
//! scope とする権限の付与・剥奪」のみで、ゲストの `users` レコード（パスワード・状態・MFA・
//! プロフィール）は操作できない（それは所属元テナントの管理者と本人のみ。§3）。判定・検証は本
//! Application 層で完結し、Presentation には結果のみ返す（CLAUDE.md「権限管理」）。HTTP
//! エンドポイント（`/{tenant_id}/admin/invitations`・`/{tenant_id}/invitations/accept`・
//! `/{tenant_id}/admin/members/{user_id}`）は MT11 で presentation に追加する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::repositories::{
    TenantMembershipRepository, UserPermissionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::values::{MembershipStatus, MembershipType};
use crate::infrastructure::crypto;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    #[error("not found")]
    NotFound,
    /// 既に当該テナントのメンバー（HOME/GUEST/INVITED）である。
    #[error("already a member")]
    AlreadyMember,
    /// 承諾者が被招待ユーザー本人でない／HOME は解除できない等。
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// 招待トークンが無効・期限切れ。
    #[error("invalid or expired invitation")]
    InvalidOrExpired,
    #[error("internal error: {0}")]
    Internal(String),
}

/// 招待作成の結果。`token` は平文の招待トークンで、**この一度だけ**返す（保存はハッシュのみ）。
pub struct CreatedInvitation {
    /// 平文の招待トークン。管理者が被招待者へ別途通知する（ログ・監査には出さない）。
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// メンバー一覧の 1 件（`GET /{tenant_id}/admin/members`）。HOME / GUEST を問わず、当該テナントに
/// 参加している利用者を表す。email / name は表示用に所属元照合なしで解決する（招待作成は内部 ID で
/// 行うため、参加先管理者が被招待者を識別できるよう最小限の情報のみ返す）。
pub struct TenantMember {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub name: Option<String>,
    pub membership_type: MembershipType,
    pub status: MembershipStatus,
}

/// 招待トークンのバイト長（base64url で 43 文字程度）。
const INVITATION_TOKEN_BYTES: usize = 32;

pub struct InvitationService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    invitation_ttl: chrono::Duration,
}

impl InvitationService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        invitation_ttl: std::time::Duration,
    ) -> Self {
        Self {
            users,
            memberships,
            permissions,
            audit,
            clock,
            invitation_ttl: chrono::Duration::from_std(invitation_ttl)
                .expect("invitation TTL out of range"),
        }
    }

    /// 参加先テナント（`host`）へゲスト招待を作成する。被招待ユーザーは既存ユーザー（所属元は他
    /// テナント）でなければならない。既にメンバー（HOME/GUEST/INVITED）なら `AlreadyMember`。
    /// 平文トークンを**一度だけ**返す（保存はハッシュのみ）。
    pub async fn create_invitation(
        &self,
        host: TenantContext,
        target_user_id: Uuid,
        invited_by: Uuid,
        ctx: &RequestContext,
    ) -> Result<CreatedInvitation, InvitationError> {
        let host_id = host.tenant_id();

        // 被招待ユーザーが実在すること（グローバル一意 ID で解決）。所属元が host のユーザーは既に
        // HOME メンバーであり、下の membership 存在チェックで `AlreadyMember` に倒れる。
        match self.users.find_by_id(target_user_id).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(InvitationError::NotFound),
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        }

        // 既存メンバーシップ（HOME/GUEST/INVITED）があれば二重招待しない。
        match self.memberships.find(host_id, target_user_id).await {
            Ok(Some(_)) => return Err(InvitationError::AlreadyMember),
            Ok(None) => {}
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        }

        let now = self.clock.now();
        let token = crypto::random_token(INVITATION_TOKEN_BYTES);
        let expires_at = now + self.invitation_ttl;
        let membership = TenantMembership {
            tenant_id: host_id,
            user_id: target_user_id,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Invited,
            invited_by: Some(invited_by),
            invitation_token_hash: Some(crypto::sha256_hex(&token)),
            invitation_expires_at: Some(expires_at),
            created_at: now,
            updated_at: now,
        };
        self.memberships
            .create(&membership)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        // 監査には被招待者の内部 ID のみ記録する（招待トークンは出さない。§3）。
        self.audit
            .record(
                AuditEventType::TenantInvitationCreated,
                AuditResult::Success,
                Some(host_id),
                Some(invited_by),
                None,
                Some(&format!("invitee={target_user_id}")),
                ctx,
            )
            .await;

        Ok(CreatedInvitation { token, expires_at })
    }

    /// 当該テナントのメンバー（HOME / GUEST）を一覧する（§3・§6）。各メンバーの email / name は
    /// 表示用に解決する（不存在ユーザーは email / name を `None` とする）。
    pub async fn list_members(
        &self,
        host: TenantContext,
    ) -> Result<Vec<TenantMember>, InvitationError> {
        let memberships = self
            .memberships
            .list_for_tenant(host.tenant_id())
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;
        let mut members = Vec::with_capacity(memberships.len());
        for m in memberships {
            let user = self
                .users
                .find_by_id(m.user_id)
                .await
                .map_err(|e| InvitationError::Internal(e.to_string()))?;
            members.push(TenantMember {
                user_id: m.user_id,
                email: user.as_ref().map(|u| u.email.clone()),
                name: user.as_ref().and_then(|u| u.name.clone()),
                membership_type: m.membership_type,
                status: m.status,
            });
        }
        Ok(members)
    }

    /// 招待を承諾する。承諾者は**所属元テナントでログイン済み**のユーザー（`session_user_id`）で、
    /// トークンを提示する。本人性はトークンの所持 + ログイン済みセッションで確認する（§3）。
    /// トークンが当該テナント（`tenant`）の招待でない／期限切れ／不存在は一律 `InvalidOrExpired`、
    /// 承諾者が被招待者本人でなければ `Forbidden`。
    pub async fn accept_invitation(
        &self,
        tenant: TenantContext,
        session_user_id: Uuid,
        token: &str,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        if token.is_empty() {
            return Err(InvitationError::InvalidOrExpired);
        }
        let token_hash = crypto::sha256_hex(token);
        let membership = match self
            .memberships
            .find_by_invitation_token_hash(&token_hash)
            .await
        {
            Ok(Some(m)) => m,
            Ok(None) => return Err(InvitationError::InvalidOrExpired),
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        };

        // トークンは当該テナントの招待でなければならない（別テナントの承諾エンドポイントで使わせない）。
        if membership.tenant_id != tenant.tenant_id() {
            return Err(InvitationError::InvalidOrExpired);
        }
        // 承諾者は被招待ユーザー本人であること（ログイン済みセッションで確認。§3）。
        if membership.user_id != session_user_id {
            return Err(InvitationError::Forbidden(
                "only the invited user may accept this invitation".to_string(),
            ));
        }
        // 期限切れは承諾不可（INVITED のまま）。
        let now = self.clock.now();
        match membership.invitation_expires_at {
            Some(exp) if exp > now => {}
            _ => return Err(InvitationError::InvalidOrExpired),
        }

        self.memberships
            .activate(tenant.tenant_id(), session_user_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantInvitationAccepted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(session_user_id),
                None,
                None,
                ctx,
            )
            .await;

        Ok(())
    }

    /// ゲストメンバーシップを解除する（ゲストの追放。§3）。HOME は解除できない（`Forbidden`）。
    /// 解除時、当該テナントを scope とするそのユーザーの権限行も削除する（§3）。
    pub async fn revoke_membership(
        &self,
        host: TenantContext,
        target_user_id: Uuid,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), InvitationError> {
        let host_id = host.tenant_id();
        let membership = match self.memberships.find(host_id, target_user_id).await {
            Ok(Some(m)) => m,
            Ok(None) => return Err(InvitationError::NotFound),
            Err(e) => return Err(InvitationError::Internal(e.to_string())),
        };
        if membership.is_home() {
            return Err(InvitationError::Forbidden(
                "home membership cannot be revoked".to_string(),
            ));
        }

        self.memberships
            .delete(host_id, target_user_id)
            .await
            .map_err(|e| InvitationError::Internal(e.to_string()))?;

        // 当該テナントを scope とする権限行を削除する（§3）。付与済みコードを列挙して個別に剥奪する
        // （各剥奪は権限キャッシュも invalidate される）。
        match self
            .permissions
            .list_codes_for_user(host_id, target_user_id)
            .await
        {
            Ok(codes) => {
                for code in codes {
                    if let Err(e) = self.permissions.revoke(host_id, target_user_id, &code).await {
                        tracing::error!(error = %e, "failed to revoke tenant-scoped permission on membership removal");
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to list permissions on membership removal");
            }
        }

        self.audit
            .record(
                AuditEventType::TenantMembershipRevoked,
                AuditResult::Success,
                Some(host_id),
                Some(actor),
                None,
                Some(&format!("member={target_user_id}")),
                ctx,
            )
            .await;

        Ok(())
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
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
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

    #[derive(Default)]
    struct FakeMemberships {
        rows: Mutex<Vec<TenantMembership>>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn create(&self, membership: &TenantMembership) -> DomainResult<()> {
            self.rows.lock().unwrap().push(membership.clone());
            Ok(())
        }
        async fn find(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Option<TenantMembership>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
                .cloned())
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
        async fn find_by_invitation_token_hash(
            &self,
            token_hash: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|m| {
                    m.status == MembershipStatus::Invited
                        && m.invitation_token_hash.as_deref() == Some(token_hash)
                })
                .cloned())
        }
        async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(m) = rows
                .iter_mut()
                .find(|m| m.tenant_id == tenant_id && m.user_id == user_id)
            {
                m.status = MembershipStatus::Active;
                m.invitation_token_hash = None;
                m.invitation_expires_at = None;
            }
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|m| !(m.tenant_id == tenant_id && m.user_id == user_id));
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
            Ok(vec![])
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
            _t: TenantId,
            _u: Uuid,
            _c: &str,
        ) -> DomainResult<bool> {
            unreachable!()
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
        async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> DomainResult<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(t, u, c)| !(*t == tenant_id && *u == user_id && c == code));
            Ok(())
        }
    }

    fn test_user(id: Uuid, home: TenantId) -> User {
        User {
            id,
            tenant_id: home,
            sub: Uuid::new_v4(),
            email: "guest@other.example.com".to_string(),
            email_verified: true,
            preferred_username: Some("guest".to_string()),
            name: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
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
        memberships: Arc<FakeMemberships>,
        permissions: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> InvitationService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(now()))));
        InvitationService::new(
            Arc::new(FakeUsers { user }),
            memberships,
            permissions,
            audit,
            Arc::new(FixedClock(now())),
            std::time::Duration::from_secs(3600),
        )
    }

    #[tokio::test]
    async fn create_then_accept_activates_membership() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let admin = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            sink.clone(),
        );

        let created = svc
            .create_invitation(TenantContext::new(host), guest, admin, &ctx())
            .await
            .expect("invitation created");
        assert!(!created.token.is_empty());
        // 保存されるのはハッシュのみ（平文は保持しない）。
        let stored_hash = memberships.rows.lock().unwrap()[0]
            .invitation_token_hash
            .clone()
            .unwrap();
        assert_eq!(stored_hash, crypto::sha256_hex(&created.token));
        assert_ne!(stored_hash, created.token);

        // 被招待者本人がトークンを提示して承諾 → ACTIVE。
        svc.accept_invitation(TenantContext::new(host), guest, &created.token, &ctx())
            .await
            .expect("accepted");
        let row = memberships.rows.lock().unwrap()[0].clone();
        assert_eq!(row.status, MembershipStatus::Active);
        assert!(row.invitation_token_hash.is_none());

        let kinds: Vec<_> = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type)
            .collect();
        assert_eq!(
            kinds,
            vec![
                AuditEventType::TenantInvitationCreated,
                AuditEventType::TenantInvitationAccepted
            ]
        );
        // 監査に招待トークンが漏れていない。
        assert!(sink.events.lock().unwrap().iter().all(|e| {
            e.reason
                .as_deref()
                .map(|r| !r.contains(&created.token))
                .unwrap_or(true)
        }));
    }

    #[tokio::test]
    async fn create_rejects_existing_member() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_home(host, guest, now()));
        let svc = service(
            Some(test_user(guest, home)),
            memberships,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_invitation(TenantContext::new(host), guest, Uuid::new_v4(), &ctx())
                .await,
            Err(InvitationError::AlreadyMember)
        ));
    }

    #[tokio::test]
    async fn create_rejects_unknown_user() {
        let host: TenantId = Uuid::now_v7().into();
        let svc = service(
            None,
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_invitation(TenantContext::new(host), Uuid::new_v4(), Uuid::new_v4(), &ctx())
                .await,
            Err(InvitationError::NotFound)
        ));
    }

    #[tokio::test]
    async fn accept_requires_the_invited_user() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        let svc = service(
            Some(test_user(guest, home)),
            memberships,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        let created = svc
            .create_invitation(TenantContext::new(host), guest, Uuid::new_v4(), &ctx())
            .await
            .unwrap();

        // 別ユーザーのセッションでは承諾できない。
        assert!(matches!(
            svc.accept_invitation(TenantContext::new(host), Uuid::new_v4(), &created.token, &ctx())
                .await,
            Err(InvitationError::Forbidden(_))
        ));
        // トークンが別テナントの承諾経路で提示された場合も拒否。
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            svc.accept_invitation(TenantContext::new(other), guest, &created.token, &ctx())
                .await,
            Err(InvitationError::InvalidOrExpired)
        ));
    }

    #[tokio::test]
    async fn accept_rejects_expired_token() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        // TTL 0 の service で期限切れを作る。
        let audit = Arc::new(AuditService::new(
            Arc::new(CapturingSink::default()),
            Arc::new(FixedClock(now())),
        ));
        let svc = InvitationService::new(
            Arc::new(FakeUsers {
                user: Some(test_user(guest, home)),
            }),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            audit,
            Arc::new(FixedClock(now())),
            std::time::Duration::from_secs(0),
        );
        let created = svc
            .create_invitation(TenantContext::new(host), guest, Uuid::new_v4(), &ctx())
            .await
            .unwrap();
        // expires_at == now（`> now` ではない）→ 期限切れ扱い。
        assert!(matches!(
            svc.accept_invitation(TenantContext::new(host), guest, &created.token, &ctx())
                .await,
            Err(InvitationError::InvalidOrExpired)
        ));
    }

    #[tokio::test]
    async fn revoke_removes_guest_and_scoped_permissions() {
        let host: TenantId = Uuid::now_v7().into();
        let home: TenantId = Uuid::now_v7().into();
        let guest = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships.rows.lock().unwrap().push(TenantMembership {
            tenant_id: host,
            user_id: guest,
            membership_type: MembershipType::Guest,
            status: MembershipStatus::Active,
            invited_by: None,
            invitation_token_hash: None,
            invitation_expires_at: None,
            created_at: now(),
            updated_at: now(),
        });
        let permissions = Arc::new(FakePermissions::default());
        permissions
            .granted
            .lock()
            .unwrap()
            .push((host, guest, "idp.tenant.admin".to_string()));
        // 別テナント scope の権限は残す。
        let other: TenantId = Uuid::now_v7().into();
        permissions
            .granted
            .lock()
            .unwrap()
            .push((other, guest, "idp.tenant.admin".to_string()));
        let svc = service(
            Some(test_user(guest, home)),
            memberships.clone(),
            permissions.clone(),
            Arc::new(CapturingSink::default()),
        );

        svc.revoke_membership(TenantContext::new(host), guest, Uuid::new_v4(), &ctx())
            .await
            .expect("revoked");
        assert!(memberships.rows.lock().unwrap().is_empty());
        // host scope の権限は消え、other scope は残る。
        let remaining = permissions.granted.lock().unwrap().clone();
        assert_eq!(remaining, vec![(other, guest, "idp.tenant.admin".to_string())]);
    }

    #[tokio::test]
    async fn revoke_forbids_home_membership() {
        let host: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let memberships = Arc::new(FakeMemberships::default());
        memberships
            .rows
            .lock()
            .unwrap()
            .push(TenantMembership::new_home(host, user, now()));
        let svc = service(
            Some(test_user(user, host)),
            memberships.clone(),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.revoke_membership(TenantContext::new(host), user, Uuid::new_v4(), &ctx())
                .await,
            Err(InvitationError::Forbidden(_))
        ));
        // HOME は残る。
        assert_eq!(memberships.rows.lock().unwrap().len(), 1);
    }
}
