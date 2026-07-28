//! SSO セッションの復元（サイレント再認証）。
//!
//! OIDC の認可フロー再開（[`crate::application::authorize`]）と SAML SSO
//! （[`crate::application::saml_sso`]）が同じ判定を共有する:
//! 有効期限 → ユーザー有効性 → **要求テナントの ACTIVE メンバーシップ**（ADR-0009 §8）の順に
//! 検証し、成功時は idle 期限を延長して `sso_session.resumed` を監査記録する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 復元に成功した SSO セッション。
pub struct RestoredSso {
    pub user_id: Uuid,
    /// 初回ログイン時刻（`auth_time`。復元では更新しない）。
    pub auth_time: DateTime<Utc>,
    /// セッションの SHA-256（Cookie 生値は含まない）。SAML の `SessionIndex` 等、
    /// セッションを不透明に参照する用途に使える。
    pub session_hash: String,
}

pub struct SsoRestorer {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
}

impl SsoRestorer {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            memberships,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
        }
    }

    /// SSO セッションの復元を試みる。有効なら idle 期限を延長して [`RestoredSso`] を返す。
    /// 期限切れは削除して `sso_session.expired` を監査ログへ記録する。
    pub async fn try_resume(
        &self,
        tenant: TenantContext,
        session_id: &str,
        ctx: &RequestContext,
    ) -> Result<Option<RestoredSso>, DomainError> {
        let session_hash = crypto::sha256_hex(session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(None);
        };

        let now = self.clock.now();
        if !session.is_valid_at(now) {
            self.sso_sessions.delete(&session_hash).await?;
            self.audit
                .record(
                    AuditEventType::SsoSessionExpired,
                    AuditResult::Failure,
                    Some(tenant.tenant_id()),
                    Some(session.user_id),
                    None,
                    Some("idle or absolute timeout"),
                    ctx,
                )
                .await;
            return Ok(None);
        }

        // ユーザーが無効化されていれば SSO 復元しない（再ログインで検出させる）。
        match self.users.find_by_id(session.user_id).await? {
            Some(user) if user.is_active() && !user.is_locked_at(now) => {}
            _ => return Ok(None),
        }

        // メンバーシップ判定（ADR-0009 §8）: SSO セッションはホスト単位で共有されるため、
        // ユーザーが**要求テナントの ACTIVE メンバーシップ（HOME または GUEST）を持つこと**を検証する。
        // メンバーシップのない SSO セッションは当該テナントのフローでは未認証として扱う（= ログインへ）。
        // ゲストは所属元テナントでログインしてこの SSO を確立し、参加先テナントではこの判定で許可される。
        if !self
            .memberships
            .is_active_member(tenant.tenant_id(), session.user_id)
            .await?
        {
            return Ok(None);
        }

        // idle 期限を更新（absolute は変更しない）。auth_time は初回ログイン時刻を維持する。
        self.sso_sessions
            .extend_idle(&session_hash, now + self.sso_idle_ttl)
            .await?;
        self.audit
            .record(
                AuditEventType::SsoSessionResumed,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(session.user_id),
                None,
                None,
                ctx,
            )
            .await;

        Ok(Some(RestoredSso {
            user_id: session.user_id,
            auth_time: session.auth_time,
            session_hash,
        }))
    }
}
