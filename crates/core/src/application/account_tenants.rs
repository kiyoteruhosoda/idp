//! ユーザーの所属テナント列挙ユースケース（テナント切り替え UI 用）。
//!
//! ログイン済みユーザーが `ACTIVE` なメンバーシップ（HOME / GUEST）を持つテナントを列挙する。
//! SSO セッションはホスト単位で共有されるため（ADR-0009 §8）、切り替えは対象テナントの管理コンソール
//! へ遷移するだけでよく、再ログインは不要。表示名はテナント行から解決する。

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, TenantRepository,
};
use std::sync::Arc;

/// 切り替え可能なテナント 1 件。
pub struct AccountTenant {
    pub tenant_id: String,
    pub name: String,
    /// メンバーシップ種別（`HOME` / `GUEST`）。
    pub membership_type: String,
}

pub enum ListTenantsOutcome {
    Ok(Vec<AccountTenant>),
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    Internal(String),
}

pub struct AccountTenantsService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    tenants: Arc<dyn TenantRepository>,
    clock: Arc<dyn Clock>,
}

impl AccountTenantsService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        tenants: Arc<dyn TenantRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            memberships,
            tenants,
            clock,
        }
    }

    pub async fn list(&self, sso_session_id: &str) -> ListTenantsOutcome {
        let now = self.clock.now();

        // SSO セッションから本人を解決する。
        let session_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s.user_id,
            Ok(_) => return ListTenantsOutcome::SessionExpired,
            Err(e) => return ListTenantsOutcome::Internal(e.to_string()),
        };

        let memberships = match self.memberships.list_active_for_user(user_id).await {
            Ok(m) => m,
            Err(e) => return ListTenantsOutcome::Internal(e.to_string()),
        };

        // 各メンバーシップのテナント表示名を解決する（所属数は小さく N+1 は問題にならない）。
        // テナント行が見つからないメンバーシップ（削除競合等）や、`DISABLED` なテナントはスキップする。
        // 無効テナントは `TenantResolutionService::resolve` が拒否する（遷移先が常に 404 になる）ため、
        // 切り替え候補に出さない。
        let mut result = Vec::with_capacity(memberships.len());
        for m in memberships {
            match self.tenants.find_by_id(m.tenant_id).await {
                Ok(Some(tenant)) if tenant.is_active() => result.push(AccountTenant {
                    tenant_id: tenant.id.to_string(),
                    name: tenant.name,
                    membership_type: m.membership_type.as_str().to_string(),
                }),
                Ok(_) => continue,
                Err(e) => return ListTenantsOutcome::Internal(e.to_string()),
            }
        }

        ListTenantsOutcome::Ok(result)
    }
}
