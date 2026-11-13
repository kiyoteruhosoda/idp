//! Use case: list the tenants a user belongs to (for the tenant switcher UI).
//!
//! Lists tenants where the logged-in user has an `ACTIVE` membership (HOME / GUEST).
//! The SSO session is shared per host (ADR-0009 §8), so switching only needs a move to the target
//! tenant's admin console; no re-login. Display names are resolved from the tenant row.

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, TenantRepository,
};
use std::sync::Arc;

/// One switchable tenant.
pub struct AccountTenant {
    pub tenant_id: String,
    pub name: String,
    /// Membership kind (`HOME` / `GUEST`).
    pub membership_type: String,
}

pub enum ListTenantsOutcome {
    Ok(Vec<AccountTenant>),
    /// No SSO session, or it has expired.
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

        // Resolve the user from the SSO session.
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

        // Resolve the tenant display name for each membership (few memberships, so N+1 is fine).
        // Skip memberships whose tenant row is missing (deletion race etc.) and `DISABLED` tenants.
        // `TenantResolutionService::resolve` rejects disabled tenants (the target would always 404),
        // so they are not offered for switching.
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
