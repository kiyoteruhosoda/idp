//! Protects admin accounts and admin permissions from holders of fine-grained codes (task #579; ADR-0037's promise).
//!
//! Fine-grained codes (`idp.users:write` etc.) are for "division of work within a tenant", and the
//! promise is that collecting them never reaches `idp.tenant.admin` / `idp.system.admin`. But each
//! route only checked "does the caller hold this route's code", so the promise was broken in two ways.
//!
//! - **Account operations**: `idp.users:write` alone could reissue an admin's password or reset MFA,
//!   and the returned setup link allowed impersonation
//! - **Granting permissions**: `idp.permissions:write` / `idp.clients:write` alone could attach codes the
//!   caller did not hold (`idp.tenant.admin` etc.) to anyone
//!
//! This service is "one more layer" called before each route; the decision itself has a single source in
//! `domain::permission`'s [`permission::may_assign`] / [`permission::may_manage_account`].
//! The caller's held codes are the admin token's `perms` (the same input as the `RequirePerms` check).

use crate::domain::account::AccountRef;
use crate::domain::permission::{self, HeldByTarget, TargetScope};
use crate::domain::repositories::{
    ApplicationRepository, ClientPermissionRepository, ClientRepository, TenantRepository,
    UserPermissionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AdminAccountGuardError {
    /// Tried to touch an account or permission stronger than the caller.
    #[error("forbidden")]
    Forbidden,
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct AdminAccountGuard {
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    clients: Arc<dyn ClientRepository>,
    client_permissions: Arc<dyn ClientPermissionRepository>,
    tenants: Arc<dyn TenantRepository>,
    applications: Arc<dyn ApplicationRepository>,
}

impl AdminAccountGuard {
    pub fn new(
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        clients: Arc<dyn ClientRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        tenants: Arc<dyn TenantRepository>,
        applications: Arc<dyn ApplicationRepository>,
    ) -> Self {
        Self {
            users,
            permissions,
            clients,
            client_permissions,
            tenants,
            applications,
        }
    }

    /// Call before granting or revoking permission code `code` (to users and to clients).
    ///
    /// Revocation uses the same decision: if codes the caller lacks could be removed, a fine-grained code
    /// holder could remove `idp.tenant.admin` from an admin and lock them out.
    pub fn ensure_may_assign(
        &self,
        held: &[String],
        code: &str,
        tenant_is_root: bool,
    ) -> Result<(), AdminAccountGuardError> {
        // The rule that only holders may handle `idp.system.admin` lives in the grant itself, which also
        // distinguishes the reasons (`PermissionManagementService::ensure_system_admin_change_allowed`; it can
        // never be attached to clients). Rejecting here first would keep that distinction from being reached.
        if code == permission::SYSTEM_ADMIN || permission::may_assign(held, code, tenant_is_root) {
            Ok(())
        } else {
            Err(AdminAccountGuardError::Forbidden)
        }
    }

    /// Call before account operations (reissuing password/MFA, changing status, profile or login
    /// identifier, deletion etc.). Looks at the target's permissions **in every scope** (including ones held as a guest in other tenants).
    ///
    /// ⚠ Does nothing when the target is not in the requested tenant or does not exist. The operation returns 404 for that:
    /// a 403 here would reveal across tenants that "a user with that ID exists".
    pub async fn ensure_may_manage_account(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        target: Uuid,
    ) -> Result<(), AdminAccountGuardError> {
        let user = self
            .users
            .find_by_id(target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        match user {
            Some(user) if user.tenant_id == tenant.tenant_id() => {}
            _ => return Ok(()),
        }
        let scoped_codes = self
            .permissions
            .list_scoped_codes_for_user(target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        // Identify guests holding root permissions (ADR-0070). If they cannot be identified, do not allow the operation.
        let root = self
            .tenants
            .find_root()
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .ok_or_else(|| AdminAccountGuardError::Internal("root tenant not found".to_string()))?
            .id;
        let held_by_target: Vec<HeldByTarget> = scoped_codes
            .into_iter()
            .map(|(scope, code)| HeldByTarget {
                code,
                scope: if scope == tenant.tenant_id() {
                    TargetScope::RequestedTenant
                } else if scope == root {
                    TargetScope::RootTenant
                } else {
                    TargetScope::OtherTenant
                },
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)
    }

    /// Call before updating a client (including keys and auth method), regenerating its secret, or deleting it (task #756).
    ///
    /// Being able to regenerate the secret or replace the public key means exercising that client's permissions. As
    /// with accounts, it is allowed only when **the caller can grant every permission of the target**. A client's
    /// permission scope is only its own tenant (`client_permissions` has no scope column).
    ///
    /// The same goes for service accounts assigned to apps: replacing the key reaches that app. Allowed only
    /// when holding `idp.applications:write`, which decides assignments (task #787).
    ///
    /// ⚠ Does nothing when the target is not in the requested tenant. The operation returns 404 for that.
    pub async fn ensure_may_manage_client(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        client_id: &str,
    ) -> Result<(), AdminAccountGuardError> {
        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        let Some(client) = client else {
            return Ok(());
        };
        let held_by_target: Vec<HeldByTarget> = self
            .client_permissions
            .list_codes_for_client(client.id)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .into_iter()
            .map(|code| HeldByTarget {
                code,
                scope: TargetScope::RequestedTenant,
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)?;
        if permission::satisfies(held, permission::APPLICATIONS_WRITE) {
            return Ok(());
        }
        let assignments = self
            .applications
            .list_account_assignments(
                tenant.tenant_id(),
                AccountRef::ServiceAccount {
                    client_row_id: client.id,
                },
            )
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?;
        if assignments.is_empty() {
            Ok(())
        } else {
            Err(AdminAccountGuardError::Forbidden)
        }
    }

    /// Call before membership operations (suspend, remove). Only permissions **in the requested tenant's scope** are
    /// considered (a guest's home tenant permissions are no concern of the host's admins; ADR-0009 §3).
    pub async fn ensure_may_manage_membership(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        held: &[String],
        target: Uuid,
    ) -> Result<(), AdminAccountGuardError> {
        let held_by_target: Vec<HeldByTarget> = self
            .permissions
            .list_codes_for_user(tenant.tenant_id(), target)
            .await
            .map_err(|e| AdminAccountGuardError::Internal(e.to_string()))?
            .into_iter()
            .map(|code| HeldByTarget {
                code,
                scope: TargetScope::RequestedTenant,
            })
            .collect();
        self.decide(held, &held_by_target, tenant_is_root)
    }

    fn decide(
        &self,
        held: &[String],
        held_by_target: &[HeldByTarget],
        tenant_is_root: bool,
    ) -> Result<(), AdminAccountGuardError> {
        if permission::may_manage_account(held, held_by_target, tenant_is_root) {
            Ok(())
        } else {
            Err(AdminAccountGuardError::Forbidden)
        }
    }
}
