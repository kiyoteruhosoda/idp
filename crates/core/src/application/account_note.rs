//! Writes an admin note on an account (ADR-0063 / ADR-0065).
//!
//! - Person: `PUT /{tenant_id}/admin/members/{user_id}/note`
//! - Service account: `PUT /{tenant_id}/admin/service-accounts/{client_id}/note`
//!
//! The routes are split per kind (the write permission differs: `idp.members:write` / `idp.clients:write`),
//! but the rules (limit, normalization, audit) live only in this service. Reading is done by the list
//! and detail joins ([`crate::application::account_directory`], [`crate::application::member_directory`]),
//! so this holds only the write.
//!
//! ⚠ **The audit does not carry the note's content.** Free-text history includes personal circumstances.
//! Only "who wrote or cleared whose note" is kept (just as `UserProfileUpdated` keeps no values).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::account::{AccountLocator, AccountRef};
use crate::domain::account_note::normalize_account_note;
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::message::MessageKey;
use crate::domain::repositories::{AccountNoteRepository, ClientRepository, TenantMemberQuery};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMemberFilter;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum AccountNoteError {
    /// Not an account of the requested tenant (do not let other tenants' existence be inferred).
    NotFound,
    /// Too long.
    Invalid(MessageKey),
    Internal(String),
}

pub struct AccountNoteService {
    members: Arc<dyn TenantMemberQuery>,
    clients: Arc<dyn ClientRepository>,
    notes: Arc<dyn AccountNoteRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountNoteService {
    pub fn new(
        members: Arc<dyn TenantMemberQuery>,
        clients: Arc<dyn ClientRepository>,
        notes: Arc<dyn AccountNoteRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            members,
            clients,
            notes,
            audit,
            clock,
        }
    }

    /// Writes the note. Empty (whitespace only) clears it.
    ///
    /// People can be written regardless of HOME / GUEST. The note is this tenant's admin memo and does
    /// not change the guest user themselves (only the home tenant's admins may; ADR-0009 §3).
    pub async fn write(
        &self,
        tenant: TenantContext,
        target: AccountLocator<'_>,
        raw: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), AccountNoteError> {
        // ⚠ Validate first (if too long, refuse before asking whether the target exists).
        let text = normalize_account_note(raw).map_err(AccountNoteError::Invalid)?;
        let account = self.resolve(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let subject = match target {
            AccountLocator::User { user_id } => format!("user={user_id}"),
            AccountLocator::ServiceAccount { client_id } => format!("service_account={client_id}"),
        };
        let reason = match text.as_deref() {
            Some(text) => {
                self.notes
                    .save(tenant_id, account, text, actor.user_id(), self.clock.now())
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                subject
            }
            None => {
                self.notes
                    .clear(tenant_id, account)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                format!("{subject} cleared")
            }
        };
        self.audit
            .record(
                AuditEventType::AccountNoteUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&reason),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Maps the route value to the note's target ([`AccountRef`]).
    ///
    /// - Person: must be a member of the requested tenant (the note attaches to the membership; the FK rejects otherwise)
    /// - Service account: a client of the requested tenant that is a service account and not deleted.
    ///   ⚠ Notes are not allowed on integrations (login clients): the note is the account's history,
    ///   not the integration's settings (decision 2 of ADR-0065)
    async fn resolve(
        &self,
        tenant: TenantContext,
        target: AccountLocator<'_>,
    ) -> Result<AccountRef, AccountNoteError> {
        match target {
            AccountLocator::User { user_id } => {
                let filter = TenantMemberFilter {
                    tenant_id: tenant.tenant_id(),
                    user_id: Some(user_id),
                    search: None,
                    limit: 1,
                    offset: 0,
                };
                let page = self
                    .members
                    .search(&filter)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?;
                if page.members.is_empty() {
                    return Err(AccountNoteError::NotFound);
                }
                Ok(AccountRef::User { user_id })
            }
            AccountLocator::ServiceAccount { client_id } => {
                let client = self
                    .clients
                    .find_by_client_id(tenant.tenant_id(), client_id)
                    .await
                    .map_err(|e| AccountNoteError::Internal(e.to_string()))?
                    .filter(|c| c.is_service_account() && !c.is_deleted())
                    .ok_or(AccountNoteError::NotFound)?;
                Ok(AccountRef::ServiceAccount {
                    client_row_id: client.id,
                })
            }
        }
    }
}
