//! Use case: view the account list (`GET /{tenant_id}/admin/accounts`; ADR-0065).
//!
//! Lists people and service accounts in one list. Read-only, so nothing is audited
//! (same standing as [`crate::application::member_directory`]).
//!
//! # List only the readable kinds
//!
//! The permission to read people (`idp.members:read`) differs from the one to read service accounts (`idp.clients:read`).
//! The list shows **only the kinds the calling principal can read**. No new permission code ("read accounts") is
//! made: that would mean redefining one more implication against the existing two (rejected option D of ADR-0065).
//!
//! - No kind specified: list every readable kind. If none is readable, [`AccountDirectoryError::Forbidden`]
//! - Kind specified: `Forbidden` if that kind is not readable. ⚠ **Never silently return empty**: an empty list
//!   reads as "nobody there"

use crate::application::member_directory::{DEFAULT_LIMIT, MAX_LIMIT};
use crate::domain::account::{AccountFilter, AccountKind, AccountPage, ServiceAccount};
use crate::domain::permission;
use crate::domain::repositories::AccountQuery;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum AccountDirectoryError {
    /// No permission to read the requested kind (or any kind).
    Forbidden,
    Internal(String),
}

/// Search parameters (raw values from Presentation; `limit`/`offset` are not clamped).
#[derive(Debug, Clone, Default)]
pub struct AccountSearchParams {
    /// Kinds to list. `None` means "everything readable".
    pub kind: Option<AccountKind>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Search result. `limit` / `offset` are the values actually applied; `kinds` are the kinds actually listed.
#[derive(Debug)]
pub struct AccountSearchResult {
    pub page: AccountPage,
    pub kinds: Vec<AccountKind>,
    /// Kinds this principal can read (so the screen can offer filter options). Separate from `kinds`:
    /// even when a kind is specified, what else can be chosen is still needed.
    pub readable: Vec<AccountKind>,
    pub limit: i64,
    pub offset: i64,
}

/// Permission code needed to read a kind.
fn read_permission(kind: AccountKind) -> &'static str {
    match kind {
        AccountKind::User => permission::MEMBERS_READ,
        AccountKind::ServiceAccount => permission::CLIENTS_READ,
    }
}

/// Returns the readable kinds from the held permissions (in [`AccountKind::ALL`] order).
pub fn readable_kinds<S: AsRef<str>>(held: &[S]) -> Vec<AccountKind> {
    AccountKind::ALL
        .into_iter()
        .filter(|kind| permission::satisfies(held, read_permission(*kind)))
        .collect()
}

pub struct AccountDirectoryService {
    accounts: Arc<dyn AccountQuery>,
}

impl AccountDirectoryService {
    pub fn new(accounts: Arc<dyn AccountQuery>) -> Self {
        Self { accounts }
    }

    /// Returns one page of accounts matching the criteria. The tenant is fixed to the requested tenant.
    ///
    /// `held` is the calling principal's held permission codes (the admin token's `perms`; implications not expanded).
    pub async fn search<S: AsRef<str>>(
        &self,
        tenant: TenantContext,
        held: &[S],
        params: AccountSearchParams,
    ) -> Result<AccountSearchResult, AccountDirectoryError> {
        let readable = readable_kinds(held);
        let kinds = match params.kind {
            Some(kind) if readable.contains(&kind) => vec![kind],
            Some(_) => return Err(AccountDirectoryError::Forbidden),
            None if readable.is_empty() => return Err(AccountDirectoryError::Forbidden),
            None => readable.clone(),
        };
        let filter = AccountFilter {
            tenant_id: tenant.tenant_id(),
            kinds: kinds.clone(),
            search: params
                .search
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            limit: match params.limit {
                Some(l) if l > 0 => l.min(MAX_LIMIT),
                _ => DEFAULT_LIMIT,
            },
            offset: params.offset.unwrap_or(0).max(0),
        };
        let page = self
            .accounts
            .search(&filter)
            .await
            .map_err(|e| AccountDirectoryError::Internal(e.to_string()))?;
        Ok(AccountSearchResult {
            page,
            kinds,
            readable,
            limit: filter.limit,
            offset: filter.offset,
        })
    }

    /// Looks up one service account by `client_id` (single-item screen). `None` unless it is a service
    /// account of the requested tenant (integrations, deleted ones and other tenants are not distinguished).
    pub async fn find_service_account(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Option<ServiceAccount>, AccountDirectoryError> {
        self.accounts
            .find_service_account(tenant.tenant_id(), client_id.trim())
            .await
            .map_err(|e| AccountDirectoryError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct CapturingQuery {
        seen: Mutex<Vec<AccountFilter>>,
    }
    #[async_trait]
    impl AccountQuery for CapturingQuery {
        async fn search(&self, filter: &AccountFilter) -> DomainResult<AccountPage> {
            self.seen.lock().unwrap().push(filter.clone());
            Ok(AccountPage {
                accounts: Vec::new(),
                total: 0,
            })
        }
        async fn find_service_account(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<ServiceAccount>> {
            Ok(None)
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(
            0x0197_0000_0000_7000_8000_0000_0000_0001,
        )))
    }

    async fn run(
        held: &[&str],
        kind: Option<AccountKind>,
    ) -> (
        Result<AccountSearchResult, AccountDirectoryError>,
        Vec<AccountFilter>,
    ) {
        let query = Arc::new(CapturingQuery::default());
        let svc = AccountDirectoryService::new(query.clone());
        let result = svc
            .search(
                tenant(),
                held,
                AccountSearchParams {
                    kind,
                    search: Some("  wiki ".to_string()),
                    limit: Some(10_000),
                    offset: Some(-1),
                },
            )
            .await;
        let seen = query.seen.lock().unwrap().clone();
        (result, seen)
    }

    #[test]
    fn readable_kinds_follow_the_implication_rules() {
        assert_eq!(
            readable_kinds(&[permission::TENANT_ADMIN]),
            vec![AccountKind::User, AccountKind::ServiceAccount]
        );
        assert_eq!(
            readable_kinds(&[permission::MEMBERS_WRITE]),
            vec![AccountKind::User]
        );
        assert_eq!(
            readable_kinds(&[permission::CLIENTS_READ]),
            vec![AccountKind::ServiceAccount]
        );
        assert!(readable_kinds(&[permission::USERS_READ]).is_empty());
    }

    #[tokio::test]
    async fn without_a_kind_only_readable_kinds_are_listed() {
        let (result, seen) = run(&[permission::MEMBERS_READ], None).await;
        let result = result.expect("ok");
        assert_eq!(result.kinds, vec![AccountKind::User]);
        assert_eq!(seen[0].kinds, vec![AccountKind::User]);
        assert_eq!(seen[0].search.as_deref(), Some("wiki"));
        assert_eq!(seen[0].limit, MAX_LIMIT);
        assert_eq!(seen[0].offset, 0);
    }

    #[tokio::test]
    async fn asking_for_an_unreadable_kind_is_forbidden_not_empty() {
        let (result, seen) = run(
            &[permission::MEMBERS_READ],
            Some(AccountKind::ServiceAccount),
        )
        .await;
        assert_eq!(result.unwrap_err(), AccountDirectoryError::Forbidden);
        assert!(
            seen.is_empty(),
            "must not query the DB for an unreadable kind"
        );
    }

    #[tokio::test]
    async fn nothing_readable_is_forbidden() {
        let (result, _) = run(&[permission::AUDIT_READ], None).await;
        assert_eq!(result.unwrap_err(), AccountDirectoryError::Forbidden);
    }

    #[tokio::test]
    async fn a_named_kind_keeps_the_other_readable_kinds_for_the_filter() {
        let (result, _) = run(
            &[permission::TENANT_ADMIN],
            Some(AccountKind::ServiceAccount),
        )
        .await;
        let result = result.expect("ok");
        assert_eq!(result.kinds, vec![AccountKind::ServiceAccount]);
        assert_eq!(
            result.readable,
            vec![AccountKind::User, AccountKind::ServiceAccount]
        );
    }
}
