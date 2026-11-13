//! Member list lookup use case (`GET /{tenant_id}/admin/members`. MT22).
//!
//! Returns users who belong to the tenant (HOME / GUEST) page by page, filtered by partial match on
//! email and name. Read-only, so nothing is audited (reads can be traced in the `log` table).
//!
//! **Changes** to membership (invite, accept, remove, suspend) are the responsibility of
//! [`crate::application::invitation`]; this service only reads (SRP; same role as [`crate::application::audit_query`]).

use crate::domain::error::DomainError;
use crate::domain::repositories::TenantMemberQuery;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::{TenantMember, TenantMemberFilter, TenantMemberPage};
use std::sync::Arc;

/// Default number of items per page.
pub const DEFAULT_LIMIT: i64 = 50;
/// Maximum number of items per page (prevents oversized fetches).
pub const MAX_LIMIT: i64 = 200;

/// Search parameters (raw values from Presentation; `limit`/`offset` not yet clamped).
#[derive(Debug, Clone, Default)]
pub struct MemberSearchParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Search result. `limit` / `offset` are the values **actually applied** (after clamping), so the caller can
/// use these instead of the requested values when computing pagination (so the clamping rules are not
/// duplicated in the Presentation layer).
#[derive(Debug)]
pub struct MemberSearchResult {
    pub page: TenantMemberPage,
    pub limit: i64,
    pub offset: i64,
}

pub struct MemberDirectoryService {
    members: Arc<dyn TenantMemberQuery>,
}

impl MemberDirectoryService {
    pub fn new(members: Arc<dyn TenantMemberQuery>) -> Self {
        Self { members }
    }

    /// Returns one page of members matching the filter. The tenant is fixed to the requested tenant
    /// (to prevent cross-tenant viewing, the caller is given no room to override it).
    pub async fn search(
        &self,
        tenant: TenantContext,
        params: MemberSearchParams,
    ) -> Result<MemberSearchResult, DomainError> {
        let filter = TenantMemberFilter {
            tenant_id: tenant.tenant_id(),
            user_id: None,
            search: normalize(params.search),
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        let page = self.members.search(&filter).await?;
        Ok(MemberSearchResult {
            page,
            limit: filter.limit,
            offset: filter.offset,
        })
    }

    /// Looks up one person by name (member detail screen). `None` if not in the requested tenant.
    ///
    /// ⚠ **Do not fetch the list and make the web side search it.** Members are paginated, so the
    /// caller cannot know which page the target person is on.
    pub async fn find(
        &self,
        tenant: TenantContext,
        user_id: uuid::Uuid,
    ) -> Result<Option<TenantMember>, DomainError> {
        let filter = TenantMemberFilter {
            tenant_id: tenant.tenant_id(),
            user_id: Some(user_id),
            search: None,
            limit: 1,
            offset: 0,
        };
        Ok(self
            .members
            .search(&filter)
            .await?
            .members
            .into_iter()
            .next())
    }
}

/// Clamps `limit` into 1..=MAX_LIMIT. Missing or non-positive values become the default.
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// Normalizes an empty string to `None` (so an unset query `?q=` is treated as "no filter").
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// A fake that only records the filter it receives (for verifying clamping and normalization).
    #[derive(Default)]
    struct CapturingQuery {
        seen: Mutex<Vec<TenantMemberFilter>>,
    }
    #[async_trait]
    impl TenantMemberQuery for CapturingQuery {
        async fn search(&self, filter: &TenantMemberFilter) -> DomainResult<TenantMemberPage> {
            self.seen.lock().unwrap().push(filter.clone());
            Ok(TenantMemberPage {
                members: Vec::new(),
                total: 0,
            })
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(
            0x0197_0000_0000_7000_8000_0000_0000_0001,
        )))
    }

    async fn captured(params: MemberSearchParams) -> TenantMemberFilter {
        let query = Arc::new(CapturingQuery::default());
        let svc = MemberDirectoryService::new(query.clone());
        svc.search(tenant(), params).await.expect("search ok");
        let seen = query.seen.lock().unwrap();
        seen.first().expect("filter captured").clone()
    }

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(-5)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[tokio::test]
    async fn blank_search_means_no_filter_and_negative_offset_is_clamped() {
        let filter = captured(MemberSearchParams {
            search: Some("   ".to_string()),
            limit: None,
            offset: Some(-10),
        })
        .await;
        assert_eq!(filter.search, None);
        assert_eq!(filter.offset, 0);
        assert_eq!(filter.limit, DEFAULT_LIMIT);
    }

    #[tokio::test]
    async fn search_term_is_trimmed_and_tenant_is_fixed_to_the_request_tenant() {
        let filter = captured(MemberSearchParams {
            search: Some("  Alice  ".to_string()),
            limit: Some(5),
            offset: Some(100),
        })
        .await;
        assert_eq!(filter.search.as_deref(), Some("Alice"));
        assert_eq!(filter.limit, 5);
        assert_eq!(filter.offset, 100);
        assert_eq!(filter.tenant_id, tenant().tenant_id());
    }
}
