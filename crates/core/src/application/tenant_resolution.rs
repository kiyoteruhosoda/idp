//! Tenant resolution use case (ADR-0009 §7).
//!
//! Used by the `TenantResolver` middleware (presentation) to resolve the target tenant from the request path's
//! `:tenant_id` (UUID). id -> tenant is a hot path, so the tenant entity is cached in a generic TTL cache
//! ([`crate::domain::cache::Cache`]) and invalidated on update (the name/status changes of
//! MT11).
//!
//! Resolution rules (§7):
//! - Not in `tenants` -> unresolvable (the middleware returns 404).
//! - `DISABLED` -> unresolvable (status is per tenant. A parent's DISABLED does not propagate to children. §1).
//! - `ACTIVE` -> resolved.
//!
//! Root is resolved as a UUID through the same path, with no special branch (§1). The cache stores the tenant entity
//! (including status), and validity is checked after retrieval. This way a DISABLED->ACTIVE recovery is
//! also reflected by invalidation alone.

use crate::domain::cache::Cache;
use crate::domain::error::Result;
use crate::domain::repositories::TenantRepository;
use crate::domain::tenant::{Tenant, TenantId};
use std::sync::Arc;

pub struct TenantResolutionService {
    tenants: Arc<dyn TenantRepository>,
    cache: Arc<dyn Cache<TenantId, Tenant>>,
}

impl TenantResolutionService {
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        cache: Arc<dyn Cache<TenantId, Tenant>>,
    ) -> Self {
        Self { tenants, cache }
    }

    /// Resolves `tenant_id`. Returns `Some(tenant)` if it exists and is `ACTIVE`, `None` if missing or `DISABLED`.
    /// Repository failures propagate as is (the middleware turns them into 5xx).
    pub async fn resolve(&self, tenant_id: TenantId) -> Result<Option<Tenant>> {
        let tenant = match self.cache.get(&tenant_id) {
            Some(cached) => cached,
            None => match self.tenants.find_by_id(tenant_id).await? {
                Some(tenant) => {
                    self.cache.insert(tenant_id, tenant.clone());
                    tenant
                }
                None => return Ok(None),
            },
        };
        // Validity is checked after retrieval (because the cached entity includes status).
        Ok(tenant.is_active().then_some(tenant))
    }

    /// Invalidates the cache entry (called when a tenant's name or status is updated. MT11).
    pub fn invalidate(&self, tenant_id: TenantId) {
        self.cache.invalidate(&tenant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::values::TenantStatus;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap()
    }

    fn tenant(id: TenantId, status: TenantStatus) -> Tenant {
        Tenant {
            id,
            parent_tenant_id: Some(Uuid::now_v7().into()),
            name: "Acme".to_string(),
            status,
            self_registration_enabled: false,
            email_login_enabled: false,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[derive(Default)]
    struct FakeTenants {
        row: Mutex<Option<Tenant>>,
        find_calls: AtomicUsize,
    }
    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, _t: &Tenant) -> Result<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>> {
            self.find_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.row.lock().unwrap().clone().filter(|t| t.id == id))
        }
        async fn find_root(&self) -> Result<Option<Tenant>> {
            unreachable!()
        }
        async fn list_children(&self, _p: TenantId) -> Result<Vec<Tenant>> {
            unreachable!()
        }
        async fn update(&self, _t: &Tenant) -> Result<()> {
            unreachable!()
        }
        async fn delete(&self, _id: TenantId) -> Result<()> {
            unreachable!()
        }
    }

    fn service(repo: Arc<FakeTenants>) -> TenantResolutionService {
        let cache = Arc::new(InMemoryTtlCache::<TenantId, Tenant>::new(
            Duration::seconds(60),
            Arc::new(FixedClock(now())),
        ));
        TenantResolutionService::new(repo, cache)
    }

    #[tokio::test]
    async fn resolves_active_tenant_and_caches() {
        let id: TenantId = Uuid::now_v7().into();
        let repo = Arc::new(FakeTenants::default());
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Active));
        let svc = service(repo.clone());

        assert_eq!(svc.resolve(id).await.unwrap().map(|t| t.id), Some(id));
        assert_eq!(svc.resolve(id).await.unwrap().map(|t| t.id), Some(id));
        // The second call is a cache hit and does not hit the DB.
        assert_eq!(repo.find_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disabled_tenant_is_not_resolvable() {
        let id: TenantId = Uuid::now_v7().into();
        let repo = Arc::new(FakeTenants::default());
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Disabled));
        let svc = service(repo);
        assert!(svc.resolve(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unknown_tenant_is_not_resolvable_and_not_cached() {
        let id: TenantId = Uuid::now_v7().into();
        let repo = Arc::new(FakeTenants::default());
        let svc = service(repo.clone());
        assert!(svc.resolve(id).await.unwrap().is_none());
        assert!(svc.resolve(id).await.unwrap().is_none());
        // Missing tenants are not cached, so the DB is queried every time.
        assert_eq!(repo.find_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_forces_reload() {
        let id: TenantId = Uuid::now_v7().into();
        let repo = Arc::new(FakeTenants::default());
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Active));
        let svc = service(repo.clone());

        assert!(svc.resolve(id).await.unwrap().is_some());
        // Changed to DISABLED in the DB, but the cache remains valid until invalidated.
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Disabled));
        assert!(svc.resolve(id).await.unwrap().is_some());
        // After invalidation it is reloaded and DISABLED is reflected.
        svc.invalidate(id);
        assert!(svc.resolve(id).await.unwrap().is_none());
    }
}
