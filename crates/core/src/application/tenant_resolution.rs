//! テナント解決ユースケース（ADR-0009 §7）。
//!
//! `TenantResolver` middleware（presentation）が、リクエストパスの `:tenant_id`（UUID）から処理対象の
//! テナントを解決するために使う。id → tenant はホットパスのため、汎用 TTL キャッシュ
//! （[`crate::domain::cache::Cache`]）でテナント実体をキャッシュし、更新時（MT11 の名称・状態変更）に
//! invalidate する。
//!
//! 解決可否の規則（§7）:
//! - `tenants` に存在しない → 解決不可（middleware は 404 を返す）。
//! - `DISABLED` → 解決不可（status は各テナント独立。親の DISABLED は子へ伝播しない。§1）。
//! - `ACTIVE` → 解決成功。
//!
//! root も同一経路で UUID として解決し、特別分岐は設けない（§1）。キャッシュにはテナント実体
//! （status を含む）を格納し、有効性判定は取り出し後に行う。これにより DISABLED→ACTIVE の復帰も
//! invalidate だけで反映できる。

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

    /// `tenant_id` を解決する。存在し `ACTIVE` なら `Some(tenant)`、不存在・`DISABLED` なら `None`。
    /// リポジトリ障害はそのまま伝播する（middleware 側で 5xx に倒す）。
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
        // 有効性判定は取り出し後（status を含む実体をキャッシュしているため）。
        Ok(tenant.is_active().then_some(tenant))
    }

    /// キャッシュエントリを無効化する（テナントの名称・状態更新時に呼ぶ。MT11）。
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
        // 2 回目はキャッシュヒットで DB を叩かない。
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
        // 不存在はキャッシュしないため毎回 DB を引く。
        assert_eq!(repo.find_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidate_forces_reload() {
        let id: TenantId = Uuid::now_v7().into();
        let repo = Arc::new(FakeTenants::default());
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Active));
        let svc = service(repo.clone());

        assert!(svc.resolve(id).await.unwrap().is_some());
        // DB 上で DISABLED に変わったが、invalidate 前はキャッシュが有効。
        *repo.row.lock().unwrap() = Some(tenant(id, TenantStatus::Disabled));
        assert!(svc.resolve(id).await.unwrap().is_some());
        // invalidate 後は再読み込みされ DISABLED が反映される。
        svc.invalidate(id);
        assert!(svc.resolve(id).await.unwrap().is_none());
    }
}
