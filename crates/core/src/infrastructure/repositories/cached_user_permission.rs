//! `UserPermissionRepository` のキャッシュデコレータ（ADR-0009 §7）。
//!
//! §4 の権限判定（`has_permission`）はリクエスト毎に評価されるホットパス（`(user_id, permission_code,
//! tenant_id)` の存在確認）である。汎用 TTL キャッシュ（[`crate::domain::cache::Cache`]）で判定結果を
//! キャッシュし、`grant` / `revoke` 時に該当エントリを invalidate する。判定・付与・剥奪は同一インスタンス
//! を共有するため、付与直後の反映漏れ（stale allow/deny）を避けられる。
//!
//! 参照系のうち `has_permission` のみをキャッシュする。`list_codes_for_user` は管理コンソール表示用で
//! ホットパスではないため素通しする（キャッシュしない）。DIP を保つため、内側の実装は trait
//! オブジェクトとして注入する（sqlx 実装に限定しない）。

use crate::domain::cache::Cache;
use crate::domain::error::Result;
use crate::domain::repositories::UserPermissionRepository;
use crate::domain::tenant::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// `has_permission` の判定結果をキャッシュするキー（scope→権限解決のキー空間）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionKey {
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub code: String,
}

pub struct CachedUserPermissionRepository {
    inner: Arc<dyn UserPermissionRepository>,
    cache: Arc<dyn Cache<PermissionKey, bool>>,
}

impl CachedUserPermissionRepository {
    pub fn new(
        inner: Arc<dyn UserPermissionRepository>,
        cache: Arc<dyn Cache<PermissionKey, bool>>,
    ) -> Self {
        Self { inner, cache }
    }

    fn key(tenant_id: TenantId, user_id: Uuid, code: &str) -> PermissionKey {
        PermissionKey {
            tenant_id,
            user_id,
            code: code.to_string(),
        }
    }
}

#[async_trait]
impl UserPermissionRepository for CachedUserPermissionRepository {
    async fn list_available_codes(&self) -> Result<Vec<String>> {
        self.inner.list_available_codes().await
    }

    async fn list_codes_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>> {
        self.inner.list_codes_for_user(tenant_id, user_id).await
    }

    async fn has_permission(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool> {
        let key = Self::key(tenant_id, user_id, code);
        if let Some(hit) = self.cache.get(&key) {
            return Ok(hit);
        }
        let held = self.inner.has_permission(tenant_id, user_id, code).await?;
        self.cache.insert(key, held);
        Ok(held)
    }

    async fn grant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()> {
        self.inner
            .grant(tenant_id, user_id, code, granted_at)
            .await?;
        // 付与を判定へ即時反映する（stale deny を避ける）。
        self.cache.invalidate(&Self::key(tenant_id, user_id, code));
        Ok(())
    }

    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()> {
        self.inner.revoke(tenant_id, user_id, code).await?;
        // 剥奪を判定へ即時反映する（stale allow を避ける）。
        self.cache.invalidate(&Self::key(tenant_id, user_id, code));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::cache::InMemoryTtlCache;
    use chrono::{Duration, TimeZone};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct FixedClock(DateTime<Utc>);
    impl crate::domain::clock::Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// 呼び出し回数を数え、保有状態を保持するフェイク。
    #[derive(Default)]
    struct CountingPermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        has_calls: AtomicUsize,
    }
    #[async_trait]
    impl UserPermissionRepository for CountingPermissions {
        async fn list_available_codes(&self) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn list_codes_for_user(
            &self,
            _tenant_id: TenantId,
            _user_id: Uuid,
        ) -> Result<Vec<String>> {
            Ok(vec![])
        }
        async fn has_permission(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
        ) -> Result<bool> {
            self.has_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code))
        }
        async fn grant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
            _g: DateTime<Utc>,
        ) -> Result<()> {
            self.granted
                .lock()
                .unwrap()
                .push((tenant_id, user_id, code.to_string()));
            Ok(())
        }
        async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(t, u, c)| !(*t == tenant_id && *u == user_id && c == code));
            Ok(())
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap()
    }

    fn setup(
        inner: Arc<CountingPermissions>,
    ) -> CachedUserPermissionRepository {
        let cache = Arc::new(InMemoryTtlCache::<PermissionKey, bool>::new(
            Duration::seconds(60),
            Arc::new(FixedClock(now())),
        ));
        CachedUserPermissionRepository::new(inner, cache)
    }

    #[tokio::test]
    async fn caches_has_permission_and_hits_inner_once() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        inner
            .granted
            .lock()
            .unwrap()
            .push((tenant, user, "idp.tenant.admin".to_string()));
        let repo = setup(inner.clone());

        assert!(repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
        assert!(repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
        // 2 回目はキャッシュヒットで内側を叩かない。
        assert_eq!(inner.has_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn grant_invalidates_stale_deny() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        let repo = setup(inner.clone());

        // まず未保有（false）をキャッシュ。
        assert!(!repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
        // 付与すると該当エントリが invalidate され、次の判定は再計算されて true。
        repo.grant(tenant, user, "idp.tenant.admin", now()).await.unwrap();
        assert!(repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
    }

    #[tokio::test]
    async fn revoke_invalidates_stale_allow() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        inner
            .granted
            .lock()
            .unwrap()
            .push((tenant, user, "idp.tenant.admin".to_string()));
        let repo = setup(inner.clone());

        assert!(repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
        repo.revoke(tenant, user, "idp.tenant.admin").await.unwrap();
        assert!(!repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
    }

    #[tokio::test]
    async fn invalidation_is_scoped_to_the_key() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        inner
            .granted
            .lock()
            .unwrap()
            .push((tenant, user, "idp.tenant.admin".to_string()));
        let repo = setup(inner.clone());

        // 別コードを 1 件キャッシュしておく。
        assert!(!repo.has_permission(tenant, user, "idp.other").await.unwrap());
        assert!(repo.has_permission(tenant, user, "idp.tenant.admin").await.unwrap());
        // idp.tenant.admin を剥奪しても idp.other のキャッシュは残る。
        repo.revoke(tenant, user, "idp.tenant.admin").await.unwrap();
        let before = inner.has_calls.load(Ordering::SeqCst);
        assert!(!repo.has_permission(tenant, user, "idp.other").await.unwrap());
        assert_eq!(inner.has_calls.load(Ordering::SeqCst), before);
    }
}
