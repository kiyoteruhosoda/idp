//! Caching decorator for `UserPermissionRepository` (ADR-0009 §7).
//!
//! The §4 permission check (`has_permission`) is a hot path evaluated per request (an existence check of `(user_id, permission_code,
//! tenant_id)`). Its result is cached with the generic TTL cache ([`crate::domain::cache::Cache`]),
//! and the matching entry is invalidated on `grant` / `revoke`. Check, grant and revoke share the same instance,
//! so missed updates right after a grant (stale allow/deny) are avoided.
//!
//! The list of grantable permission codes (`list_available_codes`, a full read of the `permissions` master) is looked up
//! by `whoami` on every admin console render as the target of implication expansion. The master only changes through migrations,
//! and a migration adding master rows ships together with the startup of the new version that uses it (ADR-0004; an old version
//! left during a rolling deploy keeps the old list, but that doesn't disagree with that version's code), so it is **kept for the process lifetime**
//! (no TTL or invalidation; the first successful result is kept, and failures are not kept but retried on the next call).
//!
//! Of the per-user lookups, only `has_permission` is cached. `list_codes_for_user` passes through
//! (not cached). Since ADR-0037 this method is the source for issuing admin tokens, called on **every admin console
//! request** (`AdminAccessService::resolve_session_grant`), and the permissions obtained there are
//! carried for the token's lifetime, so **a stale value at issuance delays revocation taking effect by that much**.
//! To keep the premise of ADR-0037 decision 2, "revocation takes effect immediately because it is re-read on every exchange",
//! this is intentionally not cached (assuming low admin console traffic; see ADR-0037's rejected alternatives).
//! To keep DIP, the inner implementation is injected as a trait object (not limited to the sqlx implementation).

use crate::domain::cache::Cache;
use crate::domain::error::Result;
use crate::domain::repositories::UserPermissionRepository;
use crate::domain::tenant::TenantId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::OnceCell;
use uuid::Uuid;

/// Key for caching `has_permission` results (the key space of scope -> permission resolution).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionKey {
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub code: String,
}

pub struct CachedUserPermissionRepository {
    inner: Arc<dyn UserPermissionRepository>,
    cache: Arc<dyn Cache<PermissionKey, bool>>,
    /// All rows of the `permissions` master (process lifetime; see the module notes).
    available_codes: OnceCell<Vec<String>>,
}

impl CachedUserPermissionRepository {
    pub fn new(
        inner: Arc<dyn UserPermissionRepository>,
        cache: Arc<dyn Cache<PermissionKey, bool>>,
    ) -> Self {
        Self {
            inner,
            cache,
            available_codes: OnceCell::new(),
        }
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
        // Concurrent first calls are coalesced into one, and failures (Err) are not stored in the cell.
        self.available_codes
            .get_or_try_init(|| self.inner.list_available_codes())
            .await
            .cloned()
    }

    async fn list_codes_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<String>> {
        self.inner.list_codes_for_user(tenant_id, user_id).await
    }

    async fn list_scoped_codes_for_user(&self, user_id: Uuid) -> Result<Vec<(TenantId, String)>> {
        // Used for the check before account operations. Bypasses the cache so stale results don't allow it.
        self.inner.list_scoped_codes_for_user(user_id).await
    }

    async fn has_permission(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<bool> {
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
        // Reflect grants in checks immediately (avoids stale deny).
        self.cache.invalidate(&Self::key(tenant_id, user_id, code));
        Ok(())
    }

    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()> {
        self.inner.revoke(tenant_id, user_id, code).await?;
        // Reflect revocations in checks immediately (avoids stale allow).
        self.cache.invalidate(&Self::key(tenant_id, user_id, code));
        Ok(())
    }

    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>> {
        let revoked = self
            .inner
            .revoke_all_for_user_in_tenant(tenant_id, user_id)
            .await?;
        // Reflect bulk revocations in checks immediately (avoids stale allow).
        for code in &revoked {
            self.cache.invalidate(&Self::key(tenant_id, user_id, code));
        }
        Ok(revoked)
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

    /// Fake that counts calls and holds the held state.
    #[derive(Default)]
    struct CountingPermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        has_calls: AtomicUsize,
        available_calls: AtomicUsize,
        /// Make `list_available_codes` fail this many more times (to check failures are not kept).
        available_failures: AtomicUsize,
    }
    #[async_trait]
    impl UserPermissionRepository for CountingPermissions {
        async fn list_scoped_codes_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<(TenantId, String)>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, u, _)| *u == user_id)
                .map(|(t, _, c)| (*t, c.clone()))
                .collect())
        }
        async fn list_available_codes(&self) -> Result<Vec<String>> {
            self.available_calls.fetch_add(1, Ordering::SeqCst);
            if self
                .available_failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(crate::domain::error::DomainError::Repository(
                    "db down".to_string(),
                ));
            }
            Ok(vec![
                "idp.system.admin".to_string(),
                "idp.tenant.admin".to_string(),
            ])
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
        async fn revoke_all_for_user_in_tenant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> Result<Vec<String>> {
            let mut granted = self.granted.lock().unwrap();
            let revoked: Vec<String> = granted
                .iter()
                .filter(|(t, u, _)| *t == tenant_id && *u == user_id)
                .map(|(_, _, c)| c.clone())
                .collect();
            granted.retain(|(t, u, _)| !(*t == tenant_id && *u == user_id));
            Ok(revoked)
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap()
    }

    fn setup(inner: Arc<CountingPermissions>) -> CachedUserPermissionRepository {
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

        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        // The second call is a cache hit and doesn't hit the inner one.
        assert_eq!(inner.has_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn grant_invalidates_stale_deny() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        let repo = setup(inner.clone());

        // First cache not-held (false).
        assert!(!repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        // Granting invalidates the matching entry, and the next check is recomputed to true.
        repo.grant(tenant, user, "idp.tenant.admin", now())
            .await
            .unwrap();
        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
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

        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        repo.revoke(tenant, user, "idp.tenant.admin").await.unwrap();
        assert!(!repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn revoke_all_invalidates_every_revoked_code() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let inner = Arc::new(CountingPermissions::default());
        {
            let mut granted = inner.granted.lock().unwrap();
            granted.push((tenant, user, "idp.tenant.admin".to_string()));
            granted.push((tenant, user, "idp.other".to_string()));
        }
        let repo = setup(inner.clone());

        // Put allows for both codes in the cache.
        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        assert!(repo
            .has_permission(tenant, user, "idp.other")
            .await
            .unwrap());

        // Bulk revoke -> returns the list of revoked codes, and no stale allow remains for either code.
        let mut revoked = repo
            .revoke_all_for_user_in_tenant(tenant, user)
            .await
            .unwrap();
        revoked.sort();
        assert_eq!(
            revoked,
            vec!["idp.other".to_string(), "idp.tenant.admin".to_string()]
        );
        assert!(!repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        assert!(!repo
            .has_permission(tenant, user, "idp.other")
            .await
            .unwrap());
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

        // Cache one entry for another code.
        assert!(!repo
            .has_permission(tenant, user, "idp.other")
            .await
            .unwrap());
        assert!(repo
            .has_permission(tenant, user, "idp.tenant.admin")
            .await
            .unwrap());
        // Revoking idp.tenant.admin leaves the cache for idp.other intact.
        repo.revoke(tenant, user, "idp.tenant.admin").await.unwrap();
        let before = inner.has_calls.load(Ordering::SeqCst);
        assert!(!repo
            .has_permission(tenant, user, "idp.other")
            .await
            .unwrap());
        assert_eq!(inner.has_calls.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn list_available_codes_reads_the_master_once() {
        let inner = Arc::new(CountingPermissions::default());
        let repo = setup(inner.clone());

        let expected = vec![
            "idp.system.admin".to_string(),
            "idp.tenant.admin".to_string(),
        ];
        assert_eq!(repo.list_available_codes().await.unwrap(), expected);
        assert_eq!(repo.list_available_codes().await.unwrap(), expected);
        // The master only changes through migrations, so from the second call on the inner one is not hit.
        assert_eq!(inner.available_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn list_available_codes_does_not_keep_a_failure() {
        let inner = Arc::new(CountingPermissions::default());
        inner.available_failures.store(1, Ordering::SeqCst);
        let repo = setup(inner.clone());

        // The first failure is not kept; the next call re-reads and succeeds.
        assert!(repo.list_available_codes().await.is_err());
        assert_eq!(repo.list_available_codes().await.unwrap().len(), 2);
        assert_eq!(repo.list_available_codes().await.unwrap().len(), 2);
        assert_eq!(inner.available_calls.load(Ordering::SeqCst), 2);
    }
}
