//! Generic TTL cache abstraction (DIP boundary. ADR-0009 §7).
//!
//! Tenant resolution (id -> tenant) and scope->permission resolution (existence check of `(user_id, permission_code, tenant_id)`)
//! are both hot paths evaluated on every request, so a TTL in-memory cache + invalidation on update
//! keeps lookup cost down. The cache is designed as a generic mechanism, with a separate instance
//! (separate key space) injected per use.
//!
//! Like `InMemoryLoginRateLimiter`, it is injected through a trait and assumes a single instance; when scaling out
//! it is swapped for a shared-store implementation such as Redis (this trait is the DIP boundary). Implemented in the
//! infrastructure layer ([`crate::infrastructure::cache`]).
#![allow(dead_code)]

/// A TTL cache that looks up value `V` by key `K`. Time dependence (expiry checks) is kept inside the implementation,
/// so callers need not be aware of the current time. Methods have no generics (object-safe) so it can be
/// injected as a trait object (`Arc<dyn Cache<K, V>>`).
pub trait Cache<K, V>: Send + Sync {
    /// Returns a clone if there is an unexpired entry. Returns `None` if there is none (unregistered or expired).
    fn get(&self, key: &K) -> Option<V>;
    /// Registers an entry (overwrites an existing key and resets the TTL).
    fn insert(&self, key: K, value: V);
    /// Invalidates the entry for the given key (called on grant, revoke, or update).
    fn invalidate(&self, key: &K);
}
