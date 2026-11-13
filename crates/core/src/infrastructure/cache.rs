//! In-memory TTL cache (ADR-0009 §7).
//!
//! **The api is assumed to run as a single instance** (README "scaling assumptions", G9), so state is kept
//! in process memory. With 2+ api processes, invalidation does not reach other instances.
//! Expiry is judged by insertion time + TTL, and
//! expired entries are lazily removed on `get`. Time comes via `Clock` (can be fixed in tests);
//! when scaling out, swap in a shared-store implementation (the `Cache` trait is the DIP boundary).

use crate::domain::cache::Cache;
use crate::domain::clock::Clock;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

struct Entry<V> {
    value: V,
    expires_at: DateTime<Utc>,
}

/// Generic TTL cache, injected as one instance per key space.
pub struct InMemoryTtlCache<K, V> {
    ttl: Duration,
    clock: Arc<dyn Clock>,
    entries: Mutex<HashMap<K, Entry<V>>>,
}

impl<K, V> InMemoryTtlCache<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    pub fn new(ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            ttl,
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, V> Cache<K, V> for InMemoryTtlCache<K, V>
where
    K: Eq + Hash + Send + Sync,
    V: Clone + Send + Sync,
{
    fn get(&self, key: &K) -> Option<V> {
        let now = self.clock.now();
        let mut map = self.entries.lock().expect("cache lock poisoned");
        match map.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.value.clone()),
            // Lazily remove expired entries (also keeps the key space from growing).
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    fn insert(&self, key: K, value: V) {
        let expires_at = self.clock.now() + self.ttl;
        self.entries
            .lock()
            .expect("cache lock poisoned")
            .insert(key, Entry { value, expires_at });
    }

    fn invalidate(&self, key: &K) {
        self.entries
            .lock()
            .expect("cache lock poisoned")
            .remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Clock that tests can advance at will.
    struct MutClock(StdMutex<DateTime<Utc>>);
    impl MutClock {
        fn new(t: DateTime<Utc>) -> Self {
            Self(StdMutex::new(t))
        }
        fn advance(&self, d: Duration) {
            let mut t = self.0.lock().unwrap();
            *t += d;
        }
    }
    impl Clock for MutClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn base() -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 7, 10, 0, 0, 0).unwrap()
    }

    #[test]
    fn returns_value_within_ttl_and_none_after_expiry() {
        let clock = Arc::new(MutClock::new(base()));
        let cache: InMemoryTtlCache<String, i32> =
            InMemoryTtlCache::new(Duration::seconds(60), clock.clone());

        cache.insert("k".to_string(), 42);
        assert_eq!(cache.get(&"k".to_string()), Some(42));

        // Kept within the TTL.
        clock.advance(Duration::seconds(59));
        assert_eq!(cache.get(&"k".to_string()), Some(42));

        // None after the TTL has elapsed (and lazily removed).
        clock.advance(Duration::seconds(2));
        assert_eq!(cache.get(&"k".to_string()), None);
    }

    #[test]
    fn invalidate_removes_entry() {
        let clock = Arc::new(MutClock::new(base()));
        let cache: InMemoryTtlCache<String, i32> =
            InMemoryTtlCache::new(Duration::seconds(60), clock);
        cache.insert("k".to_string(), 1);
        cache.invalidate(&"k".to_string());
        assert_eq!(cache.get(&"k".to_string()), None);
    }

    #[test]
    fn insert_overwrites_and_refreshes_ttl() {
        let clock = Arc::new(MutClock::new(base()));
        let cache: InMemoryTtlCache<String, i32> =
            InMemoryTtlCache::new(Duration::seconds(60), clock.clone());
        cache.insert("k".to_string(), 1);
        clock.advance(Duration::seconds(59));
        // Overwriting resets the value and the TTL.
        cache.insert("k".to_string(), 2);
        clock.advance(Duration::seconds(59));
        assert_eq!(cache.get(&"k".to_string()), Some(2));
    }

    #[test]
    fn keys_are_independent() {
        let clock = Arc::new(MutClock::new(base()));
        let cache: InMemoryTtlCache<String, i32> =
            InMemoryTtlCache::new(Duration::seconds(60), clock);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.invalidate(&"a".to_string());
        assert_eq!(cache.get(&"a".to_string()), None);
        assert_eq!(cache.get(&"b".to_string()), Some(2));
    }
}
