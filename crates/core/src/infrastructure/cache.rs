//! インメモリの TTL キャッシュ（ADR-0009 §7）。
//!
//! MVP は単一インスタンス前提のためプロセス内メモリで管理する。有効期限は挿入時刻 + TTL で判定し、
//! `get` 時に期限切れエントリを遅延削除する。時刻は `Clock` 越しに取得し（テストで固定可能）、
//! スケールアウト時は共有ストア実装へ差し替える（`Cache` trait が DIP 境界）。

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

/// キー空間ごとに 1 インスタンスを注入して使う汎用 TTL キャッシュ。
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
            // 期限切れは遅延削除する（キー空間の肥大化も防ぐ）。
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

    /// テスト内で任意に進められる Clock。
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

        // TTL 内は保持。
        clock.advance(Duration::seconds(59));
        assert_eq!(cache.get(&"k".to_string()), Some(42));

        // TTL 経過後は None（かつ遅延削除される）。
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
        // 上書きで値と TTL を張り直す。
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
