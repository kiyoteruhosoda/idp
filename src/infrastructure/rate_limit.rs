//! インメモリのログインレート制限（IP 単位、スライディングウィンドウ）。
//!
//! MVP は単一インスタンス前提のためプロセス内メモリで管理する。
//! スケールアウト時は Redis 等の共有ストア実装に差し替える（`LoginRateLimiter` が DIP 境界）。

use crate::domain::rate_limit::LoginRateLimiter;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct InMemoryLoginRateLimiter {
    max_attempts: usize,
    window: Duration,
    attempts: Mutex<HashMap<String, Vec<DateTime<Utc>>>>,
}

impl InMemoryLoginRateLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            attempts: Mutex::new(HashMap::new()),
        }
    }
}

impl LoginRateLimiter for InMemoryLoginRateLimiter {
    fn check_and_record(&self, key: &str, now: DateTime<Utc>) -> bool {
        let mut map = self.attempts.lock().expect("rate limiter lock poisoned");
        let cutoff = now - self.window;
        // ウィンドウ外のエントリを掃除する（キー全体の肥大化も防ぐ）。
        map.retain(|_, times| {
            times.retain(|t| *t > cutoff);
            !times.is_empty()
        });

        let times = map.entry(key.to_string()).or_default();
        if times.len() >= self.max_attempts {
            return false;
        }
        times.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn allows_up_to_max_then_rejects_within_window() {
        let limiter = InMemoryLoginRateLimiter::new(3, Duration::minutes(5));
        let now = Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap();
        assert!(limiter.check_and_record("203.0.113.1", now));
        assert!(limiter.check_and_record("203.0.113.1", now));
        assert!(limiter.check_and_record("203.0.113.1", now));
        assert!(!limiter.check_and_record("203.0.113.1", now));
        // 別キーは独立。
        assert!(limiter.check_and_record("203.0.113.2", now));
        // ウィンドウ経過後は再び許可される。
        let later = now + Duration::minutes(6);
        assert!(limiter.check_and_record("203.0.113.1", later));
    }
}
