//! Rate limiting of login attempts (per IP, design spec §4.3). Implemented in the infrastructure
//! layer.

use chrono::{DateTime, Utc};

pub trait LoginRateLimiter: Send + Sync {
    /// Records one attempt for `key` (IP address etc.) and returns `true` if within the limit.
    /// Returns `false` when over the limit (the caller rejects the login).
    fn check_and_record(&self, key: &str, now: DateTime<Utc>) -> bool;
}
