//! Back-channel logout delivery requests (`backchannel_logout_deliveries`. G5).
//!
//! Row representation for moving OpenID Connect Back-Channel Logout 1.0 notifications from "fire and forget"
//! to "persistent queue + retry". Prevents logouts from being silently lost just because the RP was down
//! at that moment or the network was cut.
//!
//! The signed `logout_token` is not stored (storing it would leave "a value that completes a logout when shown to the RP"
//! in the DB for a long time, and `iat`/`exp` would stay stale on every retry). Only the claim material is kept, and it
//! is signed with the current signing key right before sending. Only `jti` is fixed when the row is created and does not change on retry (the RP can
//! reject duplicate deliveries by `jti`).
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// A back-channel logout notification request to one client.
#[derive(Debug, Clone)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    /// The tenant where the logout happened (derives the `iss` of the `logout_token`).
    pub tenant_id: TenantId,
    /// The client to notify (`aud` of the `logout_token`).
    pub client_id: String,
    pub target_uri: String,
    /// `sub` of the `logout_token` (the user's externally exposed identifier).
    pub subject: String,
    /// `sid` of the `logout_token`. Used for per-session logout (`None` if unknown).
    pub sid: Option<String>,
    /// `jti` of the `logout_token`. Does not change on retry.
    pub jti: Uuid,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Values for building a new delivery request (attempt count and times are decided by [`BackchannelLogoutDelivery::new`]).
#[derive(Debug, Clone)]
pub struct NewBackchannelLogoutDelivery {
    pub id: Uuid,
    /// `jti` of the `logout_token`. Fixed when the row is created, since it does not change on retry.
    pub jti: Uuid,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub target_uri: String,
    pub subject: String,
    pub sid: Option<String>,
}

impl BackchannelLogoutDelivery {
    /// Builds a new delivery request (next attempt is immediate).
    pub fn new(new: NewBackchannelLogoutDelivery, now: DateTime<Utc>) -> Self {
        Self {
            id: new.id,
            tenant_id: new.tenant_id,
            client_id: new.client_id,
            target_uri: new.target_uri,
            subject: new.subject,
            sid: new.sid,
            jti: new.jti,
            attempts: 0,
            next_attempt_at: now,
            last_error: None,
            delivered_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_delivered(&self) -> bool {
        self.delivered_at.is_some()
    }
}

/// Retry wait time (exponential backoff).
///
/// `attempts` is **the count as of finishing that attempt** (1 after the first failure). The cap exists
/// so that the interval does not grow without bound for an RP that is down for a long time, effectively abandoning it.
pub fn retry_backoff(attempts: i32) -> Duration {
    const BASE_SECS: i64 = 30;
    const MAX_SECS: i64 = 3_600;
    let exponent = attempts.clamp(1, 16) - 1;
    let secs = BASE_SECS.saturating_mul(1i64 << exponent.min(20));
    Duration::seconds(secs.min(MAX_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(retry_backoff(1), Duration::seconds(30));
        assert_eq!(retry_backoff(2), Duration::seconds(60));
        assert_eq!(retry_backoff(3), Duration::seconds(120));
        // Does not exceed the cap (1 hour).
        assert_eq!(retry_backoff(20), Duration::seconds(3_600));
        // Zero or negative input also falls back to the minimum wait (so a caller mix-up does not cause a zero-wait loop).
        assert_eq!(retry_backoff(0), Duration::seconds(30));
        assert_eq!(retry_backoff(-5), Duration::seconds(30));
    }
}
