//! Load gate for the token endpoints (`/token`, `/introspect`, `/revoke`) (SEC10).
//!
//! These three use RFC 6749 §2.3.1 client authentication and **verify a confidential client's
//! `client_secret` with Argon2id (19 MiB, 2 iterations)**. Brute force is unrealistic, but a
//! memory-hard function is itself an amplifier: with a request of a few hundred bytes an attacker can
//! force the server to allocate 19 MiB and spend tens of milliseconds of CPU. And since verification is a
//! synchronous function running on tokio worker threads, a burst **stalls responses of every endpoint,
//! not just token issuance**.
//!
//! # Two-stage gate
//!
//! 1. **A cap on concurrency** (`TOKEN_ENDPOINT_MAX_CONCURRENCY`). Bounds peak memory to
//!    "cap × 19 MiB" and CPU to "cap workers". What matters is that it **works without knowing the
//!    source**: it is the only line of defence that holds when `TRUST_FORWARDED_HEADERS` is the default
//!    `false` (api does not know the client IP). Overflowing requests are dropped without waiting. Making
//!    them wait only turns CPU saturation into "queue memory", which makes things worse.
//! 2. **Per-source-IP rate limit** (`TOKEN_ENDPOINT_RATE_LIMIT_*`). Prevents a single source from
//!    occupying the whole budget and locking out legitimate RPs. Works only when the IP is known
//!    (`TRUST_FORWARDED_HEADERS = true`).
//!
//! # Response
//!
//! RFC 6749 §5.2 token endpoint error codes have no value meaning "busy".
//! We use §4.1.2.1's `temporarily_unavailable` (the only code for temporary overload), and
//! the HTTP status follows reality (out of slots = 503, per-source excess = 429).
//! `Retry-After` tells the client how long to wait before retrying.

use crate::domain::clock::Clock;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::presentation::state::AppState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Retry interval (seconds) sent when out of slots or rate-limited. No need to wait the whole window;
/// it only has to convey "don't hit again immediately".
const RETRY_AFTER_SECS: u32 = 5;

/// Gate decision.
pub enum Admission {
    /// May pass. `_permit` is held until the response is returned (dropping it frees the slot).
    Admitted(Option<OwnedSemaphorePermit>),
    /// Exceeded the per-source rate limit.
    RateLimited,
    /// No concurrency slot is free.
    AtCapacity,
}

/// Load gate for the token endpoints (SEC10).
///
/// It is kept separate from axum so the decision (under which condition and for which reason to drop)
/// can be tested without a DB or router. The middleware only maps it to HTTP.
pub struct TokenEndpointLoadGate {
    /// Concurrency slots. `None` means unlimited (`TOKEN_ENDPOINT_MAX_CONCURRENCY = 0`).
    slots: Option<Arc<Semaphore>>,
    /// Per-source-IP rate limit. `None` means disabled (`..._MAX_REQUESTS = 0`).
    ///
    /// It is the same sliding window implementation as login, but **the limiter is not shared**
    /// (so RPs fetching tokens do not eat into the login attempt budget).
    rate_limiter: Option<Arc<dyn LoginRateLimiter>>,
    clock: Arc<dyn Clock>,
}

impl TokenEndpointLoadGate {
    /// Builds from config. If both caps are `0`, the gate lets everything through.
    pub fn from_config(config: &crate::config::Config, clock: Arc<dyn Clock>) -> Self {
        Self {
            slots: config
                .token_endpoint_max_concurrency()
                .map(|permits| Arc::new(Semaphore::new(permits))),
            rate_limiter: config.token_endpoint_rate_limit().map(|(max, window)| {
                Arc::new(InMemoryLoginRateLimiter::new(
                    max,
                    chrono::Duration::from_std(window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(60)),
                )) as Arc<dyn LoginRateLimiter>
            }),
            clock,
        }
    }

    /// Builds with caps given directly, for tests.
    pub fn new(
        max_concurrency: Option<usize>,
        rate_limit: Option<(usize, Duration)>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            slots: max_concurrency.map(|permits| Arc::new(Semaphore::new(permits))),
            rate_limiter: rate_limit.map(|(max, window)| {
                Arc::new(InMemoryLoginRateLimiter::new(
                    max,
                    chrono::Duration::from_std(window)
                        .unwrap_or_else(|_| chrono::Duration::seconds(60)),
                )) as Arc<dyn LoginRateLimiter>
            }),
            clock,
        }
    }

    /// Decides whether one request may pass. Even when `client_ip` is `None` (source unknown),
    /// the concurrency cap applies.
    pub fn admit(&self, client_ip: Option<&str>) -> Admission {
        // Check the per-source rate limit first. If the slot (permit) were taken before rejecting, rejected
        // requests would occupy slots even briefly and an attacker could drain them.
        if let (Some(limiter), Some(ip)) = (&self.rate_limiter, client_ip) {
            if !limiter.check_and_record(ip, self.clock.now()) {
                return Admission::RateLimited;
            }
        }
        match &self.slots {
            // Drop without waiting (a queue only turns CPU saturation into memory saturation; it solves nothing).
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Admission::Admitted(Some(permit)),
                Err(_) => Admission::AtCapacity,
            },
            None => Admission::Admitted(None),
        }
    }
}

/// Load gate for the token endpoints. The router attaches it with `route_layer` to those routes only.
pub async fn limit_token_endpoint_load(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&headers, state.config.trust_forwarded_headers());
    // The permit is held until the response is returned (do not drop `_permit` early).
    let _permit = match state.token_endpoint_load.admit(ip.as_deref()) {
        Admission::Admitted(permit) => permit,
        Admission::RateLimited => {
            tracing::warn!(
                target: "security",
                "token endpoint rate limit exceeded for a single source"
            );
            return too_many_requests();
        }
        Admission::AtCapacity => {
            tracing::warn!(
                target: "security",
                "token endpoint concurrency limit reached; shedding the request"
            );
            return service_overloaded();
        }
    };

    next.run(request).await
}

/// Client IP. Uses the same derivation as `request_context` (the rightmost `X-Forwarded-For`; SEC1).
/// `None` when not trusted (= no per-IP limiting).
fn client_ip(headers: &HeaderMap, trust_forwarded: bool) -> Option<String> {
    if !trust_forwarded {
        return None;
    }
    assay_contracts::forwarded::client_ip(
        headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok()),
    )
}

fn too_many_requests() -> Response {
    oauth_error(
        StatusCode::TOO_MANY_REQUESTS,
        "too many token endpoint requests from this client; retry later",
    )
}

fn service_overloaded() -> Response {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "the token endpoint is at capacity; retry later",
    )
}

/// The wording is **not translated** (`CLAUDE.md` "Not translated": OAuth/OIDC protocol errors are fixed
/// values for RPs, and RP logs and automation may depend on the wording).
fn oauth_error(status: StatusCode, description: &'static str) -> Response {
    (
        status,
        [
            (header::RETRY_AFTER, RETRY_AFTER_SECS.to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        axum::Json(json!({
            "error": "temporarily_unavailable",
            "error_description": description,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 8, 10, 0, 0, 0).unwrap()
        }
    }

    fn gate(
        max_concurrency: Option<usize>,
        rate_limit: Option<(usize, Duration)>,
    ) -> TokenEndpointLoadGate {
        TokenEndpointLoadGate::new(max_concurrency, rate_limit, Arc::new(FixedClock))
    }

    fn admitted(a: &Admission) -> bool {
        matches!(a, Admission::Admitted(_))
    }

    /// The concurrency cap applies **even without knowing the source**. When `TRUST_FORWARDED_HEADERS`
    /// is the default `false`, this is the only line of defence against Argon2 memory amplification.
    #[test]
    fn concurrency_is_capped_even_when_the_source_is_unknown() {
        let gate = gate(Some(2), None);
        let first = gate.admit(None);
        let second = gate.admit(None);
        assert!(admitted(&first));
        assert!(admitted(&second));
        assert!(matches!(gate.admit(None), Admission::AtCapacity));

        // Releasing the permit frees the slot.
        drop(first);
        assert!(admitted(&gate.admit(None)));
    }

    /// Per-source excess is decided **before** taking a slot. If a slot were taken before rejecting,
    /// rejected requests would occupy slots briefly and an attacker could drain the concurrency slots.
    #[test]
    fn a_rate_limited_source_never_consumes_a_concurrency_slot() {
        let gate = gate(Some(1), Some((1, Duration::from_secs(60))));
        let held = gate.admit(Some("203.0.113.9"));
        assert!(admitted(&held));
        // The second request from the same source fails on the rate limit (not out of slots).
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::RateLimited
        ));
        // Seen from another source, only one slot (held) is occupied.
        assert!(matches!(
            gate.admit(Some("198.51.100.4")),
            Admission::AtCapacity
        ));
        // Once the slot frees, a source that has not used a slot yet passes.
        drop(held);
        assert!(admitted(&gate.admit(Some("192.0.2.30"))));
    }

    /// Requests dropped for lack of slots still count toward the source's total. Otherwise, while slots are
    /// full, hitting never touches the rate limit and an attacker can keep hitting while waiting for a free slot.
    #[test]
    fn a_request_shed_for_capacity_still_counts_against_its_source() {
        let gate = gate(Some(1), Some((2, Duration::from_secs(60))));
        let held = gate.admit(Some("203.0.113.9"));
        assert!(admitted(&held));
        // Second request from the same source: passes the rate limit (cap 2) but there is no slot.
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::AtCapacity
        ));
        // The third fails on the rate limit regardless of slot availability.
        drop(held);
        assert!(matches!(
            gate.admit(Some("203.0.113.9")),
            Admission::RateLimited
        ));
    }

    /// Counted independently per source (one RP's burst does not drag down other RPs).
    #[test]
    fn rate_limits_are_counted_per_source() {
        let gate = gate(None, Some((1, Duration::from_secs(60))));
        assert!(admitted(&gate.admit(Some("203.0.113.1"))));
        assert!(matches!(
            gate.admit(Some("203.0.113.1")),
            Admission::RateLimited
        ));
        assert!(admitted(&gate.admit(Some("203.0.113.2"))));
    }

    /// If both are `0` (disabled) everything passes. The gate must not silently reject all when defaults are changed.
    #[test]
    fn both_limits_disabled_admits_everything() {
        let gate = gate(None, None);
        for _ in 0..1_000 {
            assert!(admitted(&gate.admit(Some("203.0.113.1"))));
        }
    }

    /// Do not take the IP from untrusted headers (SEC1). Otherwise just claiming different sources
    /// would bypass the rate limit indefinitely.
    #[test]
    fn forwarded_headers_are_ignored_unless_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&headers, false), None);
        assert_eq!(client_ip(&headers, true).as_deref(), Some("203.0.113.7"));
    }
}
