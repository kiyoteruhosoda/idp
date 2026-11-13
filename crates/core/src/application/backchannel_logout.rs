//! Sending back-channel logout (OpenID Connect Back-Channel Logout 1.0. G5).
//!
//! Logout processing ends by putting "what to send to whom" in a persistent queue ([`enqueue`]); the actual HTTP
//! sending is done by a background worker ([`BackchannelLogoutDeliveryService::deliver_due`]).
//! Previously it was fire-and-forget via `tokio::spawn`: non-2xx only logged a WARN, and unsent ones were lost
//! on process restart (RP-side logout silently dropped, leaving supposedly logged-out sessions at the RP).
//!
//! `logout_token` is signed **right before** sending. Keeping a signed JWT in the DB would leave, for a long time,
//! a value that completes a logout when presented to the RP, and `iat` / `exp` would stay stale on every retry. Only `jti`
//! is fixed when the row is created and kept across retries (the RP can reject duplicate deliveries by `jti`).

use crate::domain::backchannel_logout::{
    retry_backoff, BackchannelLogoutDelivery, NewBackchannelLogoutDelivery,
};
use crate::domain::clock::Clock;
use crate::domain::error::Result;
use crate::domain::id_generator::IdGenerator;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::repositories::BackchannelLogoutDeliveryRepository;
use crate::domain::tenant::TenantId;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// TTL of `logout_token` (seconds). OIDC Back-Channel Logout 1.0 asks for it to be short-lived
/// (not a fixed value in the spec, but as small as possible while absorbing delivery delay).
const LOGOUT_TOKEN_TTL_SECS: i64 = 300;

/// Claims of the back-channel logout token (OpenID Back-Channel Logout 1.0 §2.4).
///
/// `exp` is not required, but without it the RP cannot tell "until when the notice is valid", and an intercepted
/// token could be replayed indefinitely. `sid` is required for per-session logout (without it the RP can only
/// revoke per `sub`, taking down the same user's sessions on other devices too).
#[derive(Debug, Serialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub events: serde_json::Value,
}

impl LogoutTokenClaims {
    fn build(delivery: &BackchannelLogoutDelivery, issuer: String, now: i64) -> Self {
        Self {
            iss: issuer,
            sub: delivery.subject.clone(),
            aud: delivery.client_id.clone(),
            iat: now,
            exp: now + LOGOUT_TOKEN_TTL_SECS,
            jti: delivery.jti.to_string(),
            sid: delivery.sid.clone(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        }
    }
}

/// One notification request to one client (input built by the Application layer).
#[derive(Debug, Clone)]
pub struct LogoutNotification {
    pub client_id: String,
    pub backchannel_logout_uri: String,
}

/// Gets the signing key (a minimal port to keep the dependency on `KeyService` inside the Application layer).
///
/// `KeyService` is concrete (`Arc<KeyService>`), but this service only needs "the current signing key",
/// so it takes a trait so tests can swap it.
#[async_trait::async_trait]
pub trait LogoutTokenSigner: Send + Sync {
    /// Signs the claims and returns a `logout+jwt`.
    async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String>;
}

/// The outlet that POSTs `logout_token` to the RP's `backchannel_logout_uri`.
#[async_trait::async_trait]
pub trait BackchannelLogoutSender: Send + Sync {
    /// Returns the send result. `Ok(())` = 2xx. `Err` = connection failure or non-2xx (reason written in the operations language, English).
    async fn post(&self, uri: &str, logout_token: &str) -> std::result::Result<(), String>;
}

pub struct BackchannelLogoutDeliveryService {
    deliveries: Arc<dyn BackchannelLogoutDeliveryRepository>,
    signer: Arc<dyn LogoutTokenSigner>,
    sender: Arc<dyn BackchannelLogoutSender>,
    ids: Arc<dyn IdGenerator>,
    clock: Arc<dyn Clock>,
    /// Base issuer. The `iss` of `logout_token` is composed per tenant (ADR-0009 §6).
    base_issuer: String,
    /// Attempt limit. Rows that reach it are no longer sent (the give-up is recorded).
    max_attempts: i32,
    /// Maximum number of items handled per worker run.
    batch_size: u32,
}

impl BackchannelLogoutDeliveryService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deliveries: Arc<dyn BackchannelLogoutDeliveryRepository>,
        signer: Arc<dyn LogoutTokenSigner>,
        sender: Arc<dyn BackchannelLogoutSender>,
        ids: Arc<dyn IdGenerator>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        max_attempts: i32,
        batch_size: u32,
    ) -> Self {
        Self {
            deliveries,
            signer,
            sender,
            ids,
            clock,
            base_issuer,
            max_attempts,
            batch_size,
        }
    }

    /// Puts logout notifications in the queue (the synchronous part ends here; no HTTP is sent).
    ///
    /// `sid` identifies the session for per-session logout. `None` only when the session being logged out
    /// could not be identified (the RP falls back to per-`sub` revocation).
    pub async fn enqueue(
        &self,
        tenant_id: TenantId,
        subject: &str,
        sid: Option<&str>,
        notifications: &[LogoutNotification],
    ) -> Result<()> {
        if notifications.is_empty() {
            return Ok(());
        }
        let now = self.clock.now();
        let rows: Vec<BackchannelLogoutDelivery> = notifications
            .iter()
            .map(|n| {
                BackchannelLogoutDelivery::new(
                    NewBackchannelLogoutDelivery {
                        id: self.ids.new_id(),
                        jti: self.ids.new_id(),
                        tenant_id,
                        client_id: n.client_id.clone(),
                        target_uri: n.backchannel_logout_uri.clone(),
                        subject: subject.to_string(),
                        sid: sid.map(str::to_string),
                    },
                    now,
                )
            })
            .collect();
        self.deliveries.enqueue(&rows).await
    }

    /// Processes requests whose send time has come (called periodically by the worker). Returns the number processed.
    pub async fn deliver_due(&self) -> Result<usize> {
        let now = self.clock.now();
        let due = self
            .deliveries
            .claim_due(now, self.max_attempts, self.batch_size)
            .await?;
        let mut handled = 0usize;
        for delivery in due {
            self.deliver_one(&delivery).await;
            handled += 1;
        }
        Ok(handled)
    }

    /// Deletes old settled rows (sent successfully or attempts given up).
    pub async fn purge_settled(&self, retention: chrono::Duration) -> Result<u64> {
        let cutoff = self.clock.now() - retention;
        self.deliveries
            .purge_settled(cutoff, self.max_attempts)
            .await
    }

    async fn deliver_one(&self, delivery: &BackchannelLogoutDelivery) {
        // Check the destination right before sending too (SEC2). Validation at registration alone lets through rows
        // registered before validation was introduced or edited directly in the DB. A request with an invalid
        // destination won't be fixed by retrying, so give it up (advance to `max_attempts`).
        if is_internal_destination(&delivery.target_uri) {
            tracing::warn!(
                client_id = %delivery.client_id,
                "skipped back-channel logout: the registered URI points at an internal destination"
            );
            self.abandon(delivery, "target URI points at an internal destination")
                .await;
            return;
        }

        let issuer = tenant_issuer(&self.base_issuer, delivery.tenant_id);
        let claims = LogoutTokenClaims::build(delivery, issuer, self.clock.now().timestamp());
        let token = match self.signer.sign(&claims).await {
            Ok(t) => t,
            Err(e) => {
                // Failing to sign is a key-side problem that changing the destination won't fix, but it may be transient.
                // Put it up for retry (same backoff as a normal failure).
                self.record_failure(delivery, &format!("failed to sign logout token: {e}"))
                    .await;
                return;
            }
        };

        match self.sender.post(&delivery.target_uri, &token).await {
            Ok(()) => {
                if let Err(e) = self
                    .deliveries
                    .mark_delivered(delivery.id, self.clock.now())
                    .await
                {
                    tracing::error!(error = %e, "failed to record back-channel logout delivery");
                }
            }
            Err(reason) => {
                if delivery.attempts >= self.max_attempts {
                    tracing::warn!(
                        client_id = %delivery.client_id,
                        attempts = delivery.attempts,
                        reason = %reason,
                        "giving up on back-channel logout delivery"
                    );
                }
                self.record_failure(delivery, &reason).await;
            }
        }
    }

    async fn record_failure(&self, delivery: &BackchannelLogoutDelivery, reason: &str) {
        let next = self.clock.now() + retry_backoff(delivery.attempts);
        if let Err(e) = self.deliveries.mark_failed(delivery.id, next, reason).await {
            tracing::error!(error = %e, "failed to record back-channel logout failure");
        }
    }

    /// Gives up a request that retrying won't fix (next time is unchanged; attempts advance to the limit).
    async fn abandon(&self, delivery: &BackchannelLogoutDelivery, reason: &str) {
        // `claim_due` only picks rows with `attempts < max_attempts`, so advancing to the limit means
        // it is never picked again. The reason stays on the row so operations can trace it.
        let far_future = self.clock.now() + chrono::Duration::days(3_650);
        if let Err(e) = self
            .deliveries
            .mark_failed(delivery.id, far_future, reason)
            .await
        {
            tracing::error!(error = %e, "failed to record back-channel logout abandonment");
        }
    }
}

/// Adapter that uses `KeyService` as a [`LogoutTokenSigner`].
pub struct KeyServiceLogoutTokenSigner {
    keys: Arc<crate::application::key_service::KeyService>,
}

impl KeyServiceLogoutTokenSigner {
    pub fn new(keys: Arc<crate::application::key_service::KeyService>) -> Self {
        Self { keys }
    }
}

#[async_trait::async_trait]
impl LogoutTokenSigner for KeyServiceLogoutTokenSigner {
    async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String> {
        let key = self.keys.active_signing_key().await?;
        jwt::sign(
            &key.private_pem,
            &key.kid,
            "logout+jwt",
            &key.algorithm,
            claims,
        )
    }
}

/// Helper for places that want v4 for `jti` among ID generators returning `Uuid`.
/// (`IdGenerator` returns UUIDv7. For `jti`, v4 is preferable as it leaves no room to guess the time.)
pub fn new_jti() -> Uuid {
    Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tenant::TenantId;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct SequentialIds {
        next: Mutex<u128>,
    }
    impl IdGenerator for SequentialIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    #[derive(Default)]
    struct RecordingRepo {
        enqueued: Mutex<Vec<BackchannelLogoutDelivery>>,
        due: Mutex<Vec<BackchannelLogoutDelivery>>,
        delivered: Mutex<Vec<Uuid>>,
        failed: Mutex<Vec<(Uuid, DateTime<Utc>, String)>>,
    }

    #[async_trait::async_trait]
    impl BackchannelLogoutDeliveryRepository for RecordingRepo {
        async fn enqueue(&self, deliveries: &[BackchannelLogoutDelivery]) -> Result<()> {
            self.enqueued.lock().unwrap().extend_from_slice(deliveries);
            Ok(())
        }
        async fn claim_due(
            &self,
            _now: DateTime<Utc>,
            _max_attempts: i32,
            _limit: u32,
        ) -> Result<Vec<BackchannelLogoutDelivery>> {
            Ok(std::mem::take(&mut *self.due.lock().unwrap()))
        }
        async fn mark_delivered(&self, id: Uuid, _at: DateTime<Utc>) -> Result<()> {
            self.delivered.lock().unwrap().push(id);
            Ok(())
        }
        async fn mark_failed(
            &self,
            id: Uuid,
            next_attempt_at: DateTime<Utc>,
            error: &str,
        ) -> Result<()> {
            self.failed
                .lock()
                .unwrap()
                .push((id, next_attempt_at, error.to_string()));
            Ok(())
        }
        async fn purge_settled(&self, _older: DateTime<Utc>, _max: i32) -> Result<u64> {
            Ok(0)
        }
    }

    struct StubSigner;
    #[async_trait::async_trait]
    impl LogoutTokenSigner for StubSigner {
        async fn sign(&self, claims: &LogoutTokenClaims) -> anyhow::Result<String> {
            Ok(serde_json::to_string(claims).unwrap())
        }
    }

    struct StubSender {
        succeed: bool,
        sent: Mutex<Vec<(String, String)>>,
    }
    #[async_trait::async_trait]
    impl BackchannelLogoutSender for StubSender {
        async fn post(&self, uri: &str, token: &str) -> std::result::Result<(), String> {
            self.sent
                .lock()
                .unwrap()
                .push((uri.to_string(), token.to_string()));
            if self.succeed {
                Ok(())
            } else {
                Err("connection refused".to_string())
            }
        }
    }

    fn service(
        repo: Arc<RecordingRepo>,
        sender: Arc<StubSender>,
    ) -> BackchannelLogoutDeliveryService {
        BackchannelLogoutDeliveryService::new(
            repo,
            Arc::new(StubSigner),
            sender,
            Arc::new(SequentialIds {
                next: Mutex::new(0),
            }),
            Arc::new(FixedClock),
            "https://idp.example.com".to_string(),
            5,
            10,
        )
    }

    fn tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn delivery(uri: &str, attempts: i32) -> BackchannelLogoutDelivery {
        BackchannelLogoutDelivery {
            attempts,
            ..BackchannelLogoutDelivery::new(
                NewBackchannelLogoutDelivery {
                    id: Uuid::from_u128(100),
                    jti: Uuid::from_u128(200),
                    tenant_id: tenant(),
                    client_id: "rp-1".to_string(),
                    target_uri: uri.to_string(),
                    subject: "sub-1".to_string(),
                    sid: Some("sid-1".to_string()),
                },
                now(),
            )
        }
    }

    /// The synchronous part of logout sends no HTTP; it only queues rows.
    #[tokio::test]
    async fn enqueue_persists_one_row_per_client_and_sends_nothing() {
        let repo = Arc::new(RecordingRepo::default());
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        svc.enqueue(
            tenant(),
            "sub-1",
            Some("sid-1"),
            &[
                LogoutNotification {
                    client_id: "rp-1".to_string(),
                    backchannel_logout_uri: "https://rp1.example.com/logout".to_string(),
                },
                LogoutNotification {
                    client_id: "rp-2".to_string(),
                    backchannel_logout_uri: "https://rp2.example.com/logout".to_string(),
                },
            ],
        )
        .await
        .unwrap();

        let rows = repo.enqueued.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.sid.as_deref() == Some("sid-1")));
        assert!(rows.iter().all(|r| r.attempts == 0));
        // jti differs per row (so the RP's idempotency check does not treat different notices as the same).
        assert_ne!(rows[0].jti, rows[1].jti);
        assert!(
            sender.sent.lock().unwrap().is_empty(),
            "nothing is sent in the synchronous part"
        );
    }

    #[tokio::test]
    async fn successful_delivery_is_recorded_and_not_retried() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("https://rp1.example.com/logout", 1));
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        assert_eq!(svc.deliver_due().await.unwrap(), 1);
        assert_eq!(repo.delivered.lock().unwrap().len(), 1);
        assert!(repo.failed.lock().unwrap().is_empty());
        // logout_token carries sid and exp (the core of G5).
        let (_, token) = sender.sent.lock().unwrap()[0].clone();
        let claims: serde_json::Value = serde_json::from_str(&token).unwrap();
        assert_eq!(claims["sid"], "sid-1");
        assert_eq!(claims["exp"], now().timestamp() + LOGOUT_TOKEN_TTL_SECS);
        assert_eq!(
            claims["iss"],
            format!("https://idp.example.com/{}", tenant())
        );
    }

    /// Non-2xx and connection failures are recorded as failures and become retryable after backoff.
    #[tokio::test]
    async fn failed_delivery_is_rescheduled_with_backoff() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("https://rp1.example.com/logout", 2));
        let sender = Arc::new(StubSender {
            succeed: false,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender);

        svc.deliver_due().await.unwrap();
        assert!(repo.delivered.lock().unwrap().is_empty());
        let failed = repo.failed.lock().unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].1, now() + retry_backoff(2));
        assert_eq!(failed[0].2, "connection refused");
    }

    /// Internal destinations are not sent to and are given up (SSRF prevention; retrying won't fix it).
    #[tokio::test]
    async fn internal_destinations_are_abandoned_without_sending() {
        let repo = Arc::new(RecordingRepo::default());
        repo.due
            .lock()
            .unwrap()
            .push(delivery("http://127.0.0.1:8080/logout", 1));
        let sender = Arc::new(StubSender {
            succeed: true,
            sent: Mutex::new(Vec::new()),
        });
        let svc = service(repo.clone(), sender.clone());

        svc.deliver_due().await.unwrap();
        assert!(sender.sent.lock().unwrap().is_empty());
        assert!(repo.delivered.lock().unwrap().is_empty());
        let failed = repo.failed.lock().unwrap();
        assert_eq!(failed.len(), 1);
        // The next time is pushed far ahead so it drops out of retries.
        assert!(failed[0].1 > now() + chrono::Duration::days(3_000));
    }
}
