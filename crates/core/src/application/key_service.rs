//! Signing key use cases: bootstrap (ensuring an ACTIVE key), fetching signing material, building JWKS, admin operations.
#![allow(dead_code)]

use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;
use crate::domain::repositories::SigningKeyRepository;
use crate::domain::signing_key::{current_signer_at, SigningKey};
use crate::domain::values::{SigningAlgorithm, SigningKeyStatus};
use crate::domain::{crypto, jwt};
use chrono::Duration;
use std::sync::Arc;

/// Key lifetime (days until not_after for a newly generated key).
const KEY_VALIDITY_DAYS: i64 = 365;

/// Material of the ACTIVE key used for signing (decrypted private key PEM, kid, algorithm).
pub struct ActiveSigningKey {
    pub kid: String,
    pub algorithm: String,
    pub private_pem: String,
}

/// Signing key management error.
#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct KeyService {
    repo: Arc<dyn SigningKeyRepository>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
}

impl KeyService {
    pub fn new(
        repo: Arc<dyn SigningKeyRepository>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
    ) -> Self {
        Self {
            repo,
            clock,
            key_encryption_key,
        }
    }

    /// If there is no **key that can sign now**, generates a key pair and persists it with the private key encrypted (idempotent).
    ///
    /// The check is `current_signer_at` —— not "is there an ACTIVE row". A successor key that is only published
    /// (`not_before` in the future) or a key left ACTIVE after expiring cannot sign, so a state with
    /// only those needs bootstrapping.
    ///
    /// Insertion goes through `insert_if_no_active` (the repository's exclusive section), so keys are not generated
    /// twice even when several instances start at once (rolling deploys, parallel tests) (SEC5).
    /// The side that loses the exclusive section discards its generated key material and treats it as success.
    pub async fn ensure_active_key(&self) -> anyhow::Result<()> {
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;
        if current_signer_at(&keys, self.clock.now()).is_some() {
            return Ok(());
        }
        // **Carry over the algorithm of the key used just before** (same rule as replenishment in `rotate_if_needed`).
        // Hard-coding it would silently send an environment running ES256 back to RS256 just by going through this path.
        let algorithm = keys
            .first()
            .and_then(|key| SigningAlgorithm::parse(&key.algorithm).ok())
            .unwrap_or(SigningAlgorithm::Rs256);
        // Bootstrap **has no grace period**. There is no key that can sign, so waiting would mean
        // no tokens can be issued in the meantime.
        let key = self.new_key_material(algorithm, Duration::zero()).await?;
        let inserted = self
            .repo
            .insert_if_no_active(&key)
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap signing key: {e}"))?;
        if inserted {
            tracing::info!(kid = %key.kid, "bootstrapped the active signing key");
        } else {
            tracing::info!("active signing key already bootstrapped by another instance");
        }
        Ok(())
    }

    /// The ACTIVE key used for signing (returns it with the private key decrypted).
    pub async fn active_signing_key(&self) -> anyhow::Result<ActiveSigningKey> {
        let key = self
            .find_active_key()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no active signing key"))?;
        let private_bytes = crypto::decrypt(&key.private_key_encrypted, &self.key_encryption_key)?;
        let private_pem = String::from_utf8(private_bytes)
            .map_err(|e| anyhow::anyhow!("decrypted private key is not valid UTF-8: {e}"))?;
        Ok(ActiveSigningKey {
            kid: key.kid,
            algorithm: key.algorithm,
            private_pem,
        })
    }

    /// `kid` of the key currently used for signing. **Does not decrypt the private key**, so use this when a
    /// public endpoint (SAML metadata) needs only the `kid`.
    pub async fn signing_kid(&self) -> anyhow::Result<Option<String>> {
        Ok(self.find_active_key().await?.map(|key| key.kid))
    }

    /// Builds the JWKS (ACTIVE + RETIRED keys whose not_after is in the future).
    pub async fn jwks(&self) -> anyhow::Result<jwt::Jwks> {
        let keys = self
            .repo
            .list_published()
            .await
            .map_err(|e| anyhow::anyhow!("list published keys: {e}"))?;
        let mut jwk_list = Vec::with_capacity(keys.len());
        for key in keys {
            jwk_list.push(jwt::public_jwk(&key.kid, &key.algorithm, &key.public_key)?);
        }
        Ok(jwt::Jwks { keys: jwk_list })
    }

    // ── Automatic rotation (K2) ─────────────────────────────────────────────────────

    /// Advances key rotation (idempotent; called periodically from a background task).
    ///
    /// **Rotation proceeds in 3 stages.** Doing it all in one call would make publishing and starting to sign
    /// happen at the same time, and verification at RPs caching the JWKS would fail.
    ///
    /// 1. When fewer than `lead_days` days remain until the current key's `not_after`, **publish a successor key**
    ///    (`not_before` is `publish_lead_hours` later). It appears in the JWKS immediately, but signing still uses the old key.
    /// 2. When `not_before` arrives, signing moves to the successor automatically (the `current_signer_at` rule).
    ///    No call is needed for this.
    /// 3. A call after the handover **retires the ACTIVE keys that were overtaken**.
    ///
    /// Putting retirement in stage 3 is the point. Retiring the old key at publish time would leave no key
    /// that can sign until `not_before` arrives.
    ///
    /// If there is no ACTIVE key at all, one is replenished (e.g. an admin retired the last key).
    pub async fn rotate_if_needed(
        &self,
        lead_days: u32,
        publish_lead_hours: u32,
    ) -> anyhow::Result<()> {
        let now = self.clock.now();
        // Fetch the list once and decide on the current key, successor and overtaken keys together.
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;

        let Some(active) = current_signer_at(&keys, now).cloned() else {
            // **Carry over the algorithm of the key used just before.** Hard-coding it would silently send an
            // environment running ES256 back to RS256 just by going through this path (the UI can also choose ES256).
            let algorithm = keys
                .first()
                .and_then(|key| SigningAlgorithm::parse(&key.algorithm).ok())
                .unwrap_or(SigningAlgorithm::Rs256);
            tracing::warn!(
                algorithm = %algorithm.as_str(),
                "no usable signing key found during rotation check; bootstrapping"
            );
            self.generate_key_internal(algorithm, Duration::zero())
                .await?;
            return Ok(());
        };

        // Stage 3: retire ACTIVE keys overtaken by the current key. A successor whose `not_before` is in the future
        // is excluded (its turn just hasn't come yet; it wasn't overtaken).
        for key in keys
            .iter()
            .filter(|key| key.status == SigningKeyStatus::Active)
            .filter(|key| key.kid != active.kid && key.not_before <= now)
        {
            self.repo
                .update_status(&key.kid, SigningKeyStatus::Retired)
                .await
                .map_err(|e| anyhow::anyhow!("retire superseded key {}: {e}", key.kid))?;
            tracing::info!(
                kid = %key.kid,
                superseded_by = %active.kid,
                "retired signing key superseded by the current signer"
            );
        }

        // Stage 1: if a successor is already published, all that remains is to wait for `not_before`.
        if let Some(pending) = keys.iter().find(|key| key.is_pending_at(now)) {
            tracing::debug!(
                kid = %pending.kid,
                signs_from = %pending.not_before,
                "a successor signing key is already published; waiting for its not_before"
            );
            return Ok(());
        }

        let remaining = active.not_after - now;
        if remaining > Duration::days(lead_days as i64) {
            return Ok(());
        }

        // **The signing handover must happen before the current key expires.** Even if `publish_lead_hours`
        // is longer than `lead_days`, cap it so it does not pass the current key's `not_after`
        // (passing it would leave no key that can sign from the moment of expiry until `not_before`).
        let signs_from = std::cmp::min(
            now + Duration::hours(publish_lead_hours as i64),
            active.not_after,
        );

        tracing::info!(
            kid = %active.kid,
            not_after = %active.not_after,
            remaining_hours = remaining.num_hours(),
            signs_from = %signs_from,
            "signing key approaching expiry; publishing a successor"
        );

        let algorithm = SigningAlgorithm::parse(&active.algorithm)
            .map_err(|e| anyhow::anyhow!("unknown algorithm on active key: {e}"))?;
        self.generate_key_internal(algorithm, signs_from - now)
            .await?;

        Ok(())
    }

    // ── Admin operations ──────────────────────────────────────────────────────────────

    /// Returns all signing keys in descending creation order (for the admin UI).
    pub async fn list_keys(&self) -> Result<Vec<SigningKey>, KeyManagementError> {
        self.repo
            .list_all()
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// Generates a new key with the given algorithm and registers it as ACTIVE.
    ///
    /// With `publish_lead`, the key appears in the JWKS immediately but is not used for signing (`not_before`
    /// is that much in the future). **This is the normal way to rotate** —— it gives RPs time to pick up the new `kid`.
    /// `Duration::zero()` means "sign with it right now", used only when there is no room for a grace period,
    /// such as a key compromise.
    pub async fn generate_key(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> Result<SigningKey, KeyManagementError> {
        let publish_lead = self
            .capped_publish_lead(publish_lead)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?;
        self.generate_key_internal(algorithm, publish_lead)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    /// Changes the ACTIVE key with the given kid to RETIRED.
    ///
    /// **The last key that can sign is not retired.** Retiring it would stop token issuance from that moment,
    /// and replenishment by `rotate_if_needed` doesn't run until the next check (hourly by default). No path is left
    /// that stops token issuance with one click. Even if a published successor exists, it doesn't count as
    /// "able to sign" until its `not_before` has arrived.
    pub async fn retire_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?;
        let key = keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Retired {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-retire-failed",
            )));
        }

        let now = self.clock.now();
        let another_key_can_sign = keys
            .iter()
            .any(|other| other.kid != kid && other.is_usable_for_signing_at(now));
        if !another_key_can_sign {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-retire-last-active",
            )));
        }

        self.repo
            .update_status(kid, SigningKeyStatus::Retired)
            .await
            .map_err(|e| match e {
                DomainError::NotFound => KeyManagementError::NotFound(kid.to_string()),
                other => KeyManagementError::Internal(other.to_string()),
            })
    }

    /// Deletes the key with the given kid. Deleting an ACTIVE key is forbidden (retire it first).
    pub async fn delete_key(&self, kid: &str) -> Result<(), KeyManagementError> {
        let key = self
            .repo
            .find_by_kid(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))?
            .ok_or_else(|| KeyManagementError::NotFound(kid.to_string()))?;

        if key.status == SigningKeyStatus::Active {
            return Err(KeyManagementError::Validation(MessageKey::new(
                "api-signing-key-delete-failed",
            )));
        }

        self.repo
            .delete(kid)
            .await
            .map_err(|e| KeyManagementError::Internal(e.to_string()))
    }

    // ── Private helpers ────────────────────────────────────────────────────────────────

    async fn find_active_key(&self) -> anyhow::Result<Option<SigningKey>> {
        self.repo
            .find_active()
            .await
            .map_err(|e| anyhow::anyhow!("find active key: {e}"))
    }

    /// Rounds the grace period from publishing to starting to sign into **a range where signing keys never run out**.
    ///
    /// Applies to manual generation the same cap that `rotate_if_needed` applies to automatic generation.
    /// - Do not pass the current key's `not_after`. Passing it leaves no key that can sign from the current key's
    ///   expiry until `not_before`.
    /// - If no key can sign now, no grace period. There is no one to wait for (an old key still signing),
    ///   and tokens just couldn't be issued during the grace period.
    async fn capped_publish_lead(&self, publish_lead: Duration) -> anyhow::Result<Duration> {
        if publish_lead <= Duration::zero() {
            return Ok(Duration::zero());
        }
        let keys = self
            .repo
            .list_all()
            .await
            .map_err(|e| anyhow::anyhow!("list signing keys: {e}"))?;
        let now = self.clock.now();
        let Some(active) = current_signer_at(&keys, now) else {
            return Ok(Duration::zero());
        };
        Ok(std::cmp::min(publish_lead, active.not_after - now))
    }

    async fn generate_key_internal(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> anyhow::Result<SigningKey> {
        let key = self.new_key_material(algorithm, publish_lead).await?;
        self.repo
            .insert(&key)
            .await
            .map_err(|e| anyhow::anyhow!("insert signing key: {e}"))?;
        tracing::info!(
            kid = %key.kid,
            algorithm = %algorithm.as_str(),
            signs_from = %key.not_before,
            "generated new signing key"
        );
        Ok(key)
    }

    /// Assembles the material of a new ACTIVE key (key pair generation, private key encryption, kid assignment) without persisting.
    ///
    /// Key pair generation is offloaded to the blocking pool (`generate_keypair` below). Encrypting the private key (AES-GCM)
    /// is quick, so it runs inline.
    async fn new_key_material(
        &self,
        algorithm: SigningAlgorithm,
        publish_lead: Duration,
    ) -> anyhow::Result<SigningKey> {
        let (private_pem, public_pem) = generate_keypair(algorithm).await?;
        let now = self.clock.now();
        // When signing starts. **The lifetime is counted from here** —— counting from `now` would shorten the
        // usable period by the grace period.
        let not_before = now + publish_lead.max(Duration::zero());
        let alg_tag = algorithm.as_str().to_lowercase().replace("256", "");
        let kid = format!(
            "{}-{}-{}",
            now.format("%Y%m%d"),
            alg_tag,
            crypto::random_token(6)
        );
        let private_key_encrypted =
            crypto::encrypt(private_pem.as_bytes(), &self.key_encryption_key)?;

        Ok(SigningKey {
            kid,
            algorithm: algorithm.as_str().to_string(),
            public_key: public_pem,
            private_key_encrypted,
            status: SigningKeyStatus::Active,
            not_before,
            not_after: not_before + Duration::days(KEY_VALIDITY_DAYS),
            created_at: now,
            updated_at: now,
        })
    }
}

/// Generates a signing key pair **on the blocking pool** and returns `(private key PEM, public key PEM)`.
///
/// RSA key generation searches for primes, so it is CPU-bound with a long-tailed run time (hundreds of ms to seconds). Calling it
/// directly in an async task occupies a tokio worker thread, and **every other future** on that thread
/// (HTTP request handling, DB I/O, a bootstrap task holding the exclusive section) makes no progress until generation finishes.
/// When concurrency exceeds the number of workers, the task holding the advisory lock is not polled, and waiters
/// pile up holding pool connections (-> connections dropped by server-side timeouts).
/// Offloading to a dedicated thread with `spawn_blocking` lets the runtime advance other futures during generation.
async fn generate_keypair(algorithm: SigningAlgorithm) -> anyhow::Result<(String, String)> {
    tokio::task::spawn_blocking(move || match algorithm {
        SigningAlgorithm::Rs256 => jwt::generate_rsa_keypair(),
        SigningAlgorithm::Es256 => jwt::generate_ec_keypair(),
    })
    .await
    .map_err(|e| anyhow::anyhow!("signing key generation task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::clock::Clock;
    use crate::domain::error::Result as RepoResult;
    use chrono::{DateTime, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::Notify;

    /// A clock that can be advanced (`rotate_if_needed` behaves differently depending on "when it was called").
    struct TestClock(Mutex<DateTime<Utc>>);

    impl TestClock {
        fn at(rfc3339: &str) -> Arc<Self> {
            Arc::new(Self(Mutex::new(parse(rfc3339))))
        }
        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().unwrap();
            *now += by;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    fn parse(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    /// In-memory signing key repository. `find_active` selects by **the same rule** as the production SQL
    /// (`current_signer_at`). Writing a different rule here would make tests pass while behaving differently from production.
    #[derive(Default)]
    struct FakeRepo(Mutex<Vec<SigningKey>>);

    impl FakeRepo {
        fn with(keys: Vec<SigningKey>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(keys)))
        }
        fn snapshot(&self) -> Vec<SigningKey> {
            self.0.lock().unwrap().clone()
        }
        fn get(&self, kid: &str) -> SigningKey {
            self.snapshot()
                .into_iter()
                .find(|key| key.kid == kid)
                .expect("key exists")
        }
    }

    #[async_trait::async_trait]
    impl SigningKeyRepository for FakeRepo {
        async fn insert(&self, key: &SigningKey) -> RepoResult<()> {
            self.0.lock().unwrap().insert(0, key.clone());
            Ok(())
        }
        async fn insert_if_no_active(&self, _key: &SigningKey) -> RepoResult<bool> {
            // The production condition is the same as `find_active` (ACTIVE and within validity), with the time taken from
            // the SQL side's `UTC_TIMESTAMP(6)`. An approximation here would drift from production, so it is not used.
            unreachable!("not exercised by these tests")
        }
        async fn find_active(&self) -> RepoResult<Option<SigningKey>> {
            unreachable!("rotate_if_needed reads the whole list")
        }
        async fn list_published(&self) -> RepoResult<Vec<SigningKey>> {
            unreachable!("not exercised by these tests")
        }
        async fn find_by_kid(&self, kid: &str) -> RepoResult<Option<SigningKey>> {
            Ok(self.snapshot().into_iter().find(|key| key.kid == kid))
        }
        async fn list_all(&self) -> RepoResult<Vec<SigningKey>> {
            // Descending creation order, same as production.
            let mut keys = self.snapshot();
            keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
            Ok(keys)
        }
        async fn update_status(&self, kid: &str, status: SigningKeyStatus) -> RepoResult<()> {
            let mut keys = self.0.lock().unwrap();
            match keys.iter_mut().find(|key| key.kid == kid) {
                Some(key) => {
                    key.status = status;
                    Ok(())
                }
                None => Err(DomainError::NotFound),
            }
        }
        async fn delete(&self, kid: &str) -> RepoResult<()> {
            self.0.lock().unwrap().retain(|key| key.kid != kid);
            Ok(())
        }
    }

    /// A stand-in for an existing key. **Uses ES256** —— RSA key generation is heavy for tests.
    fn existing(
        kid: &str,
        status: SigningKeyStatus,
        not_before: &str,
        not_after: &str,
    ) -> SigningKey {
        SigningKey {
            kid: kid.to_string(),
            algorithm: "ES256".to_string(),
            public_key: String::new(),
            private_key_encrypted: String::new(),
            status,
            not_before: parse(not_before),
            not_after: parse(not_after),
            created_at: parse(not_before),
            updated_at: parse(not_before),
        }
    }

    fn service(repo: Arc<FakeRepo>, clock: Arc<TestClock>) -> KeyService {
        KeyService::new(repo, clock, [7u8; 32])
    }

    const LEAD_DAYS: u32 = 30;
    const PUBLISH_LEAD_HOURS: u32 = 24;

    /// Stage 1: when expiry approaches, **only publish a successor key**. The old key keeps signing and is not retired.
    ///
    /// Retiring the old key here would leave no key that can sign until the successor's `not_before` arrives.
    /// Publishing and starting to sign at the same time makes verification fail at RPs caching the JWKS.
    #[tokio::test]
    async fn a_key_near_expiry_gets_a_successor_that_is_published_but_not_signing() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z", // 10 days left < lead 30 days
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        let keys = repo.snapshot();
        assert_eq!(keys.len(), 2, "a successor must be published");
        let now = clock.now();
        let successor = keys.iter().find(|key| key.kid != "old").expect("successor");
        assert!(
            successor.is_pending_at(now),
            "the successor must not sign yet"
        );
        assert_eq!(successor.not_before, now + Duration::hours(24));
        // Signing still uses the old key. It has not been retired either.
        assert_eq!(
            current_signer_at(&keys, now).map(|key| key.kid.as_str()),
            Some("old")
        );
        assert_eq!(repo.get("old").status, SigningKeyStatus::Active);
        // The algorithm is carried over.
        assert_eq!(successor.algorithm, "ES256");
    }

    /// Calls while waiting do not recreate the successor key (idempotent). Recreating it would make the
    /// wait never end.
    #[tokio::test]
    async fn a_waiting_successor_is_not_generated_again() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z",
        )]);
        let keys = service(repo.clone(), clock.clone());
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        clock.advance(Duration::hours(1));
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate again");
        assert_eq!(repo.snapshot().len(), 2);
    }

    /// Stages 2 and 3: after `not_before`, signing moves over, and **a later call** retires the old key.
    #[tokio::test]
    async fn the_old_key_is_retired_only_after_the_successor_takes_over() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            "2026-09-06T00:00:00Z",
        )]);
        let keys = service(repo.clone(), clock.clone());
        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        clock.advance(Duration::hours(25));
        let now = clock.now();
        // Signing has moved without waiting for a call (the selection rule looks at `not_before`).
        let successor_kid = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "old")
            .expect("successor")
            .kid;
        assert_eq!(
            current_signer_at(&repo.snapshot(), now).map(|key| key.kid.clone()),
            Some(successor_kid.clone())
        );

        keys.rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        assert_eq!(repo.get("old").status, SigningKeyStatus::Retired);
        assert_eq!(repo.get(&successor_kid).status, SigningKeyStatus::Active);
        // Retired keys don't disappear from the JWKS (usable for verification until `not_after`).
        assert!(repo.get("old").not_after > now);
    }

    /// Even if manual generation leaves two ACTIVE keys, the overtaken one is retired at the next check. Left alone,
    /// a state of "two ACTIVE keys, unclear which one signs" would remain for up to a year.
    #[tokio::test]
    async fn an_active_key_overtaken_by_a_newer_one_is_retired() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "older",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "newer",
                SigningKeyStatus::Active,
                "2026-08-26T00:00:00Z",
                "2027-08-26T00:00:00Z",
            ),
        ]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");
        assert_eq!(repo.get("older").status, SigningKeyStatus::Retired);
        assert_eq!(repo.get("newer").status, SigningKeyStatus::Active);
        assert_eq!(repo.snapshot().len(), 2, "no new key is needed here");
    }

    /// Even if the grace period is longer than the current key's remaining life, **the handover happens before the current key expires**.
    /// Letting it pass would leave no key that can sign from the moment of expiry until `not_before`.
    #[tokio::test]
    async fn the_publish_lead_never_pushes_the_handover_past_the_current_key_expiry() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let expiry = "2026-09-06T00:00:00Z"; // 10 days left = 240 hours
        let repo = FakeRepo::with(vec![existing(
            "old",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            expiry,
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, 1_000)
            .await
            .expect("rotate");

        let successor = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "old")
            .expect("successor");
        assert_eq!(successor.not_before, parse(expiry));
    }

    /// When no key can sign, one is replenished. **The algorithm is carried over from the previous key** ——
    /// hard-coding it would send an environment running ES256 back to RS256 just by going through this path.
    #[tokio::test]
    async fn bootstrapping_after_the_last_key_was_retired_keeps_the_algorithm() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "retired",
            SigningKeyStatus::Retired,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        service(repo.clone(), clock.clone())
            .rotate_if_needed(LEAD_DAYS, PUBLISH_LEAD_HOURS)
            .await
            .expect("rotate");

        let now = clock.now();
        let fresh = repo
            .snapshot()
            .into_iter()
            .find(|key| key.kid != "retired")
            .expect("a replacement key");
        assert_eq!(fresh.algorithm, "ES256");
        // Replenishment has no grace period (with one, tokens couldn't be issued in the meantime).
        assert!(fresh.is_usable_for_signing_at(now));
    }

    /// **The last key that can sign is not retired.** Retiring it stops token issuance, and replenishment doesn't
    /// run until the next rotation check (hourly by default).
    #[tokio::test]
    async fn the_last_key_that_can_sign_cannot_be_retired() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "only",
            SigningKeyStatus::Active,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        let err = service(repo.clone(), clock)
            .retire_key("only")
            .await
            .expect_err("retiring the last usable key must be refused");
        assert!(matches!(err, KeyManagementError::Validation(_)), "{err:?}");
        assert_eq!(repo.get("only").status, SigningKeyStatus::Active);
    }

    /// A successor that is only published does not count as "able to sign". Counting it would allow retiring
    /// the current key before `not_before` arrives, creating a period with no signing key.
    #[tokio::test]
    async fn a_successor_that_is_only_published_does_not_unlock_retiring_the_current_key() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "current",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "successor",
                SigningKeyStatus::Active,
                "2026-08-28T00:00:00Z", // not yet arrived
                "2027-08-28T00:00:00Z",
            ),
        ]);
        let err = service(repo.clone(), clock)
            .retire_key("current")
            .await
            .expect_err("must be refused while the successor is still pending");
        assert!(matches!(err, KeyManagementError::Validation(_)), "{err:?}");
    }

    /// Once the handover is done, it can be retired.
    #[tokio::test]
    async fn a_superseded_key_can_be_retired_by_hand() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![
            existing(
                "old",
                SigningKeyStatus::Active,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            ),
            existing(
                "new",
                SigningKeyStatus::Active,
                "2026-08-26T00:00:00Z",
                "2027-08-26T00:00:00Z",
            ),
        ]);
        service(repo.clone(), clock)
            .retire_key("old")
            .await
            .expect("retiring a superseded key is allowed");
        assert_eq!(repo.get("old").status, SigningKeyStatus::Retired);
    }

    /// **The grace period of manual generation is also capped before the current key expires.** Letting it pass would
    /// leave no key that can sign from the current key's expiry until `not_before` (`rotate_if_needed` just finds the
    /// published successor and waits, so this hole is not filled at the next check).
    #[tokio::test]
    async fn a_hand_generated_key_never_starts_signing_after_the_current_key_expires() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let expiry = "2026-08-27T02:00:00Z"; // 2 hours left < grace 24 hours
        let repo = FakeRepo::with(vec![existing(
            "current",
            SigningKeyStatus::Active,
            "2025-09-01T00:00:00Z",
            expiry,
        )]);
        let key = service(repo.clone(), clock)
            .generate_key(SigningAlgorithm::Es256, Duration::hours(24))
            .await
            .expect("generate");
        assert_eq!(key.not_before, parse(expiry));
    }

    /// If a key is generated manually when no key can sign, there is no grace period. There is no one to wait for
    /// (an old key still signing), and tokens just couldn't be issued during the grace period.
    #[tokio::test]
    async fn a_hand_generated_key_skips_the_grace_when_nothing_can_sign() {
        let clock = TestClock::at("2026-08-27T00:00:00Z");
        let repo = FakeRepo::with(vec![existing(
            "retired",
            SigningKeyStatus::Retired,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )]);
        let now = clock.now();
        let key = service(repo.clone(), clock)
            .generate_key(SigningAlgorithm::Es256, Duration::hours(24))
            .await
            .expect("generate");
        assert!(key.is_usable_for_signing_at(now));
    }

    /// Regression test that the runtime can advance other tasks during key generation (no DB needed).
    ///
    /// On a runtime with a single worker thread, runs (A) an RSA key generation task and (B) a task that completes
    /// immediately, in the order "submit B after A has started generating", and checks that **B completes first**.
    /// With an implementation that generates directly on the worker thread (no `spawn_blocking`), B isn't polled
    /// until A finishes generating, so the completion order is reversed and the test fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn keypair_generation_does_not_block_the_runtime_worker() {
        let completion_order = Arc::new(AtomicUsize::new(0));
        let generation_started = Arc::new(Notify::new());

        let keygen = {
            let completion_order = completion_order.clone();
            let generation_started = generation_started.clone();
            tokio::spawn(async move {
                generation_started.notify_one();
                generate_keypair(SigningAlgorithm::Rs256)
                    .await
                    .expect("generate RSA keypair");
                completion_order.fetch_add(1, Ordering::SeqCst)
            })
        };

        // Submit B only after A has actually started running (rules out an accidental reversal from submission order).
        generation_started.notified().await;

        let other = {
            let completion_order = completion_order.clone();
            tokio::spawn(async move { completion_order.fetch_add(1, Ordering::SeqCst) })
        };

        let other_position = other.await.expect("join the non-blocking task");
        let keygen_position = keygen.await.expect("join the keygen task");
        assert!(
            other_position < keygen_position,
            "keygen must not occupy the runtime worker: other task finished at {other_position}, keygen at {keygen_position}"
        );
    }
}
