//! SigningKeys entity (design spec §3.6).
#![allow(dead_code)]

use crate::domain::values::SigningKeyStatus;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct SigningKey {
    pub kid: String,
    /// Signing algorithm. The MVP supports only `RS256`.
    pub algorithm: String,
    /// Public key (published in JWKS).
    pub public_key: String,
    /// Private key encrypted with a key held outside the DB.
    pub private_key_encrypted: String,
    pub status: SigningKeyStatus,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SigningKey {
    /// Whether the key can be used for new signatures (ACTIVE and within its validity period).
    pub fn is_usable_for_signing_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SigningKeyStatus::Active && self.not_before <= now && now < self.not_after
    }

    /// **A key that is published but not yet used for signing** (an ACTIVE key whose `not_before`
    /// is in the future).
    ///
    /// Key rotation passing through this state is the point. JWKS publishes without looking at
    /// `not_before`, so the successor key reaches RPs the moment it is generated, while the old key
    /// keeps signing until `not_before` arrives. **This gives RPs caching JWKS time to pick up the
    /// new `kid`.** If publishing and signing start at once, RPs with a cache fail verification
    /// until their TTL expires.
    pub fn is_pending_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SigningKeyStatus::Active && now < self.not_before
    }
}

/// Picks the key currently used for signing (among usable keys, the one with the newest
/// `not_before`).
///
/// **The same rule as the SQL of `SigningKeyRepository::find_active`.** The admin screen's
/// "signing" label and the key that actually signs must be chosen by the same rule — if they
/// diverge, retiring the key shown as "signing" would not stop signing (or the reverse), behavior
/// the screen cannot explain.
pub fn current_signer_at(keys: &[SigningKey], now: DateTime<Utc>) -> Option<&SigningKey> {
    keys.iter()
        .filter(|key| key.is_usable_for_signing_at(now))
        .max_by_key(|key| key.not_before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn key(kid: &str, status: SigningKeyStatus, not_before: DateTime<Utc>) -> SigningKey {
        SigningKey {
            kid: kid.to_string(),
            algorithm: "RS256".to_string(),
            public_key: String::new(),
            private_key_encrypted: String::new(),
            status,
            not_before,
            not_after: not_before + Duration::days(365),
            created_at: not_before,
            updated_at: not_before,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Even after the successor key is published, the old key keeps signing until `not_before`. If
    /// this breaks, the grace period for distributing JWKS disappears and RPs with a cache fail
    /// verification.
    #[test]
    fn a_published_successor_does_not_take_over_signing_until_its_not_before() {
        let now = now();
        let old = key("old", SigningKeyStatus::Active, now - Duration::days(300));
        let successor = key("new", SigningKeyStatus::Active, now + Duration::hours(24));
        let keys = vec![old, successor];

        assert!(keys[1].is_pending_at(now));
        assert_eq!(
            current_signer_at(&keys, now).map(|k| k.kid.as_str()),
            Some("old")
        );
        // Only once `not_before` has passed does the successor take over.
        let later = now + Duration::hours(25);
        assert!(!keys[1].is_pending_at(later));
        assert_eq!(
            current_signer_at(&keys, later).map(|k| k.kid.as_str()),
            Some("new")
        );
    }

    /// Even with two ACTIVE keys, only the one with the newer `not_before` signs.
    #[test]
    fn only_one_of_several_active_keys_signs() {
        let now = now();
        let keys = vec![
            key("older", SigningKeyStatus::Active, now - Duration::days(200)),
            key("newer", SigningKeyStatus::Active, now - Duration::days(1)),
            // Retired keys are not candidates (they remain in JWKS but are not used for signing).
            key(
                "retired",
                SigningKeyStatus::Retired,
                now - Duration::hours(1),
            ),
        ];
        assert_eq!(
            current_signer_at(&keys, now).map(|k| k.kid.as_str()),
            Some("newer")
        );
    }

    /// `None` if there is no usable key. Callers read this as "token issuance stops".
    #[test]
    fn no_usable_key_yields_no_signer() {
        let now = now();
        let keys = vec![
            key(
                "retired",
                SigningKeyStatus::Retired,
                now - Duration::days(1),
            ),
            key(
                "pending",
                SigningKeyStatus::Active,
                now + Duration::hours(1),
            ),
        ];
        assert!(current_signer_at(&keys, now).is_none());
    }
}
