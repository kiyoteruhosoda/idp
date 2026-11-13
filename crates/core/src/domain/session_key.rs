//! Checking keys and signatures when binding an SSO session to a device key (DBSC) (task #887;
//! ADR-0074).
//!
//! On every registration and refresh, Chrome signs a JWT (`typ: dbsc+jwt`) with a key inside the
//! TPM and sends it.
//!
//! | | Header | Payload |
//! |---|---|---|
//! | Registration | `alg` (ES256 / RS256), `typ`, **`jwk` (public key)** | `jti` = challenge |
//! | Refresh | `alg`, `typ` (no `jwk`) | `jti` = challenge |
//!
//! On registration the signature is checked with the public key attached to the JWT, and that key
//! is remembered. On refresh it is checked with the remembered key. Whether the challenge belongs
//! to this SSO session is checked by the caller (application).
//!
//! ⚠ Whether the key is inside a TPM cannot be known from here (DBSC carries no key attestation).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Lower bound on RSA key length (bits).
const MIN_RSA_BITS: usize = 2048;
/// Upper bound on the signature JWT length (bytes). Under 2KB even with an RSA 4096 public key
/// attached.
const MAX_PROOF_LEN: usize = 8 * 1024;

/// The bound public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPublicKey {
    /// `ES256` / `RS256`.
    pub algorithm: SessionKeyAlgorithm,
    /// JWK (JSON) of the public key.
    pub jwk_json: String,
    /// RFC 7638 thumbprint (SHA-256, base64url).
    pub thumbprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeyAlgorithm {
    Es256,
    Rs256,
}

impl SessionKeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ES256" => Some(Self::Es256),
            "RS256" => Some(Self::Rs256),
            _ => None,
        }
    }

    fn jwt(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::ES256,
            Self::Rs256 => Algorithm::RS256,
        }
    }

    fn from_jwt(alg: Algorithm) -> Option<Self> {
        match alg {
            Algorithm::ES256 => Some(Self::Es256),
            Algorithm::RS256 => Some(Self::Rs256),
            _ => None,
        }
    }
}

/// Binding between an SSO session and a device key (only once per sign-in state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyBinding {
    /// Identifier Chrome sends in `Sec-Secure-Session-Id` on refresh (32 hex characters).
    pub session_identifier: String,
    pub key: SessionPublicKey,
    pub bound_at: DateTime<Utc>,
}

/// Kind of binding of a sign-in state (task #887, #892; ADR-0074, ADR-0077).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBinding {
    /// No binding.
    Unbound,
    /// Bound to a device key via DBSC (Chrome on Windows).
    DeviceKey,
    /// Created by approval in a registered authenticator app (Chrome on Android; owner's decision
    /// "30 days when authenticated by app").
    AppApproval,
}

/// Decides the length of a sign-in state.
///
/// It is 30 days (`bound_ttl`) when bound via DBSC **and** the sign-in state's device is registered
/// as one of the user's devices (ADR-0074 §6), and when approved by the authenticator app
/// (ADR-0077; the approving key itself is a device key registered with a passkey, so the browser's
/// device registration does not matter). Otherwise the length at establishment (`absolute_ttl`).
/// Both count **from creation time**. Returns (idle expiry, absolute expiry).
pub fn lifetime_for(
    created_at: DateTime<Utc>,
    current_idle: DateTime<Utc>,
    binding: SessionBinding,
    device_registered: bool,
    absolute_ttl: Duration,
    bound_ttl: Duration,
) -> (DateTime<Utc>, DateTime<Utc>) {
    if lifetime_basis(binding, device_registered, absolute_ttl, bound_ttl).is_long() {
        let absolute = created_at + bound_ttl;
        // A bound sign-in state is not cut off for "not being used" (owner's decision; idle has the
        // same length).
        (absolute, absolute)
    } else {
        let absolute = created_at + absolute_ttl;
        (current_idle.min(absolute), absolute)
    }
}

/// Why a sign-in state has the length it has (task #896; shown as one line in the user's "status").
///
/// [`lifetime_for`] chooses the length by this decision alone. So the on-screen explanation and the
/// actual length never disagree, the decision lives in this one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeBasis {
    /// Bound to a device key and that device is registered → long (`bound_ttl`).
    BoundOnRegisteredDevice,
    /// Signed in by approval in a registered authenticator app → long (`bound_ttl`).
    AppApproval,
    /// Bound to a device key but that device is not registered → the length at establishment.
    BoundOnUnregisteredDevice,
    /// Not bound → the length at establishment.
    Unbound,
    /// Meets the conditions for a longer length, but the organization's length setting does not
    /// extend it (`bound_ttl` ≤ `absolute_ttl`).
    NotExtendedBySetting,
}

impl LifetimeBasis {
    /// Whether to use the long length (`bound_ttl`).
    pub fn is_long(self) -> bool {
        matches!(self, Self::BoundOnRegisteredDevice | Self::AppApproval)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BoundOnRegisteredDevice => "bound_on_registered_device",
            Self::AppApproval => "app_approval",
            Self::BoundOnUnregisteredDevice => "bound_on_unregistered_device",
            Self::Unbound => "unbound",
            Self::NotExtendedBySetting => "not_extended_by_setting",
        }
    }
}

/// Decides the basis for the length from the binding kind and device registration.
pub fn lifetime_basis(
    binding: SessionBinding,
    device_registered: bool,
    absolute_ttl: Duration,
    bound_ttl: Duration,
) -> LifetimeBasis {
    let qualified = match binding {
        SessionBinding::Unbound => return LifetimeBasis::Unbound,
        SessionBinding::DeviceKey if !device_registered => {
            return LifetimeBasis::BoundOnUnregisteredDevice
        }
        SessionBinding::DeviceKey => LifetimeBasis::BoundOnRegisteredDevice,
        SessionBinding::AppApproval => LifetimeBasis::AppApproval,
    };
    if bound_ttl > absolute_ttl {
        qualified
    } else {
        LifetimeBasis::NotExtendedBySetting
    }
}

/// Why a signature was not accepted (recorded in the audit log; not shown to users).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// The JWT shape, `typ`, or algorithm is wrong, or it is too long.
    Malformed,
    /// Registration without a public key, or an unusable key (curve, length).
    UnusableKey,
    /// The signature does not match.
    BadSignature,
    /// `jti` (challenge) is missing or wrong.
    WrongChallenge,
}

impl ProofError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnusableKey => "unusable_key",
            Self::BadSignature => "bad_signature",
            Self::WrongChallenge => "wrong_challenge",
        }
    }
}

#[derive(Deserialize)]
struct ProofClaims {
    jti: Option<String>,
}

/// Checks a registration signature and returns the attached public key. `challenge` must match the
/// signature's `jti`.
pub fn verify_registration(proof: &str, challenge: &str) -> Result<SessionPublicKey, ProofError> {
    let header = read_header(proof)?;
    let algorithm = SessionKeyAlgorithm::from_jwt(header.alg).ok_or(ProofError::Malformed)?;
    let jwk = header.jwk.ok_or(ProofError::UnusableKey)?;
    let key = usable_key(&jwk, algorithm)?;
    verify_signature(proof, &key, algorithm, challenge)?;
    let thumbprint = jwk
        .thumbprint(ThumbprintHash::SHA256)
        .map_err(|_| ProofError::UnusableKey)?;
    let jwk_json =
        serde_json::to_string(&public_part(&jwk)).map_err(|_| ProofError::UnusableKey)?;
    Ok(SessionPublicKey {
        algorithm,
        jwk_json,
        thumbprint,
    })
}

/// Checks a refresh signature with the bound public key.
///
/// An algorithm different from registration, or an attached `jwk` that differs from the registered
/// key, are both returned as [`ProofError::BadSignature`] (a signature made with a different key =
/// suspected theft).
pub fn verify_refresh(
    proof: &str,
    bound: &SessionPublicKey,
    challenge: &str,
) -> Result<(), ProofError> {
    let header = read_header(proof)?;
    if SessionKeyAlgorithm::from_jwt(header.alg) != Some(bound.algorithm) {
        return Err(ProofError::BadSignature);
    }
    if let Some(jwk) = &header.jwk {
        if jwk.thumbprint(ThumbprintHash::SHA256).ok().as_deref() != Some(bound.thumbprint.as_str())
        {
            return Err(ProofError::BadSignature);
        }
    }
    let jwk: Jwk = serde_json::from_str(&bound.jwk_json).map_err(|_| ProofError::UnusableKey)?;
    let key = usable_key(&jwk, bound.algorithm)?;
    verify_signature(proof, &key, bound.algorithm, challenge)
}

fn read_header(proof: &str) -> Result<jsonwebtoken::Header, ProofError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_LEN {
        return Err(ProofError::Malformed);
    }
    let header = jsonwebtoken::decode_header(proof).map_err(|_| ProofError::Malformed)?;
    if header.typ.as_deref() != Some(assay_contracts::session_key::PROOF_TYPE) {
        return Err(ProofError::Malformed);
    }
    Ok(header)
}

/// Whether the key fits the algorithm (P-256 for ES256, 2048 bits or more for RS256).
fn usable_key(jwk: &Jwk, algorithm: SessionKeyAlgorithm) -> Result<DecodingKey, ProofError> {
    match (&jwk.algorithm, algorithm) {
        (AlgorithmParameters::EllipticCurve(ec), SessionKeyAlgorithm::Es256)
            if ec.curve == EllipticCurve::P256 => {}
        (AlgorithmParameters::RSA(rsa), SessionKeyAlgorithm::Rs256)
            if URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map(|n| n.len() * 8 >= MIN_RSA_BITS)
                .unwrap_or(false) => {}
        _ => return Err(ProofError::UnusableKey),
    }
    DecodingKey::from_jwk(jwk).map_err(|_| ProofError::UnusableKey)
}

fn verify_signature(
    proof: &str,
    key: &DecodingKey,
    algorithm: SessionKeyAlgorithm,
    challenge: &str,
) -> Result<(), ProofError> {
    let mut validation = Validation::new(algorithm.jwt());
    // DBSC signatures have no `exp` or `aud` (the draft defines only `jti`). Freshness is measured
    // by the challenge.
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<ProofClaims>(proof, key, &validation)
        .map_err(|_| ProofError::BadSignature)?
        .claims;
    match claims.jti {
        Some(jti) if jti == challenge => Ok(()),
        _ => Err(ProofError::WrongChallenge),
    }
}

/// The public key to remember (drops additions like `kid`, keeping only the key itself).
fn public_part(jwk: &Jwk) -> serde_json::Value {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": ec.x, "y": ec.y,
        }),
        AlgorithmParameters::RSA(rsa) => serde_json::json!({
            "kty": "RSA", "n": rsa.n, "e": rsa.e,
        }),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::jwt::generate_ec_keypair;
    use jsonwebtoken::{EncodingKey, Header};

    struct DeviceKey {
        private_pem: String,
        jwk: Jwk,
    }

    fn device_key() -> DeviceKey {
        let (private_pem, public_pem) = generate_ec_keypair().unwrap();
        let ours = crate::domain::jwt::ec_public_jwk("k", &public_pem).unwrap();
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": ours.x, "y": ours.y,
        }))
        .unwrap();
        DeviceKey { private_pem, jwk }
    }

    fn proof(key: &DeviceKey, jti: &str, with_jwk: bool, typ: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(typ.to_string());
        if with_jwk {
            header.jwk = Some(key.jwk.clone());
        }
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "jti": jti }),
            &EncodingKey::from_ec_pem(key.private_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn registration_returns_the_key_and_refresh_accepts_the_same_key() {
        let key = device_key();
        let bound = verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c1").unwrap();
        assert_eq!(bound.algorithm, SessionKeyAlgorithm::Es256);
        assert_eq!(bound.thumbprint.len(), 43);
        assert!(!bound.jwk_json.contains("\"kid\""));
        assert_eq!(
            verify_refresh(&proof(&key, "c2", false, "dbsc+jwt"), &bound, "c2"),
            Ok(())
        );
    }

    #[test]
    fn registration_needs_the_key_the_type_and_the_challenge() {
        let key = device_key();
        assert_eq!(
            verify_registration(&proof(&key, "c1", false, "dbsc+jwt"), "c1"),
            Err(ProofError::UnusableKey)
        );
        assert_eq!(
            verify_registration(&proof(&key, "c1", true, "JWT"), "c1"),
            Err(ProofError::Malformed)
        );
        assert_eq!(
            verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c2"),
            Err(ProofError::WrongChallenge)
        );
        assert_eq!(
            verify_registration("a.b.c", "c1"),
            Err(ProofError::Malformed)
        );
    }

    #[test]
    fn a_registration_signed_by_another_key_than_it_carries_is_rejected() {
        let key = device_key();
        let other = device_key();
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dbsc+jwt".to_string());
        header.jwk = Some(key.jwk.clone());
        let forged = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "jti": "c1" }),
            &EncodingKey::from_ec_pem(other.private_pem.as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_registration(&forged, "c1"),
            Err(ProofError::BadSignature)
        );
    }

    #[test]
    fn a_refresh_signed_by_another_key_is_a_bad_signature() {
        let key = device_key();
        let thief = device_key();
        let bound = verify_registration(&proof(&key, "c1", true, "dbsc+jwt"), "c1").unwrap();
        assert_eq!(
            verify_refresh(&proof(&thief, "c2", false, "dbsc+jwt"), &bound, "c2"),
            Err(ProofError::BadSignature)
        );
        // Same even when trying to swap by attaching another key.
        assert_eq!(
            verify_refresh(&proof(&thief, "c2", true, "dbsc+jwt"), &bound, "c2"),
            Err(ProofError::BadSignature)
        );
        assert_eq!(
            verify_refresh(&proof(&key, "c2", false, "dbsc+jwt"), &bound, "c3"),
            Err(ProofError::WrongChallenge)
        );
    }

    #[test]
    fn only_a_bound_session_on_a_registered_device_gets_the_long_lifetime() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let idle = created + Duration::hours(30);
        let week = Duration::days(7);
        let month = Duration::days(30);
        use SessionBinding::{DeviceKey, Unbound};
        assert_eq!(
            lifetime_for(created, idle, DeviceKey, true, week, month),
            (created + month, created + month)
        );
        for (binding, registered) in [(DeviceKey, false), (Unbound, true), (Unbound, false)] {
            assert_eq!(
                lifetime_for(created, idle, binding, registered, week, month),
                (idle, created + week),
                "binding={binding:?} registered={registered}"
            );
        }
        // When going back from 30 days to 7 days, idle does not exceed absolute.
        assert_eq!(
            lifetime_for(created, created + month, DeviceKey, false, week, month),
            (created + week, created + week)
        );
        // If the organization decided a shorter length, binding does not extend it.
        assert_eq!(
            lifetime_for(created, idle, DeviceKey, true, month, week),
            (idle, created + month)
        );
    }

    #[test]
    fn an_app_approved_session_gets_the_long_lifetime_without_a_registered_browser() {
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let idle = created + Duration::hours(30);
        let week = Duration::days(7);
        let month = Duration::days(30);
        for registered in [true, false] {
            assert_eq!(
                lifetime_for(
                    created,
                    idle,
                    SessionBinding::AppApproval,
                    registered,
                    week,
                    month
                ),
                (created + month, created + month)
            );
        }
    }

    #[test]
    fn the_basis_names_why_a_session_has_its_length() {
        let week = Duration::days(7);
        let month = Duration::days(30);
        use SessionBinding::{AppApproval, DeviceKey, Unbound};
        assert_eq!(
            lifetime_basis(DeviceKey, true, week, month),
            LifetimeBasis::BoundOnRegisteredDevice
        );
        assert_eq!(
            lifetime_basis(AppApproval, false, week, month),
            LifetimeBasis::AppApproval
        );
        assert_eq!(
            lifetime_basis(DeviceKey, false, week, month),
            LifetimeBasis::BoundOnUnregisteredDevice
        );
        assert_eq!(
            lifetime_basis(Unbound, true, week, month),
            LifetimeBasis::Unbound
        );
        assert_eq!(
            lifetime_basis(DeviceKey, true, month, week),
            LifetimeBasis::NotExtendedBySetting
        );
        // Only when the basis says long does lifetime_for also make it long.
        use chrono::TimeZone;
        let created = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        for (binding, registered) in [
            (DeviceKey, true),
            (DeviceKey, false),
            (AppApproval, false),
            (Unbound, true),
        ] {
            let long = lifetime_basis(binding, registered, week, month).is_long();
            let (_, absolute) =
                lifetime_for(created, created + week, binding, registered, week, month);
            assert_eq!(
                absolute == created + month,
                long,
                "{binding:?} {registered}"
            );
        }
    }

    #[test]
    fn algorithms_round_trip() {
        for alg in [SessionKeyAlgorithm::Es256, SessionKeyAlgorithm::Rs256] {
            assert_eq!(SessionKeyAlgorithm::parse(alg.as_str()), Some(alg));
        }
        assert_eq!(SessionKeyAlgorithm::parse("none"), None);
    }
}
