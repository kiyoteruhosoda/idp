//! Reading and verifying DPoP (RFC 9449) proofs (ADR-0075).
//!
//! This handles the checks determined only by time and the request (method, URL, access token).
//! "Has the same proof come twice?" needs a record, so the application layer
//! (`application::dpop_proof_verification`) checks the record using [`VerifiedDpopProof::replay_key`].
//!
//! - `typ` is `dpop+jwt`, `alg` is ES256 only (a P-256 key in Android Keystore. Decision 2)
//! - `jwk` is a P-256 public key only. Anything containing the secret value (`d`) is refused
//! - `htm` must exactly match the uppercase method; `htu` is compared with query and fragment removed (decision 5)
//! - `iat` from "[`MAX_PROOF_AGE_SECS`] seconds before now" to "[`MAX_CLOCK_AHEAD_SECS`] seconds after now" (decision 6)
//! - At resource endpoints, `ath` (base64url of the access token's SHA-256) must match

use crate::domain::crypto::{base64url, sha256_hex};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, TimeZone, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// How far before now `iat` is accepted (seconds). ADR-0075 decision 6.
pub const MAX_PROOF_AGE_SECS: i64 = 120;
/// How far after now `iat` is accepted (seconds), for device clocks running fast. ADR-0075 decision 6.
pub const MAX_CLOCK_AHEAD_SECS: i64 = 60;
/// Accepted signing algorithms (discovery's `dpop_signing_alg_values_supported`).
pub const SUPPORTED_ALGORITHMS: &[&str] = &["ES256"];
/// `typ` of the proof JWT.
pub const PROOF_TYPE: &str = "dpop+jwt";
/// Max length of `jti`. Records hold a hash, but unboundedly long values are not read.
const MAX_JTI_LEN: usize = 256;

/// What is required of the proof (which endpoint, which method, and which token it came with).
#[derive(Debug, Clone, Copy)]
pub struct DpopProofRequirements<'a> {
    /// Uppercase HTTP method (`POST` / `GET`).
    pub method: &'a str,
    /// The URL of this endpoint as advertised by assay in discovery (`{issuer}/token`, etc.).
    pub uri: &'a str,
    /// The access token that came with it at a resource endpoint (`/userinfo`). `None` at the token endpoint.
    pub access_token: Option<&'a str>,
    pub now: DateTime<Utc>,
}

/// A verified proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// Key fingerprint (RFC 7638 JWK Thumbprint. base64url of SHA-256). The value placed in `cnf.jkt`.
    pub jkt: String,
    pub jti: String,
    pub issued_at: DateTime<Utc>,
}

impl VerifiedDpopProof {
    /// Key of the replay record (hex of `sha256(jkt ":" jti)`). Uniqueness of `jti` is per key (decision 4).
    pub fn replay_key(&self) -> String {
        sha256_hex(&format!("{}:{}", self.jkt, self.jti))
    }

    /// The time after which this proof would be refused by time. The record only needs to be kept until then.
    pub fn retain_until(&self) -> DateTime<Utc> {
        self.issued_at + Duration::seconds(MAX_PROOF_AGE_SECS)
    }
}

/// Reason the proof was refused. Split for logs and tests, but returned to the caller as a single `invalid_dpop_proof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpopProofRejection {
    Malformed,
    WrongType,
    UnsupportedAlgorithm,
    InvalidKey,
    InvalidSignature,
    MissingClaim,
    MethodMismatch,
    UriMismatch,
    TooOld,
    FromTheFuture,
    AccessTokenHashMismatch,
    /// A proof with the same key and `jti` was already used within the accepted window (decided by the application layer).
    Replayed,
}

impl DpopProofRejection {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Malformed => "DPoP proof is not a well-formed JWT",
            Self::WrongType => "DPoP proof typ must be dpop+jwt",
            Self::UnsupportedAlgorithm => "DPoP proof alg must be ES256",
            Self::InvalidKey => "DPoP proof jwk must be a public P-256 key",
            Self::InvalidSignature => "DPoP proof signature does not verify",
            Self::MissingClaim => "DPoP proof lacks jti, htm, htu or iat",
            Self::MethodMismatch => "DPoP proof htm does not match the request",
            Self::UriMismatch => "DPoP proof htu does not match the endpoint",
            Self::TooOld => "DPoP proof iat is too old",
            Self::FromTheFuture => "DPoP proof iat is in the future",
            Self::AccessTokenHashMismatch => "DPoP proof ath does not match the access token",
            Self::Replayed => "DPoP proof has already been used",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProofHeader {
    typ: Option<String>,
    alg: Option<String>,
    jwk: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct ProofClaims {
    jti: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    ath: Option<String>,
}

/// P-256 public key (JWK `x`, `y`. Both base64url of 32 bytes).
struct PublicP256 {
    x: String,
    y: String,
}

impl PublicP256 {
    fn from_jwk(jwk: &serde_json::Map<String, serde_json::Value>) -> Option<Self> {
        // Refuse keys containing a secret value (RFC 9449 §4.3 item 6: must not include a private key).
        if jwk.contains_key("d") {
            return None;
        }
        let text = |name: &str| jwk.get(name).and_then(|v| v.as_str());
        if text("kty") != Some("EC") || text("crv") != Some("P-256") {
            return None;
        }
        let coordinate = |name: &str| {
            let value = text(name)?;
            // Check that it decodes back to 32 bytes. The value is inserted into the thumbprint JSON as is,
            // so characters other than base64url (such as quotes) must not pass.
            let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
            (bytes.len() == 32).then(|| value.to_string())
        };
        Some(Self {
            x: coordinate("x")?,
            y: coordinate("y")?,
        })
    }

    /// RFC 7638 JWK Thumbprint (SHA-256 of JSON with the required members in lexicographic order, no whitespace).
    fn thumbprint(&self) -> String {
        jwk_thumbprint_p256(&self.x, &self.y)
    }
}

/// JWK Thumbprint (RFC 7638) of a P-256 public key (`x`, `y` in base64url).
pub fn jwk_thumbprint_p256(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    base64url(&Sha256::digest(canonical.as_bytes()))
}

/// The access token's `ath` (base64url of SHA-256. RFC 9449 §4.2).
pub fn access_token_hash(access_token: &str) -> String {
    base64url(&Sha256::digest(access_token.as_bytes()))
}

/// Normalizes `htu` into a comparable form (removes query and fragment. `url` lowercases scheme and host).
fn comparable_uri(uri: &str) -> Option<String> {
    let mut parsed = url::Url::parse(uri).ok()?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return None;
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

/// Verifies a proof. Replay checks (records) are done by the caller with [`VerifiedDpopProof::replay_key`].
pub fn verify_proof(
    proof: &str,
    expected: &DpopProofRequirements<'_>,
) -> Result<VerifiedDpopProof, DpopProofRejection> {
    let header_segment = proof
        .split('.')
        .next()
        .ok_or(DpopProofRejection::Malformed)?;
    if proof.split('.').count() != 3 {
        return Err(DpopProofRejection::Malformed);
    }
    let header: ProofHeader = URL_SAFE_NO_PAD
        .decode(header_segment)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(DpopProofRejection::Malformed)?;
    if !header
        .typ
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case(PROOF_TYPE))
    {
        return Err(DpopProofRejection::WrongType);
    }
    if header.alg.as_deref() != Some("ES256") {
        return Err(DpopProofRejection::UnsupportedAlgorithm);
    }
    let key = header
        .jwk
        .as_ref()
        .and_then(PublicP256::from_jwk)
        .ok_or(DpopProofRejection::InvalidKey)?;
    let decoding_key = DecodingKey::from_ec_components(&key.x, &key.y)
        .map_err(|_| DpopProofRejection::InvalidKey)?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<ProofClaims>(proof, &decoding_key, &validation)
        .map_err(|_| DpopProofRejection::InvalidSignature)?
        .claims;

    let (Some(jti), Some(htm), Some(htu), Some(iat)) =
        (claims.jti, claims.htm, claims.htu, claims.iat)
    else {
        return Err(DpopProofRejection::MissingClaim);
    };
    if jti.is_empty() || jti.len() > MAX_JTI_LEN {
        return Err(DpopProofRejection::MissingClaim);
    }
    if htm != expected.method {
        return Err(DpopProofRejection::MethodMismatch);
    }
    match (comparable_uri(&htu), comparable_uri(expected.uri)) {
        (Some(presented), Some(endpoint)) if presented == endpoint => {}
        _ => return Err(DpopProofRejection::UriMismatch),
    }
    let issued_at = Utc
        .timestamp_opt(iat, 0)
        .single()
        .ok_or(DpopProofRejection::MissingClaim)?;
    if issued_at < expected.now - Duration::seconds(MAX_PROOF_AGE_SECS) {
        return Err(DpopProofRejection::TooOld);
    }
    if issued_at > expected.now + Duration::seconds(MAX_CLOCK_AHEAD_SECS) {
        return Err(DpopProofRejection::FromTheFuture);
    }
    if let Some(access_token) = expected.access_token {
        if claims.ath.as_deref() != Some(access_token_hash(access_token).as_str()) {
            return Err(DpopProofRejection::AccessTokenHashMismatch);
        }
    }
    Ok(VerifiedDpopProof {
        jkt: key.thumbprint(),
        jti,
        issued_at,
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Tools for making proofs in tests (standing in for the app).
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use p256::elliptic_curve::Generate as _;

    pub struct DeviceKey {
        key: SigningKey,
    }

    impl DeviceKey {
        pub fn generate() -> Self {
            Self {
                key: SigningKey::generate_from_rng(&mut rand::rng()),
            }
        }

        pub fn public_jwk(&self) -> serde_json::Value {
            let point = p256::PublicKey::from(self.key.verifying_key()).to_sec1_point(false);
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": base64url(point.x().unwrap()),
                "y": base64url(point.y().unwrap()),
            })
        }

        pub fn thumbprint(&self) -> String {
            let jwk = self.public_jwk();
            jwk_thumbprint_p256(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
        }

        /// Signs with arbitrary header and payload (for tests that make broken proofs).
        pub fn sign_raw(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
            let signing_input = format!(
                "{}.{}",
                base64url(header.to_string().as_bytes()),
                base64url(claims.to_string().as_bytes())
            );
            let signature: Signature = self.key.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", base64url(&signature.to_bytes()))
        }

        pub fn proof(
            &self,
            method: &str,
            uri: &str,
            iat: i64,
            jti: &str,
            access_token: Option<&str>,
        ) -> String {
            let header = serde_json::json!({
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": self.public_jwk(),
            });
            let mut claims = serde_json::json!({
                "jti": jti, "htm": method, "htu": uri, "iat": iat,
            });
            if let Some(at) = access_token {
                claims["ath"] = serde_json::Value::String(access_token_hash(at));
            }
            self.sign_raw(&header, &claims)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::DeviceKey;
    use super::*;

    const TOKEN_URI: &str = "https://assay.example.com/t1/token";

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000, 0).unwrap()
    }

    fn at_token_endpoint() -> DpopProofRequirements<'static> {
        DpopProofRequirements {
            method: "POST",
            uri: TOKEN_URI,
            access_token: None,
            now: now(),
        }
    }

    #[test]
    fn a_fresh_proof_yields_the_key_thumbprint() {
        let device = DeviceKey::generate();
        let proof = device.proof("POST", TOKEN_URI, now().timestamp(), "j1", None);
        let verified = verify_proof(&proof, &at_token_endpoint()).unwrap();
        assert_eq!(verified.jkt, device.thumbprint());
        assert_eq!(verified.jti, "j1");
        assert_eq!(verified.jkt.len(), 43);
    }

    #[test]
    fn the_thumbprint_matches_rfc_7638_example_shape() {
        // RFC 7638 procedure: SHA-256 of JSON with the required members in lexicographic order, no whitespace.
        let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        let expected = base64url(&Sha256::digest(
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#).as_bytes(),
        ));
        assert_eq!(jwk_thumbprint_p256(x, y), expected);
    }

    #[test]
    fn the_query_and_fragment_of_htu_are_ignored() {
        let device = DeviceKey::generate();
        let proof = device.proof(
            "POST",
            "https://ASSAY.example.com/t1/token?x=1#y",
            now().timestamp(),
            "j1",
            None,
        );
        assert!(verify_proof(&proof, &at_token_endpoint()).is_ok());
    }

    #[test]
    fn another_endpoint_or_method_is_rejected() {
        let device = DeviceKey::generate();
        let other_uri = device.proof(
            "POST",
            "https://assay.example.com/t1/userinfo",
            now().timestamp(),
            "j1",
            None,
        );
        assert_eq!(
            verify_proof(&other_uri, &at_token_endpoint()),
            Err(DpopProofRejection::UriMismatch)
        );
        let other_method = device.proof("GET", TOKEN_URI, now().timestamp(), "j1", None);
        assert_eq!(
            verify_proof(&other_method, &at_token_endpoint()),
            Err(DpopProofRejection::MethodMismatch)
        );
    }

    #[test]
    fn iat_must_be_inside_the_window() {
        let device = DeviceKey::generate();
        let t = now().timestamp();
        let ok_old = device.proof("POST", TOKEN_URI, t - MAX_PROOF_AGE_SECS, "a", None);
        assert!(verify_proof(&ok_old, &at_token_endpoint()).is_ok());
        let too_old = device.proof("POST", TOKEN_URI, t - MAX_PROOF_AGE_SECS - 1, "b", None);
        assert_eq!(
            verify_proof(&too_old, &at_token_endpoint()),
            Err(DpopProofRejection::TooOld)
        );
        let ok_ahead = device.proof("POST", TOKEN_URI, t + MAX_CLOCK_AHEAD_SECS, "c", None);
        assert!(verify_proof(&ok_ahead, &at_token_endpoint()).is_ok());
        let ahead = device.proof("POST", TOKEN_URI, t + MAX_CLOCK_AHEAD_SECS + 1, "d", None);
        assert_eq!(
            verify_proof(&ahead, &at_token_endpoint()),
            Err(DpopProofRejection::FromTheFuture)
        );
    }

    #[test]
    fn the_access_token_hash_must_match_at_a_resource() {
        let device = DeviceKey::generate();
        let uri = "https://assay.example.com/t1/userinfo";
        let expected = DpopProofRequirements {
            method: "GET",
            uri,
            access_token: Some("token-a"),
            now: now(),
        };
        let right = device.proof("GET", uri, now().timestamp(), "j", Some("token-a"));
        assert!(verify_proof(&right, &expected).is_ok());
        let wrong = device.proof("GET", uri, now().timestamp(), "j", Some("token-b"));
        assert_eq!(
            verify_proof(&wrong, &expected),
            Err(DpopProofRejection::AccessTokenHashMismatch)
        );
        let missing = device.proof("GET", uri, now().timestamp(), "j", None);
        assert_eq!(
            verify_proof(&missing, &expected),
            Err(DpopProofRejection::AccessTokenHashMismatch)
        );
    }

    #[test]
    fn a_proof_signed_by_another_key_is_rejected() {
        let device = DeviceKey::generate();
        let thief = DeviceKey::generate();
        // Put the owner's public key in the header and sign with the thief's key.
        let header =
            serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": device.public_jwk()});
        let claims = serde_json::json!({"jti": "j", "htm": "POST", "htu": TOKEN_URI, "iat": now().timestamp()});
        let forged = thief.sign_raw(&header, &claims);
        assert_eq!(
            verify_proof(&forged, &at_token_endpoint()),
            Err(DpopProofRejection::InvalidSignature)
        );
    }

    #[test]
    fn the_header_must_be_a_dpop_proof_with_a_public_p256_key() {
        let device = DeviceKey::generate();
        let claims = serde_json::json!({"jti": "j", "htm": "POST", "htu": TOKEN_URI, "iat": now().timestamp()});
        let wrong_typ = device.sign_raw(
            &serde_json::json!({"typ": "JWT", "alg": "ES256", "jwk": device.public_jwk()}),
            &claims,
        );
        assert_eq!(
            verify_proof(&wrong_typ, &at_token_endpoint()),
            Err(DpopProofRejection::WrongType)
        );
        let rs256 = device.sign_raw(
            &serde_json::json!({"typ": "dpop+jwt", "alg": "RS256", "jwk": device.public_jwk()}),
            &claims,
        );
        assert_eq!(
            verify_proof(&rs256, &at_token_endpoint()),
            Err(DpopProofRejection::UnsupportedAlgorithm)
        );
        let mut private = device.public_jwk();
        private["d"] = serde_json::Value::String("AAAA".into());
        let with_private = device.sign_raw(
            &serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": private}),
            &claims,
        );
        assert_eq!(
            verify_proof(&with_private, &at_token_endpoint()),
            Err(DpopProofRejection::InvalidKey)
        );
        let no_jwk = device.sign_raw(
            &serde_json::json!({"typ": "dpop+jwt", "alg": "ES256"}),
            &claims,
        );
        assert_eq!(
            verify_proof(&no_jwk, &at_token_endpoint()),
            Err(DpopProofRejection::InvalidKey)
        );
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(
            verify_proof("not-a-jwt", &at_token_endpoint()),
            Err(DpopProofRejection::Malformed)
        );
    }

    #[test]
    fn the_replay_key_is_per_key_and_jti() {
        let a = VerifiedDpopProof {
            jkt: "k1".into(),
            jti: "j".into(),
            issued_at: now(),
        };
        let b = VerifiedDpopProof {
            jkt: "k2".into(),
            ..a.clone()
        };
        assert_ne!(a.replay_key(), b.replay_key());
        assert_eq!(
            a.retain_until(),
            now() + Duration::seconds(MAX_PROOF_AGE_SECS)
        );
    }
}
