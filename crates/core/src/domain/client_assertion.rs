//! Verification of `private_key_jwt` client assertions (ADR-0030 decisions 2, 5, 6, 7. RFC 7523, OIDC Core §9).
//!
//! The client presents a JWT signed with its own private key, and the IdP verifies it with the registered public keys
//! ([`crate::domain::client_jwks::ClientJwks`]). This handles **signature and claim verification**
//! only; recording `jti` (persistence for replay prevention) is done by the application layer, because recording needs the DB,
//! and how to handle "verification passed but recording failed" is a transaction-boundary question.
//!
//! The verification algorithm is decided from **the type of the registered key**. The verification method is never chosen
//! by trusting the assertion header's `alg` (to prevent `alg` confusion attacks). Even if the header claims `none` or an HMAC
//! family, it does not match the key, so verification fails.

use crate::domain::client_jwks::ClientJwks;
use crate::domain::jwt::decoding_key_from_jwk;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

/// The only allowed value of `client_assertion_type` (RFC 7523 §2.2).
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Upper bound of an assertion's validity period (ADR-0030 decision 5).
///
/// Assertions whose `exp` points beyond this are rejected. This keeps the replay window short, and is also
/// the upper bound of how long `jti` is recorded (keeping the record until [`VerifiedClientAssertion::replay_guard_until`]
/// prevents replay).
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::minutes(5);

/// Allowed clock skew. Client and IdP clocks cannot be expected to match exactly.
const CLOCK_SKEW_LEEWAY: Duration = Duration::seconds(60);

/// Max length of `jti`. Matches the width of `client_assertion_jtis.jti`.
///
/// Longer ones are rejected on the verification side so the record INSERT does not become a DB error (= 500).
/// An overly long `jti` is a bad request, not an IdP failure.
const MAX_JTI_LENGTH: usize = 255;

/// Only the values needed for replay prevention, extracted from an assertion that passed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClientAssertion {
    /// The `jti` claim. Recorded uniquely by `(tenant_id, client_id, jti)`.
    pub jti: String,
    /// The `exp` claim.
    pub expires_at: DateTime<Utc>,
    /// The time until which `jti` is not re-accepted. **Not `exp` itself, but `exp` plus the allowed clock skew**.
    ///
    /// Acceptance lets through assertions up to [`CLOCK_SKEW_LEEWAY`] past `exp`, so if the record were kept only until `exp`,
    /// the same assertion could be used again in the gap after cleanup deletes the row and before acceptance stops.
    /// The record is kept until acceptance stops.
    pub replay_guard_until: DateTime<Utc>,
}

/// Reasons an assertion cannot be accepted. The string goes into the audit log `reason` as is
/// (the client always gets `invalid_client`, without revealing which check failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAssertionFailure {
    /// `client_assertion_type` is not `jwt-bearer`.
    UnsupportedAssertionType,
    /// Cannot be read as a JWT (malformed header or separators).
    Malformed,
    /// No key is registered for the header's `kid` (including when there is no `kid` and several keys).
    UnknownKey,
    /// Signature verification failed. Expired `exp` and mismatched `aud` are returned as their own reasons, not here.
    InvalidSignature,
    /// Expired (`exp` is in the past).
    Expired,
    /// `exp` is too far ahead (exceeds [`MAX_ASSERTION_LIFETIME`]).
    LifetimeTooLong,
    /// `aud` does not point to an assay tenant.
    AudienceMismatch,
    /// `iss` or `sub` is not the client itself.
    SubjectMismatch,
    /// No `jti` (required in assay).
    MissingJti,
    /// `jti` is too long (exceeds [`MAX_JTI_LENGTH`]).
    JtiTooLong,
}

impl ClientAssertionFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAssertionType => "unsupported_assertion_type",
            Self::Malformed => "malformed_client_assertion",
            Self::UnknownKey => "unknown_assertion_key",
            Self::InvalidSignature => "invalid_assertion_signature",
            Self::Expired => "expired_client_assertion",
            Self::LifetimeTooLong => "assertion_lifetime_too_long",
            Self::AudienceMismatch => "assertion_audience_mismatch",
            Self::SubjectMismatch => "assertion_subject_mismatch",
            Self::MissingJti => "missing_assertion_jti",
            Self::JtiTooLong => "assertion_jti_too_long",
        }
    }
}

/// `aud` can be written as a single string or an array (RFC 7519 §4.1.3).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(one) => one == value,
            Self::Many(many) => many.iter().any(|a| a == value),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    jti: Option<String>,
}

/// Peeks only at `sub` (= the client itself) without verifying the signature.
///
/// Used only to decide "which client's registered keys to verify with" before client authentication.
/// RFC 7521 §4.2 allows omitting `client_id` when using an assertion, in which case this is
/// the only clue. Even if the value is forged, it simply fails if the signature cannot be verified with the chosen key, so
/// it is not used for the authentication decision: **after verification, always check that `iss`/`sub` match client_id**
/// (done by [`verify_client_assertion`]).
pub fn unverified_subject(assertion: &str) -> Option<String> {
    // No signature verification, so `jsonwebtoken`'s decode cannot be used. Only the payload part is opened manually.
    let mut parts = assertion.split('.');
    let (_header, payload) = (parts.next()?, parts.next()?);
    // Something without a signature part is not a JWT (do not let `header.payload` alone slip through).
    parts.next()?;
    let decoded = base64url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("sub")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn base64url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(value).ok()
}

/// Verifies an assertion.
///
/// Pass both the tenant issuer and the token endpoint URL in `accepted_audiences`
/// (ADR-0030 decision 6. Client implementations differ in which one they put). Both
/// include the tenant, so an assertion for tenant A cannot be carried to tenant B.
pub fn verify_client_assertion(
    assertion_type: Option<&str>,
    assertion: &str,
    client_id: &str,
    jwks: &ClientJwks,
    accepted_audiences: &[String],
    now: DateTime<Utc>,
) -> Result<VerifiedClientAssertion, ClientAssertionFailure> {
    if assertion_type != Some(JWT_BEARER_ASSERTION_TYPE) {
        return Err(ClientAssertionFailure::UnsupportedAssertionType);
    }

    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| ClientAssertionFailure::Malformed)?;
    let jwk = jwks
        .select(header.kid.as_deref())
        .ok_or(ClientAssertionFailure::UnknownKey)?;
    let key = decoding_key_from_jwk(jwk).map_err(|_| ClientAssertionFailure::UnknownKey)?;
    // The verification algorithm is decided by the registered key's type (the header's `alg` is not looked at).
    let algorithm = match jwk.alg.as_str() {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        // `ClientJwks` only produces RS256 / ES256 so this is unreachable, but keep it fail-closed.
        _ => return Err(ClientAssertionFailure::UnknownKey),
    };

    let mut validation = Validation::new(algorithm);
    // **All** claim checks are done ourselves; `jsonwebtoken` only verifies the signature.
    // Delegating the `exp` check would read system time internally, so the injected `now` (`Clock`) would not apply,
    // and tests could not fix the time (`CLAUDE.md` "Tests"). `aud` and `iss` are also conditions of matching any
    // of a candidate set and "being the client itself", so they cannot be expressed as a simple match.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

    let token = jsonwebtoken::decode::<AssertionClaims>(assertion, &key, &validation).map_err(
        |e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                ClientAssertionFailure::InvalidSignature
            }
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_)
            | jsonwebtoken::errors::ErrorKind::Json(_) => ClientAssertionFailure::Malformed,
            _ => ClientAssertionFailure::InvalidSignature,
        },
    )?;
    let claims = token.claims;

    // RFC 7523 §3: both `iss` and `sub` must be the client itself.
    if claims.iss != client_id || claims.sub != client_id {
        return Err(ClientAssertionFailure::SubjectMismatch);
    }
    if !accepted_audiences.iter().any(|a| claims.aud.contains(a)) {
        return Err(ClientAssertionFailure::AudienceMismatch);
    }

    let expires_at =
        DateTime::from_timestamp(claims.exp, 0).ok_or(ClientAssertionFailure::Malformed)?;
    if expires_at + CLOCK_SKEW_LEEWAY < now {
        return Err(ClientAssertionFailure::Expired);
    }
    // The upper bound also allows for clock skew. Otherwise, with the client's clock just a few seconds fast, an assertion
    // with a validity of exactly the limit would fail as "too long" (uses the same leeway as the expiry check).
    if expires_at - now > MAX_ASSERTION_LIFETIME + CLOCK_SKEW_LEEWAY {
        return Err(ClientAssertionFailure::LifetimeTooLong);
    }

    let jti = claims
        .jti
        .filter(|j| !j.is_empty())
        .ok_or(ClientAssertionFailure::MissingJti)?;
    if jti.len() > MAX_JTI_LENGTH {
        return Err(ClientAssertionFailure::JtiTooLong);
    }

    Ok(VerifiedClientAssertion {
        jti,
        expires_at,
        replay_guard_until: expires_at + CLOCK_SKEW_LEEWAY,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::client_jwks::parse_registration_jwks;
    use crate::domain::jwt::{generate_ec_keypair, generate_rsa_keypair, public_jwk, sign};
    use serde::Serialize;

    const CLIENT_ID: &str = "machine-client";
    const AUDIENCE: &str = "https://idp.example.com/019700000000700080000000000000001";

    #[derive(Serialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        jti: Option<String>,
    }

    struct Fixture {
        private_pem: String,
        algorithm: &'static str,
        jwks: ClientJwks,
    }

    fn fixture(algorithm: &'static str) -> Fixture {
        let (private_pem, public_pem) = match algorithm {
            "RS256" => generate_rsa_keypair().unwrap(),
            _ => generate_ec_keypair().unwrap(),
        };
        let jwk = public_jwk("k1", algorithm, &public_pem).unwrap();
        let raw = serde_json::to_string(&crate::domain::jwt::Jwks { keys: vec![jwk] }).unwrap();
        Fixture {
            private_pem,
            algorithm,
            jwks: parse_registration_jwks(&raw).unwrap(),
        }
    }

    fn assertion(f: &Fixture, claims: TestClaims) -> String {
        sign(&f.private_pem, "k1", "JWT", f.algorithm, &claims).unwrap()
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    fn valid_claims() -> TestClaims {
        TestClaims {
            iss: CLIENT_ID.to_string(),
            sub: CLIENT_ID.to_string(),
            aud: AUDIENCE.to_string(),
            exp: now().timestamp() + 120,
            jti: Some("jti-1".to_string()),
        }
    }

    fn verify(f: &Fixture, token: &str) -> Result<VerifiedClientAssertion, ClientAssertionFailure> {
        verify_client_assertion(
            Some(JWT_BEARER_ASSERTION_TYPE),
            token,
            CLIENT_ID,
            &f.jwks,
            &[AUDIENCE.to_string()],
            now(),
        )
    }

    #[test]
    fn accepts_a_well_formed_assertion_for_both_algorithms() {
        for algorithm in ["RS256", "ES256"] {
            let f = fixture(algorithm);
            let verified = verify(&f, &assertion(&f, valid_claims())).unwrap();
            assert_eq!(verified.jti, "jti-1");
            assert_eq!(verified.expires_at.timestamp(), now().timestamp() + 120);
            // The replay-refusal period is longer than `exp` by the clock skew leeway (kept until acceptance stops).
            assert_eq!(
                verified.replay_guard_until,
                verified.expires_at + CLOCK_SKEW_LEEWAY
            );
        }
    }

    #[test]
    fn the_assertion_type_must_be_jwt_bearer() {
        let f = fixture("RS256");
        let token = assertion(&f, valid_claims());
        assert_eq!(
            verify_client_assertion(
                None,
                &token,
                CLIENT_ID,
                &f.jwks,
                &[AUDIENCE.to_string()],
                now()
            ),
            Err(ClientAssertionFailure::UnsupportedAssertionType)
        );
        assert_eq!(
            verify_client_assertion(
                Some("urn:example:other"),
                &token,
                CLIENT_ID,
                &f.jwks,
                &[AUDIENCE.to_string()],
                now()
            ),
            Err(ClientAssertionFailure::UnsupportedAssertionType)
        );
    }

    /// An assertion signed with a different key does not pass (= replacing the registered key revokes it).
    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let registered = fixture("RS256");
        let attacker = fixture("RS256");
        let token = assertion(&attacker, valid_claims());
        assert_eq!(
            verify(&registered, &token),
            Err(ClientAssertionFailure::InvalidSignature)
        );
    }

    #[test]
    fn an_unregistered_kid_is_rejected() {
        let f = fixture("RS256");
        let token = sign(
            &f.private_pem,
            "other-kid",
            "JWT",
            f.algorithm,
            &valid_claims(),
        )
        .unwrap();
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::UnknownKey));
    }

    #[test]
    fn iss_and_sub_must_both_be_the_client_itself() {
        let f = fixture("RS256");
        let other_iss = assertion(
            &f,
            TestClaims {
                iss: "someone-else".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &other_iss),
            Err(ClientAssertionFailure::SubjectMismatch)
        );

        let other_sub = assertion(
            &f,
            TestClaims {
                sub: "someone-else".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &other_sub),
            Err(ClientAssertionFailure::SubjectMismatch)
        );
    }

    /// A JWT signed for a different audience does not pass even if forwarded to assay's `/token`.
    #[test]
    fn an_assertion_for_another_audience_is_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                aud: "https://other.example.com/token".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::AudienceMismatch)
        );
    }

    /// An assertion addressed to another tenant's issuer does not pass in this tenant (ADR-0030 decision 6).
    #[test]
    fn an_assertion_for_another_tenant_is_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                aud: "https://idp.example.com/019700000000700080000000000000002".to_string(),
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::AudienceMismatch)
        );
    }

    /// Expiry is checked with **the injected `now`** (not system time). The fixed `now()` points ahead of real time,
    /// so if the `exp` check were left to `jsonwebtoken`, this assertion would pass.
    #[test]
    fn expired_assertions_are_rejected_against_the_injected_clock() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                // Placed safely in the past, beyond the clock skew leeway (60 seconds).
                exp: now().timestamp() - 300,
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::Expired));
    }

    #[test]
    fn assertions_valid_for_longer_than_the_cap_are_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                exp: now().timestamp()
                    + MAX_ASSERTION_LIFETIME.num_seconds()
                    + CLOCK_SKEW_LEEWAY.num_seconds()
                    + 60,
                ..valid_claims()
            },
        );
        assert_eq!(
            verify(&f, &token),
            Err(ClientAssertionFailure::LifetimeTooLong)
        );
    }

    /// A validity of exactly the limit passes even if the client's clock is a little fast (clock skew leeway).
    #[test]
    fn a_cap_length_assertion_from_a_slightly_fast_clock_is_accepted() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                exp: now().timestamp() + MAX_ASSERTION_LIFETIME.num_seconds() + 5,
                ..valid_claims()
            },
        );
        assert!(verify(&f, &token).is_ok());
    }

    /// An overly long `jti` is rejected at verification (so the record INSERT does not become a DB error).
    #[test]
    fn an_overlong_jti_is_rejected() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                jti: Some("j".repeat(MAX_JTI_LENGTH + 1)),
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::JtiTooLong));

        let at_limit = assertion(
            &f,
            TestClaims {
                jti: Some("j".repeat(MAX_JTI_LENGTH)),
                ..valid_claims()
            },
        );
        assert!(verify(&f, &at_limit).is_ok());
    }

    #[test]
    fn a_jti_is_required() {
        let f = fixture("RS256");
        let token = assertion(
            &f,
            TestClaims {
                jti: None,
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &token), Err(ClientAssertionFailure::MissingJti));

        let empty = assertion(
            &f,
            TestClaims {
                jti: Some(String::new()),
                ..valid_claims()
            },
        );
        assert_eq!(verify(&f, &empty), Err(ClientAssertionFailure::MissingJti));
    }

    #[test]
    fn the_unverified_subject_is_readable_without_the_key() {
        let f = fixture("RS256");
        let token = assertion(&f, valid_claims());
        assert_eq!(unverified_subject(&token).as_deref(), Some(CLIENT_ID));
        // Nothing can be extracted from something not shaped like a JWT.
        assert_eq!(unverified_subject("not-a-jwt"), None);
        assert_eq!(unverified_subject("a.b"), None);
    }

    #[test]
    fn garbage_is_rejected_as_malformed() {
        let f = fixture("RS256");
        assert_eq!(
            verify(&f, "not-a-jwt"),
            Err(ClientAssertionFailure::Malformed)
        );
    }

    /// `aud` can also be an array (RFC 7519 §4.1.3). Passes if it contains any of the candidates.
    #[test]
    fn an_audience_array_containing_the_tenant_is_accepted() {
        let f = fixture("RS256");
        #[derive(Serialize)]
        struct ArrayAudClaims {
            iss: String,
            sub: String,
            aud: Vec<String>,
            exp: i64,
            jti: String,
        }
        let token = sign(
            &f.private_pem,
            "k1",
            "JWT",
            f.algorithm,
            &ArrayAudClaims {
                iss: CLIENT_ID.to_string(),
                sub: CLIENT_ID.to_string(),
                aud: vec![
                    "https://other.example.com".to_string(),
                    AUDIENCE.to_string(),
                ],
                exp: now().timestamp() + 120,
                jti: "jti-1".to_string(),
            },
        )
        .unwrap();
        assert_eq!(verify(&f, &token).unwrap().jti, "jti-1");
    }
}
