//! Validation and normalization of verification keys (JWK Set) registered by clients (ADR-0030 decisions 3, 4).
//!
//! Public keys for verifying `private_key_jwt` client assertions are looked up **only** in this set stored in
//! `clients.jwks`. The client's `jwks_uri` is not fetched, so as not to bring client-side hosting failures
//! and requests to arbitrary URLs (SSRF) into the authentication path.
//!
//! Keys that cannot be imported fail **at registration time** and are not carried to `/token` time. If
//! "stored but unusable keys" show up mid-authentication, it cannot be determined on the spot whether the failure
//! is caused by the client's signature or by the registration.
//!
//! Key rotation is done by listing old and new keys side by side in this set (the IdP has no notion of a transition period).

use crate::domain::jwt::{decoding_key_from_jwk, Jwk, Jwks};
use crate::domain::message::MessageKey;

/// Number of keys one client can register. Rotation (old and new side by side) needs 2, and
/// 8 is enough even allowing for distributing separate keys to several callers. The limit exists to
/// bound the scan when an assertion without `kid` arrives at verification, and the size of the stored JSON.
pub const MAX_CLIENT_JWKS_KEYS: usize = 8;

/// A validated, normalized client JWK Set (public keys only).
///
/// There are only two ways to create one, [`parse_registration_jwks`] (admin path input) and [`from_storage`] (read back from the DB),
/// and both go through the same validation. An "unvalidated JWK Set" never becomes this type.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientJwks {
    keys: Vec<Jwk>,
}

/// Why a registered JWK Set is unusable. Carries translation keys because it is returned to users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientJwksError {
    /// Cannot be read as JSON.
    Malformed,
    /// No keys at all.
    Empty,
    /// Too many keys.
    TooManyKeys,
    /// Unsupported key type (other than RSA / EC P-256).
    UnsupportedKeyType,
    /// A required field (`kid` or key components) is missing.
    MissingField,
    /// Contains private key components.
    PrivateKeyMaterial,
    /// The same `kid` appears more than once.
    DuplicateKid,
    /// Key components cannot be read as a key (broken as base64url, etc.).
    InvalidKeyMaterial,
}

impl ClientJwksError {
    pub fn message_key(&self) -> MessageKey {
        MessageKey::new(match self {
            Self::Malformed => "api-client-jwks-malformed",
            Self::Empty => "api-client-jwks-empty",
            Self::TooManyKeys => "api-client-jwks-too-many-keys",
            Self::UnsupportedKeyType => "api-client-jwks-unsupported-key-type",
            Self::MissingField => "api-client-jwks-missing-field",
            Self::PrivateKeyMaterial => "api-client-jwks-private-key-material",
            Self::DuplicateKid => "api-client-jwks-duplicate-kid",
            Self::InvalidKeyMaterial => "api-client-jwks-invalid-key-material",
        })
    }
}

/// The JWK received at registration (as written by the client).
///
/// Many implementations omit `use` and `alg`, so they are optional and filled in during normalization. Private key components
/// (`d` / `p` / `q` / `dp` / `dq` / `qi`) are **explicitly rejected rather than just not accepted**, so they are
/// held as fields to check for presence (silently discarding them would tell a registrant who pasted a private key
/// that "registration succeeded").
#[derive(Debug, Clone, serde::Deserialize)]
struct SubmittedJwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    // `alg` is accepted but not used (silently discarded as an unknown field). The verification algorithm is decided
    // from the key type, so the client's self-declaration is not carried around (ADR-0030 decision 7).
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<String>,
    p: Option<String>,
    q: Option<String>,
    dp: Option<String>,
    dq: Option<String>,
    qi: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SubmittedJwks {
    keys: Vec<SubmittedJwk>,
}

impl SubmittedJwk {
    fn has_private_material(&self) -> bool {
        self.d.is_some()
            || self.p.is_some()
            || self.q.is_some()
            || self.dp.is_some()
            || self.dq.is_some()
            || self.qi.is_some()
    }

    /// Normalizes into a [`Jwk`] holding only public key components. `use` becomes `sig`; `alg` is filled from the key type.
    fn normalize(self) -> Result<Jwk, ClientJwksError> {
        if self.has_private_material() {
            return Err(ClientJwksError::PrivateKeyMaterial);
        }
        // `kid` is required. When several keys are listed during rotation, only `kid` can determine
        // which one signed the assertion (a key without one would force brute force).
        let kid = self.kid.filter(|k| !k.is_empty());
        let Some(kid) = kid else {
            return Err(ClientJwksError::MissingField);
        };
        match self.kty.as_str() {
            "RSA" => {
                let (Some(n), Some(e)) = (
                    self.n.filter(|v| !v.is_empty()),
                    self.e.filter(|v| !v.is_empty()),
                ) else {
                    return Err(ClientJwksError::MissingField);
                };
                Ok(Jwk {
                    kty: "RSA".to_string(),
                    use_: self.use_.unwrap_or_else(|| "sig".to_string()),
                    kid,
                    // The only RSA algorithm assay uses for verification is RS256 (ADR-0030 decision 7).
                    // Even if the client wrote a different `alg`, verification is decided from the registered key type.
                    alg: "RS256".to_string(),
                    n: Some(n),
                    e: Some(e),
                    crv: None,
                    x: None,
                    y: None,
                })
            }
            "EC" => {
                // The only supported curve is P-256 (aligned with the signing key's `SigningAlgorithm`).
                if self.crv.as_deref() != Some("P-256") {
                    return Err(ClientJwksError::UnsupportedKeyType);
                }
                let (Some(x), Some(y)) = (
                    self.x.filter(|v| !v.is_empty()),
                    self.y.filter(|v| !v.is_empty()),
                ) else {
                    return Err(ClientJwksError::MissingField);
                };
                Ok(Jwk {
                    kty: "EC".to_string(),
                    use_: self.use_.unwrap_or_else(|| "sig".to_string()),
                    kid,
                    alg: "ES256".to_string(),
                    n: None,
                    e: None,
                    crv: Some("P-256".to_string()),
                    x: Some(x),
                    y: Some(y),
                })
            }
            _ => Err(ClientJwksError::UnsupportedKeyType),
        }
    }
}

/// Validates and normalizes a JWK Set (JSON string) received by the admin path.
pub fn parse_registration_jwks(raw: &str) -> Result<ClientJwks, ClientJwksError> {
    let submitted: SubmittedJwks =
        serde_json::from_str(raw).map_err(|_| ClientJwksError::Malformed)?;
    build(submitted)
}

fn build(submitted: SubmittedJwks) -> Result<ClientJwks, ClientJwksError> {
    if submitted.keys.is_empty() {
        return Err(ClientJwksError::Empty);
    }
    if submitted.keys.len() > MAX_CLIENT_JWKS_KEYS {
        return Err(ClientJwksError::TooManyKeys);
    }
    let keys = submitted
        .keys
        .into_iter()
        .map(SubmittedJwk::normalize)
        .collect::<Result<Vec<_>, _>>()?;

    // Check at registration that key components can actually be read as a key. Letting through keys that are only well-shaped
    // (e.g. `n` broken as base64url) makes the failure happen at `/token` time, with the reason being
    // "registered key not found", which cannot be told apart from a problem with the client's signature.
    for key in &keys {
        if decoding_key_from_jwk(key).is_err() {
            return Err(ClientJwksError::InvalidKeyMaterial);
        }
    }

    // With a duplicate `kid`, "which key verified it" cannot be decided from the request. Rejected at registration so that
    // adding a new key with the same `kid` as a supposedly revoked key does not silently work.
    for (i, key) in keys.iter().enumerate() {
        if keys[i + 1..].iter().any(|other| other.kid == key.kid) {
            return Err(ClientJwksError::DuplicateKid);
        }
    }
    Ok(ClientJwks { keys })
}

impl ClientJwks {
    /// Reads back from JSON stored in the DB. Goes through the same validation as when saving.
    ///
    /// Stored values are not trusted unchecked so that rows edited directly in the DB or saved in an old format
    /// do not slip into the verification path (fail-closed).
    pub fn from_storage(raw: &str) -> Result<Self, ClientJwksError> {
        parse_registration_jwks(raw)
    }

    /// The JSON string stored in the DB (normalized).
    pub fn to_storage_json(&self) -> String {
        // Contains only normalized `Jwk`s, so serialization does not fail.
        serde_json::to_string(&Jwks {
            keys: self.keys.clone(),
        })
        .unwrap_or_else(|_| "{\"keys\":[]}".to_string())
    }

    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Selects the key matching the assertion header's `kid`.
    ///
    /// An assertion without `kid` is verified with the registered key only when there is exactly one. If there are several,
    /// there is no way to choose, so `None` (= verification fails): letting brute force pass would
    /// silently hide that an old key listed for rotation is "still valid".
    pub fn select(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => self.keys.iter().find(|k| k.kid == kid),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl\
                         UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre\
                         cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_\
                         7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI\
                         Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU\
                         7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";

    fn rsa_jwks(kid: &str) -> String {
        format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"{RSA_N}","e":"AQAB"}}]}}"#)
    }

    #[test]
    fn normalizes_a_minimal_rsa_key() {
        let jwks = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        let key = &jwks.keys()[0];
        assert_eq!(key.kid, "k1");
        // `use` and `alg` are filled in even if omitted.
        assert_eq!(key.use_, "sig");
        assert_eq!(key.alg, "RS256");
        assert_eq!(key.e.as_deref(), Some("AQAB"));
    }

    #[test]
    fn a_private_key_is_rejected_rather_than_silently_stripped() {
        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB","d":"secret"}}]}}"#
        );
        assert_eq!(
            parse_registration_jwks(&raw),
            Err(ClientJwksError::PrivateKeyMaterial)
        );
    }

    #[test]
    fn keys_need_a_kid_and_their_components() {
        let no_kid = format!(r#"{{"keys":[{{"kty":"RSA","n":"{RSA_N}","e":"AQAB"}}]}}"#);
        assert_eq!(
            parse_registration_jwks(&no_kid),
            Err(ClientJwksError::MissingField)
        );
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[{"kty":"RSA","kid":"k1","e":"AQAB"}]}"#),
            Err(ClientJwksError::MissingField)
        );
    }

    #[test]
    fn unsupported_key_types_and_curves_are_rejected() {
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[{"kty":"oct","kid":"k1","k":"c2VjcmV0"}]}"#),
            Err(ClientJwksError::UnsupportedKeyType)
        );
        assert_eq!(
            parse_registration_jwks(
                r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-384","x":"a","y":"b"}]}"#
            ),
            Err(ClientJwksError::UnsupportedKeyType)
        );
    }

    #[test]
    fn empty_malformed_and_oversized_sets_are_rejected() {
        assert_eq!(
            parse_registration_jwks(r#"{"keys":[]}"#),
            Err(ClientJwksError::Empty)
        );
        assert_eq!(
            parse_registration_jwks("not json"),
            Err(ClientJwksError::Malformed)
        );
        let many: Vec<String> = (0..=MAX_CLIENT_JWKS_KEYS)
            .map(|i| format!(r#"{{"kty":"RSA","kid":"k{i}","n":"{RSA_N}","e":"AQAB"}}"#))
            .collect();
        assert_eq!(
            parse_registration_jwks(&format!(r#"{{"keys":[{}]}}"#, many.join(","))),
            Err(ClientJwksError::TooManyKeys)
        );
    }

    /// Values that are well-shaped but unreadable as keys are rejected at registration (not carried to `/token` time).
    #[test]
    fn keys_whose_components_are_not_readable_are_rejected() {
        assert_eq!(
            parse_registration_jwks(
                r#"{"keys":[{"kty":"RSA","kid":"k1","n":"not base64!!","e":"AQAB"}]}"#
            ),
            Err(ClientJwksError::InvalidKeyMaterial)
        );
        assert_eq!(
            parse_registration_jwks(
                r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"not base64!!","y":"AQAB"}]}"#
            ),
            Err(ClientJwksError::InvalidKeyMaterial)
        );
    }

    #[test]
    fn duplicate_kids_are_rejected() {
        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}},
                         {{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}}]}}"#
        );
        assert_eq!(
            parse_registration_jwks(&raw),
            Err(ClientJwksError::DuplicateKid)
        );
    }

    #[test]
    fn selecting_without_a_kid_works_only_when_one_key_is_registered() {
        let single = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        assert_eq!(single.select(None).unwrap().kid, "k1");
        assert_eq!(single.select(Some("k1")).unwrap().kid, "k1");
        assert!(single.select(Some("other")).is_none());

        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{RSA_N}","e":"AQAB"}},
                         {{"kty":"RSA","kid":"k2","n":"{RSA_N}","e":"AQAB"}}]}}"#
        );
        let pair = parse_registration_jwks(&raw).unwrap();
        assert!(pair.select(None).is_none());
        assert_eq!(pair.select(Some("k2")).unwrap().kid, "k2");
    }

    #[test]
    fn storage_round_trip_keeps_the_normalized_form() {
        let jwks = parse_registration_jwks(&rsa_jwks("k1")).unwrap();
        let restored = ClientJwks::from_storage(&jwks.to_storage_json()).unwrap();
        assert_eq!(restored, jwks);
    }
}
