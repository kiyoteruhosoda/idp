//! JWT (RS256 / ES256) signing and the public key representation for JWKS.
//!
//! - Signing: signs RS256 or ES256 with `jsonwebtoken`'s `EncodingKey` (from a private key PEM).
//!   Adds `kid` and `typ` (ID Token=`JWT` / Access Token=`at+jwt`) to the header.
//! - JWKS: builds a `Jwk` by extracting `n`/`e` for RSA, `crv`/`x`/`y` for EC, in base64url.
//! - Verification: builds a `DecodingKey` from JWKS fields (used by `/userinfo` and tests).
#![allow(dead_code)]

use crate::domain::crypto::base64url;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize, PublicKey as RsaPublicKey};
use aws_lc_rs::signature::KeyPair as _;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use p256::elliptic_curve::Generate as _;
use p256::pkcs8::{
    DecodePublicKey as EcDecodePublicKey, EncodePrivateKey, EncodePublicKey as _, LineEnding,
};
use pkcs8::der::pem;
use serde::{Deserialize, Serialize};

/// JWK (RSA or EC public key). One element of the JWKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    /// RSA: modulus. EC: x coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA: exponent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC: curve name (e.g. `P-256`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC: x coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC: y coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Generates an RSA-2048 key pair and returns `(private key PKCS#1 PEM, public key SPKI PEM)`.
///
/// aws-lc-rs writes private keys only as PKCS#8, so its content (the `privateKey` OCTET STRING is
/// exactly the PKCS#1 `RSAPrivateKey`) is extracted and rewrapped as PKCS#1, matching the stored
/// keys' form.
pub fn generate_rsa_keypair() -> anyhow::Result<(String, String)> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|e| anyhow::anyhow!("RSA keygen failed: {e}"))?;

    let pkcs8_der = pair
        .as_der()
        .map_err(|e| anyhow::anyhow!("encode private key: {e}"))?;
    let info = pkcs8::PrivateKeyInfoRef::try_from(pkcs8_der.as_ref())
        .map_err(|e| anyhow::anyhow!("read PKCS#8 private key: {e}"))?;
    let private_pem = pem::encode_string(
        "RSA PRIVATE KEY",
        LineEnding::LF,
        info.private_key.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("encode private PEM: {e}"))?;

    let spki_der = pair
        .public_key()
        .as_der()
        .map_err(|e| anyhow::anyhow!("encode public key: {e}"))?;
    let public_pem = pem::encode_string("PUBLIC KEY", LineEnding::LF, spki_der.as_ref())
        .map_err(|e| anyhow::anyhow!("encode public PEM: {e}"))?;

    Ok((private_pem, public_pem))
}

/// Generates a NIST P-256 (for ES256) key pair and returns
/// `(private key PKCS#8 PEM, public key SPKI PEM)`.
pub fn generate_ec_keypair() -> anyhow::Result<(String, String)> {
    use p256::ecdsa::SigningKey;
    let secret = SigningKey::generate_from_rng(&mut rand::rng());
    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode EC private PEM: {e}"))?
        .to_string();
    let public_pem = secret
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode EC public PEM: {e}"))?;
    Ok((private_pem, public_pem))
}

/// Returns a JWT signed RS256 or ES256 with the private key PEM.
/// `typ` is `JWT` (ID Token) or `at+jwt` (Access Token).
/// `algorithm` is `RS256` or `ES256`.
pub fn sign<T: Serialize>(
    private_pem: &str,
    kid: &str,
    typ: &str,
    algorithm: &str,
    claims: &T,
) -> anyhow::Result<String> {
    let (key, alg) = match algorithm {
        "RS256" => (
            EncodingKey::from_rsa_pem(private_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("load RSA encoding key: {e}"))?,
            Algorithm::RS256,
        ),
        "ES256" => (
            EncodingKey::from_ec_pem(private_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("load EC encoding key: {e}"))?,
            Algorithm::ES256,
        ),
        other => anyhow::bail!("unsupported signing algorithm: {other}"),
    };

    let mut header = Header::new(alg);
    header.kid = Some(kid.to_string());
    header.typ = Some(typ.to_string());

    encode(&header, claims, &key).map_err(|e| anyhow::anyhow!("jwt encode: {e}"))
}

/// Builds an RSA JWK with `kid` from a public key PEM.
pub fn rsa_public_jwk(kid: &str, public_pem: &str) -> anyhow::Result<Jwk> {
    let (_, spki_der) = pem::decode_vec(public_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("parse RSA public PEM: {e}"))?;
    let public = RsaPublicKey::from_der(&spki_der)
        .map_err(|e| anyhow::anyhow!("parse RSA public key: {e}"))?;
    Ok(Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        kid: kid.to_string(),
        alg: "RS256".to_string(),
        n: Some(base64url(
            public.modulus().big_endian_without_leading_zero(),
        )),
        e: Some(base64url(
            public.exponent().big_endian_without_leading_zero(),
        )),
        crv: None,
        x: None,
        y: None,
    })
}

/// Builds an EC JWK (P-256 / ES256) with `kid` from a public key PEM (SPKI).
pub fn ec_public_jwk(kid: &str, public_pem: &str) -> anyhow::Result<Jwk> {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let public: p256::PublicKey = p256::PublicKey::from_public_key_pem(public_pem)
        .map_err(|e| anyhow::anyhow!("parse EC public PEM: {e}"))?;
    let point = public.to_sec1_point(false);
    let x = point
        .x()
        .ok_or_else(|| anyhow::anyhow!("EC point has no x coordinate"))?;
    let y = point
        .y()
        .ok_or_else(|| anyhow::anyhow!("EC point has no y coordinate"))?;
    Ok(Jwk {
        kty: "EC".to_string(),
        use_: "sig".to_string(),
        kid: kid.to_string(),
        alg: "ES256".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(base64url(x)),
        y: Some(base64url(y)),
        n: None,
        e: None,
    })
}

/// Builds the JWK matching the algorithm (distinguishes `RS256` / `ES256`).
pub fn public_jwk(kid: &str, algorithm: &str, public_pem: &str) -> anyhow::Result<Jwk> {
    match algorithm {
        "RS256" => rsa_public_jwk(kid, public_pem),
        "ES256" => ec_public_jwk(kid, public_pem),
        other => anyhow::bail!("unsupported algorithm for JWK: {other}"),
    }
}

/// Builds an RSA verification `DecodingKey` from a JWK (`n`/`e`).
pub fn decoding_key_from_jwk(jwk: &Jwk) -> anyhow::Result<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("RSA JWK missing n"))?;
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("RSA JWK missing e"))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| anyhow::anyhow!("build RSA decoding key: {e}"))
        }
        "EC" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("EC JWK missing x"))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("EC JWK missing y"))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| anyhow::anyhow!("build EC decoding key: {e}"))
        }
        other => anyhow::bail!("unsupported JWK kty: {other}"),
    }
}

/// Builds an RSA verification `DecodingKey` from a public key PEM (SPKI / RSA SPKI) (used by
/// `/userinfo`).
pub fn decoding_key_from_public_pem(public_pem: &str) -> anyhow::Result<DecodingKey> {
    DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("build decoding key from PEM: {e}"))
}

/// Builds a verification `DecodingKey` and `Algorithm` from a signing key record
/// (algorithm string + public key PEM).
///
/// Unlike `decoding_key_from_public_pem`, it also handles ES256 keys. The path verifying old tokens
/// signed with a retired key (`id_token_hint` etc.) cannot hard-code the key's algorithm.
pub fn decoding_key_for(
    algorithm: &str,
    public_pem: &str,
) -> anyhow::Result<(DecodingKey, Algorithm)> {
    let jwk = public_jwk("verify", algorithm, public_pem)?;
    let key = decoding_key_from_jwk(&jwk)?;
    let alg = match algorithm {
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        other => anyhow::bail!("unsupported algorithm for verification: {other}"),
    };
    Ok((key, alg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Claims {
        sub: String,
        iss: String,
        exp: usize,
    }

    #[test]
    fn rs256_sign_sets_header_and_verifies_against_jwk() {
        let (private_pem, public_pem) = generate_rsa_keypair().unwrap();
        let claims = Claims {
            sub: "user-1".to_string(),
            iss: "https://idp.example.com".to_string(),
            exp: 9_999_999_999,
        };

        let token = sign(&private_pem, "kid-1", "at+jwt", "RS256", &claims).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some("kid-1"));
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));

        let jwk = rsa_public_jwk("kid-1", &public_pem).unwrap();
        let decoding_key = decoding_key_from_jwk(&jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp"]);

        let data = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(data.claims.sub, "user-1");
    }

    #[test]
    fn rs256_verification_fails_with_a_different_key() {
        let (private_pem, _) = generate_rsa_keypair().unwrap();
        let (_, other_public_pem) = generate_rsa_keypair().unwrap();
        let claims = Claims {
            sub: "u".to_string(),
            iss: "i".to_string(),
            exp: 9_999_999_999,
        };
        let token = sign(&private_pem, "kid-1", "JWT", "RS256", &claims).unwrap();

        let jwk = rsa_public_jwk("kid-1", &other_public_pem).unwrap();
        let decoding_key = decoding_key_from_jwk(&jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp"]);

        assert!(jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).is_err());
    }

    #[test]
    fn es256_sign_sets_header_and_verifies_against_jwk() {
        let (private_pem, public_pem) = generate_ec_keypair().unwrap();
        let claims = Claims {
            sub: "user-2".to_string(),
            iss: "https://idp.example.com".to_string(),
            exp: 9_999_999_999,
        };

        let token = sign(&private_pem, "kid-ec-1", "at+jwt", "ES256", &claims).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("kid-ec-1"));

        let jwk = ec_public_jwk("kid-ec-1", &public_pem).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));

        let decoding_key = decoding_key_from_jwk(&jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp"]);

        let data = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(data.claims.sub, "user-2");
    }
}
