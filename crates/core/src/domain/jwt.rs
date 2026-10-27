//! JWT（RS256 / ES256）の署名と、JWKS 用の公開鍵表現。
//!
//! - 署名: `jsonwebtoken` の `EncodingKey`（秘密鍵 PEM から）で RS256 または ES256 署名する。
//!   ヘッダに `kid` と `typ`（ID Token=`JWT` / Access Token=`at+jwt`）を付与する。
//! - JWKS: RSA は `n`/`e`、EC は `crv`/`x`/`y` を base64url で取り出して `Jwk` を構築する。
//! - 検証: JWKS の各フィールドから `DecodingKey` を作る（`/userinfo`・テストで使用）。
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

/// JWK（RSA または EC 公開鍵）。JWKS エンドポイントの 1 要素。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    /// RSA: modulus。EC: x 座標。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA: exponent。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC: 曲線名（例 `P-256`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC: x 座標。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC: y 座標。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// RSA-2048 の鍵ペアを生成し、`(秘密鍵 PKCS#1 PEM, 公開鍵 SPKI PEM)` を返す。
///
/// aws-lc-rs は秘密鍵を PKCS#8 でしか書き出さないので、その中身（`privateKey` の OCTET STRING が
/// そのまま PKCS#1 の `RSAPrivateKey`）を取り出して PKCS#1 で包み直す。保存済みの鍵と同じ形に揃える。
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

/// NIST P-256（ES256 用）の鍵ペアを生成し、`(秘密鍵 PKCS#8 PEM, 公開鍵 SPKI PEM)` を返す。
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

/// 秘密鍵 PEM で RS256 または ES256 署名した JWT を返す。
/// `typ` は `JWT`（ID Token）または `at+jwt`（Access Token）。
/// `algorithm` は `RS256` または `ES256`。
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

/// 公開鍵 PEM から `kid` 付きの RSA JWK を構築する。
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

/// 公開鍵 PEM（SPKI）から `kid` 付きの EC JWK（P-256 / ES256）を構築する。
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

/// algorithm に応じた JWK を構築する（`RS256` / `ES256` を判別）。
pub fn public_jwk(kid: &str, algorithm: &str, public_pem: &str) -> anyhow::Result<Jwk> {
    match algorithm {
        "RS256" => rsa_public_jwk(kid, public_pem),
        "ES256" => ec_public_jwk(kid, public_pem),
        other => anyhow::bail!("unsupported algorithm for JWK: {other}"),
    }
}

/// JWK（`n`/`e`）から RSA 検証用の `DecodingKey` を作る。
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

/// 公開鍵 PEM（SPKI / RSA SPKI）から RSA 検証用の `DecodingKey` を作る（`/userinfo` で使用）。
pub fn decoding_key_from_public_pem(public_pem: &str) -> anyhow::Result<DecodingKey> {
    DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("build decoding key from PEM: {e}"))
}

/// 署名鍵レコード（algorithm 文字列 + 公開鍵 PEM）から検証用の `DecodingKey` と `Algorithm` を作る。
///
/// `decoding_key_from_public_pem` と違い ES256 の鍵も扱える。退役済みの鍵で署名された古い
/// トークン（`id_token_hint` 等）を検証する経路は、鍵の algorithm を決め打ちにできない。
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
