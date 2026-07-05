//! JWT（RS256）の署名と、JWKS 用の公開鍵表現。
//!
//! - 署名: `jsonwebtoken` の `EncodingKey`（秘密鍵 PEM から）で RS256 署名する。
//!   ヘッダに `kid` と `typ`（ID Token=`JWT` / Access Token=`at+jwt`）を付与する。
//! - JWKS: 公開鍵 PEM から RSA の `n`/`e` を base64url で取り出して `Jwk` を構築する。
//! - 検証: JWKS の `n`/`e` から `DecodingKey` を作る（`/userinfo`・テストで使用）。
#![allow(dead_code)]

use crate::infrastructure::crypto::base64url;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

/// JWK（RSA 公開鍵）。JWKS エンドポイントの 1 要素。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// RSA-2048 の鍵ペアを生成し、`(秘密鍵 PKCS#1 PEM, 公開鍵 SPKI PEM)` を返す。
pub fn generate_rsa_keypair() -> anyhow::Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| anyhow::anyhow!("RSA keygen failed: {e}"))?;
    let public = RsaPublicKey::from(&private);

    let private_pem = private
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode private PEM: {e}"))?
        .to_string();
    let public_pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("encode public PEM: {e}"))?;

    Ok((private_pem, public_pem))
}

/// 秘密鍵 PEM で RS256 署名した JWT を返す。`typ` は `JWT`（ID Token）または `at+jwt`（Access Token）。
pub fn sign<T: Serialize>(
    private_pem: &str,
    kid: &str,
    typ: &str,
    claims: &T,
) -> anyhow::Result<String> {
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("load encoding key: {e}"))?;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    header.typ = Some(typ.to_string());

    encode(&header, claims, &key).map_err(|e| anyhow::anyhow!("jwt encode: {e}"))
}

/// 公開鍵 PEM から `kid` 付きの JWK を構築する。
pub fn rsa_public_jwk(kid: &str, public_pem: &str) -> anyhow::Result<Jwk> {
    let public = RsaPublicKey::from_public_key_pem(public_pem)
        .map_err(|e| anyhow::anyhow!("parse public PEM: {e}"))?;
    Ok(Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        kid: kid.to_string(),
        alg: "RS256".to_string(),
        n: base64url(&public.n().to_bytes_be()),
        e: base64url(&public.e().to_bytes_be()),
    })
}

/// JWK（`n`/`e`）から検証用の `DecodingKey` を作る。
pub fn decoding_key_from_jwk(jwk: &Jwk) -> anyhow::Result<DecodingKey> {
    DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| anyhow::anyhow!("build decoding key: {e}"))
}

/// 公開鍵 PEM（SPKI）から検証用の `DecodingKey` を作る（`/userinfo` で使用）。
pub fn decoding_key_from_public_pem(public_pem: &str) -> anyhow::Result<DecodingKey> {
    DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("build decoding key from PEM: {e}"))
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
    fn sign_sets_header_and_verifies_against_jwk() {
        let (private_pem, public_pem) = generate_rsa_keypair().unwrap();
        let claims = Claims {
            sub: "user-1".to_string(),
            iss: "https://idp.example.com".to_string(),
            exp: 9_999_999_999,
        };

        let token = sign(&private_pem, "kid-1", "at+jwt", &claims).unwrap();

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
    fn verification_fails_with_a_different_key() {
        let (private_pem, _) = generate_rsa_keypair().unwrap();
        let (_, other_public_pem) = generate_rsa_keypair().unwrap();
        let claims = Claims {
            sub: "u".to_string(),
            iss: "i".to_string(),
            exp: 9_999_999_999,
        };
        let token = sign(&private_pem, "kid-1", "JWT", &claims).unwrap();

        let jwk = rsa_public_jwk("kid-1", &other_public_pem).unwrap();
        let decoding_key = decoding_key_from_jwk(&jwk).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp"]);

        assert!(jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).is_err());
    }
}
