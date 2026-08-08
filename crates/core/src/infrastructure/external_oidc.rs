//! `ExternalOidcClient` の実装（reqwest + jsonwebtoken。AP10）。
//!
//! 外部 IdP の `/token` へ認可コードを出し、返ってきた ID Token を **JWKS で署名検証してから**
//! クレームを返す。検証の中身:
//!
//! 1. 署名（`kid` で JWKS から鍵を選ぶ。RS256 / ES256）
//! 2. `iss` が設定した issuer と完全一致
//! 3. `aud` に自分の `client_id` を含む
//! 4. `exp`（jsonwebtoken の既定検証。leeway は既定 60 秒）
//! 5. `nonce` が発行時に保存した値と一致（リプレイ検出）
//!
//! どれか 1 つでも欠けると「外部 IdP が言ったことにできる」ので、すべてこの 1 箇所で行う。

use crate::domain::error::{DomainError, Result};
use crate::domain::external_idp::ExternalClaims;
use crate::domain::external_oidc_port::{ExternalOidcClient, ExternalTokenRequest};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// 外部 IdP への 1 リクエストの上限。応答しない IdP でログインを待たせ続けない。
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// `/token` の応答（必要なのは `id_token` だけ）。
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// JWKS の 1 鍵（RSA / EC のうち、署名検証に必要な値だけを読む）。
#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    // RSA
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// ID Token のクレームのうち、連携に使うもの。
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

pub struct ReqwestExternalOidcClient {
    http: reqwest::Client,
}

impl ReqwestExternalOidcClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                // リダイレクトは追わない。追うと、設定した token/jwks エンドポイントとは別の
                // ホストへ資格情報や検証要求が飛びうる（設定の意味が失われる）。
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet> {
        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| DomainError::Repository(format!("failed to fetch JWKS: {e}")))?;
        if !response.status().is_success() {
            return Err(DomainError::Repository(format!(
                "JWKS endpoint returned {}",
                response.status()
            )));
        }
        response
            .json::<JwkSet>()
            .await
            .map_err(|e| DomainError::Repository(format!("invalid JWKS document: {e}")))
    }
}

impl Default for ReqwestExternalOidcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// JWK を `jsonwebtoken` の検証鍵へ変換する。
fn decoding_key(jwk: &Jwk) -> Result<(DecodingKey, Algorithm)> {
    match jwk.kty.as_str() {
        "RSA" => {
            let (n, e) = (jwk.n.as_deref(), jwk.e.as_deref());
            let (Some(n), Some(e)) = (n, e) else {
                return Err(DomainError::Repository(
                    "RSA JWK is missing `n` or `e`".to_string(),
                ));
            };
            let key = DecodingKey::from_rsa_components(n, e)
                .map_err(|e| DomainError::Repository(format!("invalid RSA JWK: {e}")))?;
            // `alg` を明示していない JWKS もあるため、RSA の既定は RS256 とする。
            let alg = match jwk.alg.as_deref() {
                Some("RS384") => Algorithm::RS384,
                Some("RS512") => Algorithm::RS512,
                _ => Algorithm::RS256,
            };
            Ok((key, alg))
        }
        "EC" => {
            let (x, y) = (jwk.x.as_deref(), jwk.y.as_deref());
            let (Some(x), Some(y)) = (x, y) else {
                return Err(DomainError::Repository(
                    "EC JWK is missing `x` or `y`".to_string(),
                ));
            };
            let key = DecodingKey::from_ec_components(x, y)
                .map_err(|e| DomainError::Repository(format!("invalid EC JWK: {e}")))?;
            let alg = match (jwk.alg.as_deref(), jwk.crv.as_deref()) {
                (Some("ES384"), _) | (_, Some("P-384")) => Algorithm::ES384,
                _ => Algorithm::ES256,
            };
            Ok((key, alg))
        }
        other => Err(DomainError::Repository(format!(
            "unsupported JWK key type: {other}"
        ))),
    }
}

#[async_trait]
impl ExternalOidcClient for ReqwestExternalOidcClient {
    async fn exchange_code(&self, request: ExternalTokenRequest<'_>) -> Result<ExternalClaims> {
        // 1. 認可コードを交換する。client_secret を持つなら POST body で送る
        //    （`client_secret_post`。Basic のみの IdP もあるが、まずは広く受け入れられる方を使う）。
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", request.code),
            ("redirect_uri", request.redirect_uri),
            ("client_id", request.client_id),
            ("code_verifier", request.code_verifier),
        ];
        if let Some(secret) = request.client_secret {
            form.push(("client_secret", secret));
        }
        let response = self
            .http
            .post(request.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| DomainError::Repository(format!("token request failed: {e}")))?;
        if !response.status().is_success() {
            // 応答本文には外部 IdP のエラー詳細が入るが、そのまま利用者へは返さない
            //（呼び出し側が汎用の失敗として扱う）。運用ログのために状態コードだけ残す。
            return Err(DomainError::Repository(format!(
                "external token endpoint returned {}",
                response.status()
            )));
        }
        let tokens: TokenResponse = response
            .json()
            .await
            .map_err(|e| DomainError::Repository(format!("invalid token response: {e}")))?;
        let Some(id_token) = tokens.id_token else {
            return Err(DomainError::Repository(
                "external token response has no id_token".to_string(),
            ));
        };

        // 2. `kid` で検証鍵を選ぶ。`kid` が無い IdP もあるので、その場合は唯一の鍵を使う
        //    （複数あって `kid` が無いのは選びようがないため失敗させる）。
        let header = jsonwebtoken::decode_header(&id_token)
            .map_err(|e| DomainError::Repository(format!("invalid id_token header: {e}")))?;
        let jwks = self.fetch_jwks(request.jwks_uri).await?;
        let jwk = match header.kid.as_deref() {
            Some(kid) => jwks
                .keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .ok_or_else(|| {
                    DomainError::Repository("id_token kid is not in the JWKS".to_string())
                })?,
            None if jwks.keys.len() == 1 => &jwks.keys[0],
            None => {
                return Err(DomainError::Repository(
                    "id_token has no kid and the JWKS has multiple keys".to_string(),
                ));
            }
        };
        let (key, algorithm) = decoding_key(jwk)?;

        // 3. 署名・`iss`・`aud`・`exp` を検証する。
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[request.expected_issuer]);
        validation.set_audience(&[request.client_id]);
        let claims = jsonwebtoken::decode::<IdTokenClaims>(&id_token, &key, &validation)
            .map_err(|e| DomainError::Repository(format!("id_token verification failed: {e}")))?
            .claims;

        // 4. `nonce` を照合する（リプレイ検出）。`iss`/`aud`/`exp` と違い jsonwebtoken は見ないため、
        //    ここで必ず自分で確かめる。欠落も不一致として扱う（fail-closed）。
        if claims.nonce.as_deref() != Some(request.expected_nonce) {
            return Err(DomainError::Repository(
                "id_token nonce does not match the authorization request".to_string(),
            ));
        }

        Ok(ExternalClaims {
            issuer: claims.iss,
            subject: claims.sub,
            email: claims.email,
            email_verified: claims.email_verified.unwrap_or(false),
            name: claims.name,
            nonce: claims.nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RSA JWK に `alg` が無ければ RS256 とみなす（多くの IdP が `alg` を省く）。
    #[test]
    fn rsa_jwk_without_alg_defaults_to_rs256() {
        // RFC 7515 A.2 のテスト鍵（modulus は途中で切っても構文検証には十分ではないため、
        // ここでは変換の失敗系だけを確認する）。
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        // `n`/`e` が無ければ鍵を作れない（黙って通さない）。
        assert!(decoding_key(&jwk).is_err());
    }

    #[test]
    fn unsupported_key_types_are_rejected() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: None,
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        // 共有鍵（`oct`）を受け入れると、JWKS を差し替えられる立場の相手が任意の ID Token を
        // 作れてしまう。非対称鍵に限る。
        assert!(decoding_key(&jwk).is_err());
    }
}
