//! Access Token（`typ=at+jwt` の JWT）の検証（`/userinfo`・`/introspect`・`/revoke` で共有する）。
//!
//! 確かめる段は 2 つある:
//!
//! 1. [`AccessTokenVerifier::verify_issued`] —— **このテナントが発行したアクセストークンか**
//!    （`typ`・`kid`・署名鍵・署名・`iss`）。宛先（`aud`）も期限も見ない。失効（`/revoke`）は、
//!    管理 API 向けなど宛先の違うトークンも対象にするので、ここまででよい
//! 2. [`AccessTokenVerifier::verify_for_userinfo`] —— 1 に加えて、`/userinfo` 宛てで、期限内で
//!    （クロックスキューを許す）、失効していないか。`/userinfo` と `/introspect` が使う
//!
//! 失敗の理由は [`AccessTokenRejection`] で返し、どう扱うか（401 にするか、`active: false` に
//! するか）は呼び出し側が決める。

use crate::application::token::{userinfo_audience, AccessTokenClaims};
use crate::domain::clock::Clock;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::repositories::{RevokedAccessTokenRepository, SigningKeyRepository};
use crate::domain::tenant_context::TenantContext;
use jsonwebtoken::Validation;
use std::sync::Arc;

/// アクセストークンを受け付けない理由。
#[derive(Debug)]
pub enum AccessTokenRejection {
    /// JWT として読めない。
    Malformed,
    /// `typ` が `at+jwt` ではない（ID Token 等の取り違え）。
    NotAnAccessToken,
    /// `kid` が無い。
    MissingKeyId,
    /// `kid` の署名鍵が無い（別の発行者・破棄済みの鍵）。
    UnknownSigningKey,
    /// 署名が合わない。
    InvalidSignature,
    /// `iss` がこのテナントの発行者ではない。
    IssuerMismatch,
    /// `aud` が `/userinfo` ではない。
    AudienceMismatch,
    /// 期限切れ（クロックスキューを越えて）。
    Expired,
    /// 失効リストにある。
    Revoked,
    /// 確かめる材料を引けなかった（保存先の障害など）。
    Unavailable(String),
}

impl AccessTokenRejection {
    /// `/userinfo` の 401 に載せる短い理由（利用者の言語に依らない固定文字列）。
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed token",
            Self::NotAnAccessToken => "token typ must be `at+jwt`",
            Self::MissingKeyId => "token has no kid",
            Self::UnknownSigningKey => "unknown signing key",
            Self::InvalidSignature => "signature verification failed",
            Self::IssuerMismatch => "issuer mismatch",
            Self::AudienceMismatch => "audience mismatch",
            Self::Expired => "token expired",
            Self::Revoked => "token has been revoked",
            Self::Unavailable(_) => "verification material unavailable",
        }
    }
}

pub struct AccessTokenVerifier {
    keys: Arc<dyn SigningKeyRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer。テナント毎に `<基底>/<tenant_id>` を合成して `iss`/`aud` を厳密照合する
    /// （ADR-0009 §6。他テナント発行トークンの流用を防ぐ）。
    base_issuer: String,
    clock_skew: chrono::Duration,
}

impl AccessTokenVerifier {
    pub fn new(
        keys: Arc<dyn SigningKeyRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        clock_skew: std::time::Duration,
    ) -> Self {
        Self {
            keys,
            revoked_access_tokens,
            clock,
            base_issuer,
            clock_skew: chrono::Duration::from_std(clock_skew).expect("clock skew out of range"),
        }
    }

    /// このテナントが発行したアクセストークンか（`typ`・`kid`・署名・`iss`）。宛先と期限は見ない。
    pub async fn verify_issued(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<AccessTokenClaims, AccessTokenRejection> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| AccessTokenRejection::Malformed)?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(AccessTokenRejection::NotAnAccessToken);
        }
        let kid = header.kid.ok_or(AccessTokenRejection::MissingKeyId)?;
        let key = self
            .keys
            .find_by_kid(&kid)
            .await
            .map_err(|e| AccessTokenRejection::Unavailable(e.to_string()))?
            .ok_or(AccessTokenRejection::UnknownSigningKey)?;
        // 検証アルゴリズムは**署名鍵の algorithm**（RS256 / ES256）で決める。RS256 に決め打ちに
        // すると、ES256 鍵を ACTIVE にした環境で発行された at+jwt がすべて弾かれる。
        let (decoding_key, algorithm) = jwt::decoding_key_for(&key.algorithm, &key.public_key)
            .map_err(|e| AccessTokenRejection::Unavailable(e.to_string()))?;

        // exp / aud は Clock トレイト経由の時刻で自前検証する（テストで時刻固定するため）。
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let claims = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| AccessTokenRejection::InvalidSignature)?
            .claims;

        if claims.iss != self.issuer_of(tenant) {
            return Err(AccessTokenRejection::IssuerMismatch);
        }
        Ok(claims)
    }

    /// `/userinfo` 宛ての、期限内で失効していないアクセストークンか。
    pub async fn verify_for_userinfo(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<AccessTokenClaims, AccessTokenRejection> {
        let claims = self.verify_issued(tenant, token).await?;
        if claims.aud != userinfo_audience(&self.issuer_of(tenant)) {
            return Err(AccessTokenRejection::AudienceMismatch);
        }
        if self.is_expired(&claims) {
            return Err(AccessTokenRejection::Expired);
        }
        // jti 失効リスト確認（F5: token revocation）。
        if !claims.jti.is_empty()
            && self
                .revoked_access_tokens
                .is_revoked(&claims.jti)
                .await
                .map_err(|e| AccessTokenRejection::Unavailable(e.to_string()))?
        {
            return Err(AccessTokenRejection::Revoked);
        }
        Ok(claims)
    }

    /// 期限切れか（クロックスキューを許す）。
    pub fn is_expired(&self, claims: &AccessTokenClaims) -> bool {
        claims.exp + self.clock_skew.num_seconds() <= self.clock.now().timestamp()
    }

    fn issuer_of(&self, tenant: TenantContext) -> String {
        tenant_issuer(&self.base_issuer, tenant.tenant_id())
    }
}
