//! UserInfo のユースケース（`GET /userinfo`、設計仕様 §4.7）。
//!
//! Bearer の Access Token（JWT / `typ=at+jwt`）を検証し、scope に応じたクレームのみ返す。
//! `exp` はクロックスキュー（±60 秒）を許容して `Clock` トレイト経由の時刻で検証する。

use crate::application::token::{userinfo_audience, AccessTokenClaims};
use crate::domain::clock::Clock;
use crate::domain::repositories::{
    RevokedAccessTokenRepository, SigningKeyRepository, UserRepository,
};
use crate::domain::values::Scope;
use crate::infrastructure::jwt;
use jsonwebtoken::{Algorithm, Validation};
use std::sync::Arc;
use uuid::Uuid;

/// scope に応じて返却するクレーム（設計仕様 §4.7「scope制御」）。
#[derive(Debug, serde::Serialize)]
pub struct UserInfoClaims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug)]
pub enum UserInfoError {
    /// トークン不正（署名・typ・iss・aud・exp・ユーザー状態）→ 401。
    InvalidToken(&'static str),
    /// `openid` scope を含まない → 403。
    InsufficientScope,
    Internal(String),
}

pub struct UserInfoService {
    keys: Arc<dyn SigningKeyRepository>,
    users: Arc<dyn UserRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    clock: Arc<dyn Clock>,
    issuer: String,
    clock_skew: chrono::Duration,
}

impl UserInfoService {
    pub fn new(
        keys: Arc<dyn SigningKeyRepository>,
        users: Arc<dyn UserRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        clock: Arc<dyn Clock>,
        issuer: String,
        clock_skew: std::time::Duration,
    ) -> Self {
        Self {
            keys,
            users,
            revoked_access_tokens,
            clock,
            issuer,
            clock_skew: chrono::Duration::from_std(clock_skew).expect("clock skew out of range"),
        }
    }

    pub async fn userinfo(&self, bearer_token: &str) -> Result<UserInfoClaims, UserInfoError> {
        let claims = self.verify_access_token(bearer_token).await?;

        let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
        if !scopes.contains(&Scope::OpenId.as_str()) {
            return Err(UserInfoError::InsufficientScope);
        }

        let sub = Uuid::parse_str(&claims.sub)
            .map_err(|_| UserInfoError::InvalidToken("invalid subject"))?;
        let user = self
            .users
            .find_by_sub(sub)
            .await
            .map_err(|e| UserInfoError::Internal(e.to_string()))?
            .ok_or(UserInfoError::InvalidToken("unknown subject"))?;
        if !user.is_active() {
            return Err(UserInfoError::InvalidToken("user is not active"));
        }

        let has = |s: Scope| scopes.contains(&s.as_str());
        Ok(UserInfoClaims {
            sub: user.sub.to_string(),
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: if has(Scope::Profile) {
                user.preferred_username.clone()
            } else {
                None
            },
            name: if has(Scope::Profile) {
                user.name.clone()
            } else {
                None
            },
        })
    }

    /// Access Token（JWT）を検証してクレームを返す（署名・typ・iss・aud・exp）。
    async fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, UserInfoError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| UserInfoError::InvalidToken("malformed token"))?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(UserInfoError::InvalidToken("token typ must be `at+jwt`"));
        }
        let Some(kid) = header.kid else {
            return Err(UserInfoError::InvalidToken("token has no kid"));
        };

        let key = self
            .keys
            .find_by_kid(&kid)
            .await
            .map_err(|e| UserInfoError::Internal(e.to_string()))?
            .ok_or(UserInfoError::InvalidToken("unknown signing key"))?;
        let decoding_key = jwt::decoding_key_from_public_pem(&key.public_key)
            .map_err(|e| UserInfoError::Internal(e.to_string()))?;

        // exp / aud は Clock トレイト経由の時刻で自前検証する（テストで時刻固定するため）。
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let data = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| UserInfoError::InvalidToken("signature verification failed"))?;
        let claims = data.claims;

        if claims.iss != self.issuer {
            return Err(UserInfoError::InvalidToken("issuer mismatch"));
        }
        if claims.aud != userinfo_audience(&self.issuer) {
            return Err(UserInfoError::InvalidToken("audience mismatch"));
        }
        let now = self.clock.now().timestamp();
        if claims.exp + self.clock_skew.num_seconds() <= now {
            return Err(UserInfoError::InvalidToken("token expired"));
        }

        // jti 失効リスト確認（F5: token revocation）。
        if !claims.jti.is_empty() {
            match self.revoked_access_tokens.is_revoked(&claims.jti).await {
                Ok(true) => return Err(UserInfoError::InvalidToken("token has been revoked")),
                Ok(false) => {}
                Err(e) => return Err(UserInfoError::Internal(e.to_string())),
            }
        }

        Ok(claims)
    }
}
