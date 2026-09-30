//! UserInfo のユースケース（`GET /userinfo`、設計仕様 §4.7）。
//!
//! Bearer の Access Token（JWT / `typ=at+jwt`）を検証し、scope に応じたクレームのみ返す。
//! `exp` はクロックスキュー（±60 秒）を許容して `Clock` トレイト経由の時刻で検証する。

use crate::application::access_token_verification::{AccessTokenRejection, AccessTokenVerifier};
use crate::domain::repositories::UserRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::Scope;
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
    users: Arc<dyn UserRepository>,
    /// アクセストークンの検証（署名・typ・iss・aud・exp・失効。`access_token_verification`）。
    access_tokens: Arc<AccessTokenVerifier>,
}

impl UserInfoService {
    pub fn new(users: Arc<dyn UserRepository>, access_tokens: Arc<AccessTokenVerifier>) -> Self {
        Self {
            users,
            access_tokens,
        }
    }

    pub async fn userinfo(
        &self,
        tenant: TenantContext,
        bearer_token: &str,
    ) -> Result<UserInfoClaims, UserInfoError> {
        let claims = self
            .access_tokens
            .verify_for_userinfo(tenant, bearer_token)
            .await
            .map_err(|rejection| match rejection {
                AccessTokenRejection::Unavailable(e) => UserInfoError::Internal(e),
                other => UserInfoError::InvalidToken(other.reason()),
            })?;

        // `client_credentials` で発行したトークンは利用者主体ではないため `/userinfo` では使えない
        //（G4）。`sub` はクライアント自身で、返すべき利用者クレームが存在しない。
        if claims.subject_is_client() {
            return Err(UserInfoError::InvalidToken(
                "client_credentials tokens have no end-user subject",
            ));
        }

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
}
