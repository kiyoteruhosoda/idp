//! トークン発行のユースケース（`POST /token`、設計仕様 §4.4・§5）。
//!
//! client 認証（confidential は `client_secret_basic`）→ code の原子的 one-time 消費 →
//! 各種一致検証 → PKCE S256 検証 → ID Token / Access Token（RS256）発行。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::key_service::KeyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::OAuthErrorCode;
use crate::domain::password::PasswordHasher;
use crate::domain::pkce;
use crate::domain::repositories::{AuthorizationCodeRepository, ClientRepository, UserRepository};
use crate::domain::values::{ClientType, Scope, TokenEndpointAuthMethod};
use crate::infrastructure::crypto;
use crate::infrastructure::jwt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// ID Token のクレーム（設計仕様 §5.1）。任意クレームは scope に応じて付与する。
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub nonce: String,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Access Token のクレーム（設計仕様 §5.2）。`aud` は `/userinfo` に固定する。
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

/// `/userinfo` 用 Access Token の `aud` を構築する（issuer は末尾スラッシュ無し）。
pub fn userinfo_audience(issuer: &str) -> String {
    format!("{issuer}/userinfo")
}

#[derive(Debug, Default)]
pub struct TokenCommand {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// body の `client_id`（public client では必須）。
    pub client_id: Option<String>,
    /// `Authorization: Basic` から取り出した `(client_id, client_secret)`。
    pub basic_credentials: Option<(String, String)>,
}

/// トークンエンドポイントのエラー（RFC 6749 §5.2 形式で返す）。
#[derive(Debug)]
pub struct TokenError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl TokenError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct IssuedTokens {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: u64,
    pub scope: String,
}

pub struct TokenService {
    clients: Arc<dyn ClientRepository>,
    users: Arc<dyn UserRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    keys: Arc<KeyService>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    issuer: String,
    access_token_ttl: std::time::Duration,
    id_token_ttl: std::time::Duration,
}

impl TokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        users: Arc<dyn UserRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        keys: Arc<KeyService>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        issuer: String,
        access_token_ttl: std::time::Duration,
        id_token_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            users,
            codes,
            keys,
            hasher,
            audit,
            clock,
            issuer,
            access_token_ttl,
            id_token_ttl,
        }
    }

    pub async fn exchange(
        &self,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        // 1. grant_type。
        if cmd.grant_type.as_deref() != Some("authorization_code") {
            return Err(TokenError::new(
                OAuthErrorCode::UnsupportedGrantType,
                "grant_type must be `authorization_code`",
            ));
        }

        // 2. client_id の決定（Basic ヘッダ優先。双方あって不一致なら invalid_request）。
        let client_id = match (&cmd.basic_credentials, &cmd.client_id) {
            (Some((basic_id, _)), Some(body_id)) if basic_id != body_id => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidRequest,
                    "client_id mismatch between Authorization header and body",
                ));
            }
            (Some((basic_id, _)), _) => basic_id.clone(),
            (None, Some(body_id)) if !body_id.is_empty() => body_id.clone(),
            _ => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidClient,
                    "client authentication is required",
                ));
            }
        };

        // 3. client の存在・状態・認証。
        let client = match self.clients.find_by_client_id(&client_id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err(self
                    .client_auth_failed(&client_id, "unknown_client", ctx)
                    .await);
            }
            Err(e) => return Err(internal(&e)),
        };
        if !client.is_active() {
            return Err(self
                .client_auth_failed(&client_id, "client_not_active", ctx)
                .await);
        }
        self.authenticate_client(&client, &cmd, ctx).await?;

        // 4. code_verifier の形式検証（RFC 7636 §4.1）。
        let Some(code_verifier) = cmd.code_verifier.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier is required",
            ));
        };
        if !pkce::is_valid_code_verifier(code_verifier) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier must be 43-128 characters of [A-Za-z0-9-._~]",
            ));
        }

        // 5. code の原子的 one-time 消費（0 行 = 不存在・期限切れ・使用済み → invalid_grant）。
        let Some(code) = cmd.code.as_deref().filter(|c| !c.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code is required",
            ));
        };
        let now = self.clock.now();
        let consumed = match self.codes.consume(&crypto::sha256_hex(code), now).await {
            Ok(c) => c,
            Err(e) => return Err(internal(&e)),
        };
        let Some(auth_code) = consumed else {
            self.audit
                .record(
                    AuditEventType::AuthorizationCodeReuseDetected,
                    AuditResult::Failure,
                    None,
                    Some(&client_id),
                    Some("code not found, expired, or already used"),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "authorization code is invalid, expired, or already used",
            ));
        };
        self.audit
            .record(
                AuditEventType::AuthorizationCodeUsed,
                AuditResult::Success,
                Some(auth_code.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 6. client_id / redirect_uri の一致検証。
        if auth_code.client_id != client_id {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "authorization code was issued to another client",
            ));
        }
        if cmd.redirect_uri.as_deref() != Some(auth_code.redirect_uri.as_str()) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "redirect_uri does not match the authorization request",
            ));
        }

        // 7. PKCE S256 検証。
        if !pkce::verify_s256(code_verifier, &auth_code.code_challenge) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "PKCE verification failed",
            ));
        }

        // 8. ユーザーの状態確認。
        let user = match self.users.find_by_id(auth_code.user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "user no longer exists",
                ));
            }
            Err(e) => return Err(internal(&e)),
        };
        if !user.is_active() {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "user is not active",
            ));
        }

        // 9. トークン発行（scope は AuthorizationCodes.scope を引き継ぐ）。
        let scope = auth_code.scope.join(" ");
        let iat = now.timestamp();
        let has = |s: Scope| auth_code.scope.iter().any(|v| v == s.as_str());

        let id_claims = IdTokenClaims {
            iss: self.issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: auth_code.auth_time.timestamp(),
            nonce: auth_code.nonce.clone(),
            jti: Uuid::new_v4().to_string(),
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
        };
        let access_claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&self.issuer),
            client_id: client_id.clone(),
            scope: scope.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
        };

        let signing_key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        let id_token = jwt::sign(
            &signing_key.private_pem,
            &signing_key.kid,
            "JWT",
            &id_claims,
        )
        .map_err(|e| internal(&e))?;
        let access_token = jwt::sign(
            &signing_key.private_pem,
            &signing_key.kid,
            "at+jwt",
            &access_claims,
        )
        .map_err(|e| internal(&e))?;

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(auth_code.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token,
            expires_in: self.access_token_ttl.as_secs(),
            scope,
        })
    }

    /// クライアント認証（設計仕様 §4.4）。confidential は `client_secret_basic` 必須、
    /// public は認証なし（`token_endpoint_auth_method=none`）。
    async fn authenticate_client(
        &self,
        client: &Client,
        cmd: &TokenCommand,
        ctx: &RequestContext,
    ) -> Result<(), TokenError> {
        match client.client_type {
            ClientType::Confidential => {
                let Some((_, secret)) = &cmd.basic_credentials else {
                    return Err(self
                        .client_auth_failed(&client.client_id, "missing_basic_credentials", ctx)
                        .await);
                };
                if client.token_endpoint_auth_method != TokenEndpointAuthMethod::ClientSecretBasic {
                    return Err(self
                        .client_auth_failed(&client.client_id, "unsupported_auth_method", ctx)
                        .await);
                }
                let Some(secret_hash) = &client.client_secret_hash else {
                    return Err(self
                        .client_auth_failed(&client.client_id, "client_has_no_secret", ctx)
                        .await);
                };
                let ok = self
                    .hasher
                    .verify(secret, secret_hash)
                    .map_err(|e| internal(&e))?;
                if !ok {
                    return Err(self
                        .client_auth_failed(&client.client_id, "invalid_client_secret", ctx)
                        .await);
                }
                Ok(())
            }
            ClientType::Public => Ok(()),
        }
    }

    async fn client_auth_failed(
        &self,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) -> TokenError {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                None,
                Some(client_id),
                Some(reason),
                ctx,
            )
            .await;
        TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication failed",
        )
    }
}

fn internal<E: std::fmt::Display>(e: &E) -> TokenError {
    tracing::error!(error = %e, "token endpoint internal error");
    TokenError {
        code: OAuthErrorCode::ServerError,
        description: "internal server error".to_string(),
    }
}
