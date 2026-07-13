//! トークン発行のユースケース（`POST /token`、設計仕様 §4.4・§5・§9.1）。
//!
//! - `authorization_code` grant: client 認証 → code の原子的 one-time 消費 →
//!   各種一致検証 → PKCE S256 検証 → ID Token / Access Token（RS256）発行。
//!   scope に `offline_access` が含まれる場合は Refresh Token も発行する。
//! - `refresh_token` grant: client 認証 → Refresh Token の検証 → rotation →
//!   reuse detection → 新 Access Token / ID Token 発行。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::key_service::KeyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::OAuthErrorCode;
use crate::domain::issuer::tenant_issuer;
use crate::domain::password::PasswordHasher;
use crate::domain::pkce;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::repositories::{
    AuthorizationCodeRepository, ClientRepository, RefreshTokenRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
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
    /// `authorization_code` grant 専用。
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// body の `client_id`（public client では必須）。
    pub client_id: Option<String>,
    /// `Authorization: Basic` から取り出した `(client_id, client_secret)`。
    pub basic_credentials: Option<(String, String)>,
    /// `refresh_token` grant 専用。
    pub refresh_token: Option<String>,
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
    /// `offline_access` scope が含まれる場合のみ発行する。
    pub refresh_token: Option<String>,
}

pub struct TokenService {
    clients: Arc<dyn ClientRepository>,
    users: Arc<dyn UserRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    keys: Arc<KeyService>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer（`https://<host>`）。`iss` はテナント毎に `<基底>/<tenant_id>` を合成する
    /// （ADR-0009 §6。`domain::issuer::tenant_issuer`）。
    base_issuer: String,
    access_token_ttl: std::time::Duration,
    id_token_ttl: std::time::Duration,
    refresh_token_ttl: std::time::Duration,
}

impl TokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        users: Arc<dyn UserRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        keys: Arc<KeyService>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        access_token_ttl: std::time::Duration,
        id_token_ttl: std::time::Duration,
        refresh_token_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            users,
            codes,
            refresh_tokens,
            keys,
            hasher,
            audit,
            clock,
            base_issuer,
            access_token_ttl,
            id_token_ttl,
            refresh_token_ttl,
        }
    }

    pub async fn exchange(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        match cmd.grant_type.as_deref() {
            Some("authorization_code") => self.exchange_code(tenant, cmd, ctx).await,
            Some("refresh_token") => self.exchange_refresh_token(tenant, cmd, ctx).await,
            _ => Err(TokenError::new(
                OAuthErrorCode::UnsupportedGrantType,
                "grant_type must be `authorization_code` or `refresh_token`",
            )),
        }
    }

    /// `authorization_code` grant の処理。
    async fn exchange_code(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. client_id の決定（Basic ヘッダ優先）。
        let client_id = resolve_client_id(&cmd)?;

        // 2. client の存在・状態・認証（フローのテナントに属する client のみ解決する）。
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 3. code_verifier の形式検証（RFC 7636 §4.1）。
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

        // 4. code の原子的 one-time 消費。
        let Some(code) = cmd.code.as_deref().filter(|c| !c.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code is required",
            ));
        };
        let now = self.clock.now();
        let consumed = match self
            .codes
            .consume(tenant_id, &crypto::sha256_hex(code), now)
            .await
        {
            Ok(c) => c,
            Err(e) => return Err(internal(&e)),
        };
        let Some(auth_code) = consumed else {
            self.audit
                .record(
                    AuditEventType::AuthorizationCodeReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
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
                Some(tenant_id),
                Some(auth_code.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 5. client_id / redirect_uri の一致検証。
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

        // 6. PKCE S256 検証。
        if !pkce::verify_s256(code_verifier, &auth_code.code_challenge) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "PKCE verification failed",
            ));
        }

        // 7. ユーザーの状態確認。
        let user = self.load_active_user(auth_code.user_id, ctx).await?;

        // 8. トークン発行（scope は AuthorizationCodes.scope を引き継ぐ）。
        let has_offline = auth_code
            .scope
            .iter()
            .any(|v| v == Scope::OfflineAccess.as_str());
        let has = |s: Scope| auth_code.scope.iter().any(|v| v == s.as_str());
        let scope_str = auth_code.scope.join(" ");
        let iat = now.timestamp();
        // `iss` はテナント毎に合成する（ADR-0009 §6）。発行テナント（= フローのテナント）に束縛する。
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: auth_code.auth_time.timestamp(),
            nonce: auth_code.nonce.clone(),
            jti: Uuid::new_v4().to_string(),
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 9. Refresh Token 発行（offline_access scope のときのみ）。
        let refresh_token_plain = if has_offline {
            let plain = crypto::random_token(32);
            let rt = RefreshToken {
                token_hash: crypto::sha256_hex(&plain),
                parent_hash: None,
                tenant_id,
                user_id: auth_code.user_id,
                client_id: client_id.clone(),
                scope: auth_code.scope.clone(),
                expires_at: now + chrono::Duration::from_std(self.refresh_token_ttl).unwrap(),
                revoked_at: None,
                created_at: now,
            };
            if let Err(e) = self.refresh_tokens.create(&rt).await {
                return Err(internal(&e));
            }
            self.audit
                .record(
                    AuditEventType::RefreshTokenIssued,
                    AuditResult::Success,
                    Some(tenant_id),
                    Some(auth_code.user_id),
                    Some(&client_id),
                    None,
                    ctx,
                )
                .await;
            Some(plain)
        } else {
            None
        };

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
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
            scope: scope_str,
            refresh_token: refresh_token_plain,
        })
    }

    /// `refresh_token` grant の処理（rotation + reuse detection）。
    async fn exchange_refresh_token(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. client_id の決定・認証。
        let client_id = resolve_client_id(&cmd)?;
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 2. refresh_token パラメータの取り出し。
        let Some(rt_plain) = cmd.refresh_token.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "refresh_token is required",
            ));
        };
        let rt_hash = crypto::sha256_hex(rt_plain);
        let now = self.clock.now();

        // 3. トークン検索（発行テナントの一致を含む。他テナント発行のトークンは解決しない）。
        let stored = match self.refresh_tokens.find_by_hash(tenant_id, &rt_hash).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "refresh_token not found",
                ));
            }
            Err(e) => return Err(internal(&e)),
        };

        // 4. client_id 一致確認。
        if stored.client_id != client_id {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token was issued to another client",
            ));
        }

        // 5. reuse detection: すでに同じトークンから新トークンが発行済みなら全チェーン失効。
        let already_rotated = match self.refresh_tokens.exists_by_parent_hash(&rt_hash).await {
            Ok(v) => v,
            Err(e) => return Err(internal(&e)),
        };
        if already_rotated {
            // このトークンはすでに rotation 済み → 再利用攻撃の可能性。
            // 旧トークンも失効させる（best-effort）。
            let _ = self.refresh_tokens.revoke(&rt_hash, now).await;
            self.audit
                .record(
                    AuditEventType::RefreshTokenReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(stored.user_id),
                    Some(&client_id),
                    Some("refresh token already rotated"),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token has already been used",
            ));
        }

        // 6. 有効性確認（失効・期限切れ）。
        if !stored.is_valid_at(now) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token is revoked or expired",
            ));
        }

        // 7. ユーザーの状態確認。
        let user = self.load_active_user(stored.user_id, ctx).await?;

        // 8. 旧トークンを失効させる（rotation）。
        if let Err(e) = self.refresh_tokens.revoke(&rt_hash, now).await {
            return Err(internal(&e));
        }

        // 9. 新トークン発行。
        let has = |s: Scope| stored.scope.iter().any(|v| v == s.as_str());
        let scope_str = stored.scope.join(" ");
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: iat,       // refresh 時は現在時刻（再認証なし）
            nonce: String::new(), // refresh grant では nonce は不要
            jti: Uuid::new_v4().to_string(),
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 10. 新 Refresh Token 発行（rotation）。
        let new_rt_plain = crypto::random_token(32);
        let new_rt = RefreshToken {
            token_hash: crypto::sha256_hex(&new_rt_plain),
            parent_hash: Some(rt_hash.clone()),
            tenant_id,
            user_id: stored.user_id,
            client_id: client_id.clone(),
            scope: stored.scope.clone(),
            expires_at: stored.expires_at, // TTL は引き継ぐ（スライドさせない）
            revoked_at: None,
            created_at: now,
        };
        if let Err(e) = self.refresh_tokens.create(&new_rt).await {
            return Err(internal(&e));
        }

        self.audit
            .record(
                AuditEventType::RefreshTokenUsed,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::RefreshTokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token,
            expires_in: self.access_token_ttl.as_secs(),
            scope: scope_str,
            refresh_token: Some(new_rt_plain),
        })
    }

    async fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "JWT", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    async fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "at+jwt", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    /// クライアント認証（設計仕様 §4.4）。
    async fn authenticate_client(
        &self,
        tenant: TenantContext,
        client: &Client,
        cmd: &TokenCommand,
        ctx: &RequestContext,
    ) -> Result<(), TokenError> {
        match client.client_type {
            ClientType::Confidential => {
                let Some((_, secret)) = &cmd.basic_credentials else {
                    return Err(self
                        .client_auth_failed(
                            tenant,
                            &client.client_id,
                            "missing_basic_credentials",
                            ctx,
                        )
                        .await);
                };
                if client.token_endpoint_auth_method != TokenEndpointAuthMethod::ClientSecretBasic {
                    return Err(self
                        .client_auth_failed(
                            tenant,
                            &client.client_id,
                            "unsupported_auth_method",
                            ctx,
                        )
                        .await);
                }
                let Some(secret_hash) = &client.client_secret_hash else {
                    return Err(self
                        .client_auth_failed(tenant, &client.client_id, "client_has_no_secret", ctx)
                        .await);
                };
                let ok = self
                    .hasher
                    .verify(secret, secret_hash)
                    .map_err(|e| internal(&e))?;
                if !ok {
                    return Err(self
                        .client_auth_failed(tenant, &client.client_id, "invalid_client_secret", ctx)
                        .await);
                }
                Ok(())
            }
            ClientType::Public => Ok(()),
        }
    }

    async fn load_active_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<Client, TokenError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            Ok(Some(c)) if c.is_active() => Ok(c),
            Ok(Some(_)) => Err(self
                .client_auth_failed(tenant, client_id, "client_not_active", ctx)
                .await),
            Ok(None) => Err(self
                .client_auth_failed(tenant, client_id, "unknown_client", ctx)
                .await),
            Err(e) => Err(internal(&e)),
        }
    }

    async fn load_active_user(
        &self,
        user_id: uuid::Uuid,
        _ctx: &RequestContext,
    ) -> Result<crate::domain::user::User, TokenError> {
        match self.users.find_by_id(user_id).await {
            Ok(Some(u)) if u.is_active() => Ok(u),
            Ok(Some(_)) => Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "user is not active",
            )),
            Ok(None) => Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "user no longer exists",
            )),
            Err(e) => Err(internal(&e)),
        }
    }

    async fn client_auth_failed(
        &self,
        tenant: TenantContext,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) -> TokenError {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
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

/// client_id を Basic ヘッダ優先で解決する。
fn resolve_client_id(cmd: &TokenCommand) -> Result<String, TokenError> {
    match (&cmd.basic_credentials, &cmd.client_id) {
        (Some((basic_id, _)), Some(body_id)) if basic_id != body_id => Err(TokenError::new(
            OAuthErrorCode::InvalidRequest,
            "client_id mismatch between Authorization header and body",
        )),
        (Some((basic_id, _)), _) => Ok(basic_id.clone()),
        (None, Some(body_id)) if !body_id.is_empty() => Ok(body_id.clone()),
        _ => Err(TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication is required",
        )),
    }
}

fn internal<E: std::fmt::Display>(e: &E) -> TokenError {
    tracing::error!(error = %e, "token endpoint internal error");
    TokenError {
        code: OAuthErrorCode::ServerError,
        description: "internal server error".to_string(),
    }
}
