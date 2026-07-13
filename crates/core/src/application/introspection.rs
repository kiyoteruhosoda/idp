//! Token イントロスペクションエンドポイントのユースケース（F5: RFC 7662）。
//!
//! - confidential client の `client_secret_basic` 認証が必須（public client は使用不可）。
//! - access_token: JWT を検証（署名・iss・aud・exp）し、jti を失効リストと照合する。
//! - refresh_token: DB で有効性（未失効・期限内）を確認する。
//! - 不正トークン・不存在は `{ "active": false }` を返す（エラーにしない）。

use crate::application::token::{userinfo_audience, AccessTokenClaims};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::OAuthErrorCode;
use crate::domain::issuer::tenant_issuer;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{
    ClientRepository, RefreshTokenRepository, RevokedAccessTokenRepository, SigningKeyRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::TokenEndpointAuthMethod;
use crate::infrastructure::crypto;
use crate::infrastructure::jwt;
use jsonwebtoken::{Algorithm, Validation};
use serde::Serialize;
use std::sync::Arc;

/// RFC 7662 イントロスペクションレスポンス。
#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            iss: None,
            jti: None,
        }
    }
}

/// イントロスペクション固有のエラー（client 認証失敗のみ。トークン不正は inactive を返す）。
#[derive(Debug)]
pub struct IntrospectionError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl IntrospectionError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct IntrospectionService {
    clients: Arc<dyn ClientRepository>,
    signing_keys: Arc<dyn SigningKeyRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
    /// 基底 issuer。検証・応答の `iss` はテナント毎に `<基底>/<tenant_id>` を合成する（ADR-0009 §6）。
    base_issuer: String,
    clock_skew: chrono::Duration,
}

impl IntrospectionService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        signing_keys: Arc<dyn SigningKeyRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        clock_skew: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            signing_keys,
            refresh_tokens,
            revoked_access_tokens,
            hasher,
            clock,
            base_issuer,
            clock_skew: chrono::Duration::from_std(clock_skew).expect("clock skew out of range"),
        }
    }

    pub async fn introspect(
        &self,
        tenant: TenantContext,
        token: &str,
        token_type_hint: Option<&str>,
        client_id: &str,
        basic_credentials: Option<(&str, &str)>,
    ) -> Result<IntrospectionResponse, IntrospectionError> {
        if token.is_empty() {
            return Ok(IntrospectionResponse::inactive());
        }

        // confidential client 認証（必須。フローのテナントに属する client のみ解決する）。
        let client = self
            .authenticate_confidential_client(tenant, client_id, basic_credentials)
            .await?;

        // `iss` はテナント毎に合成する（発行テナントに束縛。ADR-0009 §6）。
        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());

        // token_type_hint に従って access_token / refresh_token を試みる。
        match token_type_hint {
            Some("refresh_token") => {
                let resp = self
                    .introspect_refresh_token(tenant, token, &client, &issuer)
                    .await;
                if resp.active {
                    return Ok(resp);
                }
                Ok(self.introspect_access_token(token, &issuer).await)
            }
            _ => {
                let resp = self.introspect_access_token(token, &issuer).await;
                if resp.active {
                    return Ok(resp);
                }
                Ok(self
                    .introspect_refresh_token(tenant, token, &client, &issuer)
                    .await)
            }
        }
    }

    /// Access Token（JWT）のイントロスペクション。`issuer` は要求テナントの合成 issuer。
    async fn introspect_access_token(&self, token: &str, issuer: &str) -> IntrospectionResponse {
        // JWT ヘッダから kid を取得。
        let header = match jsonwebtoken::decode_header(token) {
            Ok(h) => h,
            Err(_) => return IntrospectionResponse::inactive(),
        };
        if header.typ.as_deref() != Some("at+jwt") {
            return IntrospectionResponse::inactive();
        }
        let kid = match header.kid {
            Some(k) => k,
            None => return IntrospectionResponse::inactive(),
        };

        let key = match self.signing_keys.find_by_kid(&kid).await {
            Ok(Some(k)) => k,
            _ => return IntrospectionResponse::inactive(),
        };
        let decoding_key = match jwt::decoding_key_from_public_pem(&key.public_key) {
            Ok(k) => k,
            Err(_) => return IntrospectionResponse::inactive(),
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let claims =
            match jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation) {
                Ok(d) => d.claims,
                Err(_) => return IntrospectionResponse::inactive(),
            };

        // iss / aud 検証（要求テナントの合成 issuer と厳密一致）。
        if claims.iss != issuer || claims.aud != userinfo_audience(issuer) {
            return IntrospectionResponse::inactive();
        }

        // exp 検証（clock skew 許容）。
        let now = self.clock.now().timestamp();
        if claims.exp + self.clock_skew.num_seconds() <= now {
            return IntrospectionResponse::inactive();
        }

        // jti 失効リスト確認。
        if !claims.jti.is_empty() {
            match self.revoked_access_tokens.is_revoked(&claims.jti).await {
                Ok(true) => return IntrospectionResponse::inactive(),
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "failed to check access token revocation list");
                    return IntrospectionResponse::inactive();
                }
            }
        }

        IntrospectionResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: Some(claims.client_id),
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
        }
    }

    /// Refresh Token のイントロスペクション（発行テナントの一致を含む）。
    async fn introspect_refresh_token(
        &self,
        tenant: TenantContext,
        token: &str,
        _requesting_client: &Client,
        issuer: &str,
    ) -> IntrospectionResponse {
        let hash = crypto::sha256_hex(token);
        let rt = match self
            .refresh_tokens
            .find_by_hash(tenant.tenant_id(), &hash)
            .await
        {
            Ok(Some(rt)) => rt,
            _ => return IntrospectionResponse::inactive(),
        };

        let now = self.clock.now();
        if !rt.is_valid_at(now) {
            return IntrospectionResponse::inactive();
        }

        IntrospectionResponse {
            active: true,
            scope: Some(rt.scope.join(" ")),
            client_id: Some(rt.client_id),
            username: None,
            token_type: Some("refresh_token".to_string()),
            exp: Some(rt.expires_at.timestamp()),
            iat: None,
            sub: Some(rt.user_id.to_string()),
            iss: Some(issuer.to_string()),
            jti: Some(rt.token_hash.clone()),
        }
    }

    /// confidential client のみ認証を許可する（RFC 7662 §2.1）。
    async fn authenticate_confidential_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
        basic_credentials: Option<(&str, &str)>,
    ) -> Result<Client, IntrospectionError> {
        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| IntrospectionError::new(OAuthErrorCode::InvalidClient, &e.to_string()))?
            .ok_or_else(|| {
                IntrospectionError::new(OAuthErrorCode::InvalidClient, "unknown client")
            })?;

        if !client.is_active() {
            return Err(IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "client is disabled",
            ));
        }

        if client.token_endpoint_auth_method != TokenEndpointAuthMethod::ClientSecretBasic {
            return Err(IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "introspection requires confidential client (client_secret_basic)",
            ));
        }

        let (cid, secret) = basic_credentials.ok_or_else(|| {
            IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "client_secret_basic authentication required",
            )
        })?;
        if cid != client_id {
            return Err(IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "client_id mismatch",
            ));
        }
        let hash = client.client_secret_hash.as_deref().ok_or_else(|| {
            IntrospectionError::new(OAuthErrorCode::InvalidClient, "client has no secret")
        })?;
        let ok = self
            .hasher
            .verify(secret, hash)
            .map_err(|e| IntrospectionError::new(OAuthErrorCode::ServerError, &e.to_string()))?;
        if !ok {
            return Err(IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "client authentication failed",
            ));
        }

        Ok(client)
    }
}
