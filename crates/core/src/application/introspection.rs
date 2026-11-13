//! Token introspection endpoint use case (F5: RFC 7662).
//!
//! - Confidential client authentication is required (public clients cannot use it). The method follows the
//!   client's registered value (`client_secret_basic` / `client_secret_post`), same as `/token`.
//! - access_token: verify the JWT (signature, iss, aud, exp) and check jti against the revocation list.
//! - refresh_token: check validity in the DB (not revoked, not expired).
//! - Invalid or unknown tokens return `{ "active": false }` (not an error).

use crate::application::access_token_verification::{AccessTokenRejection, AccessTokenVerifier};
use crate::application::client_authentication::{
    ClientAuthError, ClientAuthOutcome, ClientAuthenticator, PresentedClientCredentials,
};
use crate::application::token::KeyConfirmation;
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::OAuthErrorCode;
use crate::domain::issuer::tenant_issuer;
use crate::domain::repositories::{ClientRepository, RefreshTokenRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use serde::Serialize;
use std::sync::Arc;

/// RFC 7662 introspection response.
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
    /// Key bound with DPoP (RFC 9449 §6.2. ADR-0075 decision 8). Omitted when not bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<KeyConfirmation>,
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
            cnf: None,
        }
    }
}

/// Introspection-specific errors (client authentication failure only; an invalid token returns inactive).
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
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    /// Access token verification (signature, typ, iss, aud, exp, revocation. `access_token_verification`).
    access_tokens: Arc<AccessTokenVerifier>,
    users: Arc<dyn UserRepository>,
    client_auth: Arc<ClientAuthenticator>,
    clock: Arc<dyn Clock>,
    /// Base issuer. The `iss` for verification and response is composed per tenant as `<base>/<tenant_id>` (ADR-0009 §6).
    base_issuer: String,
}

impl IntrospectionService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        access_tokens: Arc<AccessTokenVerifier>,
        users: Arc<dyn UserRepository>,
        client_auth: Arc<ClientAuthenticator>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            clients,
            refresh_tokens,
            access_tokens,
            users,
            client_auth,
            clock,
            base_issuer,
        }
    }

    pub async fn introspect(
        &self,
        tenant: TenantContext,
        token: &str,
        token_type_hint: Option<&str>,
        credentials: &PresentedClientCredentials,
    ) -> Result<IntrospectionResponse, IntrospectionError> {
        // Confidential client authentication (required; only resolves clients belonging to the flow's tenant).
        // Authenticate first regardless of whether a token is present (there is no point answering an unauthenticated
        // party with a different response just for "is the token empty", and RFC 7662 §2.1 requires authentication).
        let client = self
            .authenticate_confidential_client(tenant, credentials)
            .await?;

        if token.is_empty() {
            return Ok(IntrospectionResponse::inactive());
        }

        // `iss` is composed per tenant (bound to the issuing tenant. ADR-0009 §6).
        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());

        // Try access_token / refresh_token according to token_type_hint.
        match token_type_hint {
            Some("refresh_token") => {
                let resp = self
                    .introspect_refresh_token(tenant, token, &client, &issuer)
                    .await;
                if resp.active {
                    return Ok(resp);
                }
                Ok(self.introspect_access_token(tenant, token).await)
            }
            _ => {
                let resp = self.introspect_access_token(tenant, token).await;
                if resp.active {
                    return Ok(resp);
                }
                Ok(self
                    .introspect_refresh_token(tenant, token, &client, &issuer)
                    .await)
            }
        }
    }

    /// Introspection of an access token (JWT).
    async fn introspect_access_token(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> IntrospectionResponse {
        let claims = match self.access_tokens.verify_for_userinfo(tenant, token).await {
            Ok(claims) => claims,
            Err(AccessTokenRejection::Unavailable(e)) => {
                tracing::warn!(error = %e, "failed to verify access token for introspection");
                return IntrospectionResponse::inactive();
            }
            Err(_) => return IntrospectionResponse::inactive(),
        };

        // Check the subject's current state. Tokens of disabled or deleted subjects are inactive even before exp
        // (admin disabling/deletion takes effect immediately; same check as /userinfo).
        // For `client_credentials` tokens (G4) the subject is the client itself, so check the client's validity, not
        // a user's (`sub` is not a UUID, so a user lookup would always fail).
        let subject_active = if claims.subject_is_client() {
            self.client_subject_is_active(tenant, &claims.sub).await
        } else {
            self.subject_is_active(&claims.sub).await
        };
        if !subject_active {
            return IntrospectionResponse::inactive();
        }

        IntrospectionResponse {
            active: true,
            scope: Some(claims.scope),
            client_id: Some(claims.client_id),
            username: None,
            token_type: Some(
                if claims.cnf.is_some() {
                    "DPoP"
                } else {
                    "Bearer"
                }
                .to_string(),
            ),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
            cnf: claims.cnf,
        }
    }

    /// Introspection of a refresh token (including matching the issuing tenant).
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

        // Check the user's current state (disabled/deleted are inactive; same as the access_token path).
        let user = match self.users.find_by_id(rt.user_id).await {
            Ok(Some(user)) if user.is_active() => user,
            _ => return IntrospectionResponse::inactive(),
        };

        IntrospectionResponse {
            active: true,
            scope: Some(rt.scope.join(" ")),
            client_id: Some(rt.client_id),
            username: None,
            token_type: Some("refresh_token".to_string()),
            exp: Some(rt.expires_at.timestamp()),
            iat: None,
            // The public `sub` (same value as the ID Token and access token). It used to return the internal user ID
            // (task #593; it disagreed with the access token path and leaked the internal ID to RPs).
            sub: Some(user.sub.to_string()),
            iss: Some(issuer.to_string()),
            // A refresh token is opaque and has no JWT `jti`. Returning the stored SHA-256 hash as `jti`
            // would leak an internal stored value to the client, so it is omitted (jti is optional in RFC 7662).
            jti: None,
            cnf: rt.dpop_jkt.map(|jkt| KeyConfirmation { jkt }),
        }
    }

    /// Returns whether the client in the `sub` claim exists and is ACTIVE (G4; a lookup failure counts as inactive).
    async fn client_subject_is_active(&self, tenant: TenantContext, sub: &str) -> bool {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), sub)
            .await
        {
            Ok(Some(client)) => client.is_active(),
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load client during introspection");
                false
            }
        }
    }

    /// Returns whether the user in the `sub` claim exists and is ACTIVE (an invalid `sub` or lookup failure counts as inactive).
    async fn subject_is_active(&self, sub: &str) -> bool {
        let Ok(sub) = uuid::Uuid::parse_str(sub) else {
            return false;
        };
        match self.users.find_by_sub(sub).await {
            Ok(Some(user)) => user.is_active(),
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load user during introspection");
                false
            }
        }
    }

    /// Only confidential clients may authenticate (RFC 7662 §2.1). The method is the same as `/token`
    /// (`client_secret_basic` / `client_secret_post`. G3).
    async fn authenticate_confidential_client(
        &self,
        tenant: TenantContext,
        credentials: &PresentedClientCredentials,
    ) -> Result<Client, IntrospectionError> {
        credentials.ensure_single_method().map_err(|_| {
            IntrospectionError::new(
                OAuthErrorCode::InvalidRequest,
                "client credentials must be presented with a single authentication method",
            )
        })?;
        let client_id = credentials.resolve_client_id().map_err(|_| {
            IntrospectionError::new(
                OAuthErrorCode::InvalidClient,
                "client authentication is required for introspection",
            )
        })?;

        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), &client_id)
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

        // Credential checking is centralized in `client_authentication` (G3, ADR-0030).
        // Public clients cannot use this (RFC 7662 §2.1). The authenticator passes public clients through as
        // `NotRequired`, so they are rejected separately here.
        match self
            .client_auth
            .authenticate(tenant, &client, credentials)
            .await
        {
            Ok(ClientAuthOutcome::Authenticated) => {}
            Ok(ClientAuthOutcome::NotRequired) => {
                return Err(IntrospectionError::new(
                    OAuthErrorCode::InvalidClient,
                    "introspection requires a confidential client",
                ))
            }
            Err(ClientAuthError::Failed(_)) => {
                return Err(IntrospectionError::new(
                    OAuthErrorCode::InvalidClient,
                    "client authentication failed",
                ))
            }
            Err(ClientAuthError::Internal(message)) => {
                // Internal error details are not shown to the client (not subject to translation under `CLAUDE.md` "i18n").
                tracing::error!(error = %message, "client authentication internal error");
                return Err(IntrospectionError::new(
                    OAuthErrorCode::ServerError,
                    "internal server error",
                ));
            }
        }

        Ok(client)
    }
}
