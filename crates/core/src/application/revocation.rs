//! Use case for the token revocation endpoint (F5: RFC 7009 Token Revocation).
//!
//! - `refresh_token`: revoked by setting `revoked_at` in the DB.
//! - `access_token`: immediate revocation by adding the JWT's jti to the `revoked_access_tokens` table.
//! - RFC 7009 §2.2: returns 200 even if already revoked or missing (callers always treat it as success).
//! - Confidential clients require authentication (method is the client's registered value: `client_secret_basic` /
//!   `client_secret_post`). Public clients have no authentication.

use crate::application::access_token_verification::{AccessTokenRejection, AccessTokenVerifier};
use crate::application::audit::{AuditService, RequestContext};
use crate::application::client_authentication::{
    ClientAuthError, ClientAuthFailure, ClientAuthOutcome, ClientAuthenticator,
    PresentedClientCredentials,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    ClientRepository, RefreshTokenRepository, RevokedAccessTokenRepository,
};
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

/// Errors of `/revoke` (following RFC 7009 §2.2.1).
#[derive(Debug)]
pub struct RevocationError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl RevocationError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct RevocationService {
    clients: Arc<dyn ClientRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    /// Before revoking, checks "is this an access token issued by this tenant" (T41).
    access_tokens: Arc<AccessTokenVerifier>,
    client_auth: Arc<ClientAuthenticator>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl RevocationService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        access_tokens: Arc<AccessTokenVerifier>,
        client_auth: Arc<ClientAuthenticator>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            refresh_tokens,
            revoked_access_tokens,
            access_tokens,
            client_auth,
            audit,
            clock,
        }
    }

    /// Revokes a token. RFC 7009 §2.2: always expected to return 200 (the only error is client authentication failure).
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        token: &str,
        token_type_hint: Option<&str>,
        credentials: &PresentedClientCredentials,
        ctx: &RequestContext,
    ) -> Result<(), RevocationError> {
        if token.is_empty() {
            return Ok(());
        }

        // Client authentication (resolves only clients belonging to the flow's tenant).
        let client = match self.load_client(tenant, credentials, ctx).await {
            Ok(c) => c,
            Err(e) => return Err(e),
        };

        let now = self.clock.now();

        // Tries according to token_type_hint, but tries both kinds (RFC 7009 §2.1).
        match token_type_hint {
            Some("access_token") => {
                if !self
                    .try_revoke_access_token(tenant, token, now, &client)
                    .await?
                {
                    self.try_revoke_refresh_token(tenant, token, now, &client)
                        .await?;
                }
            }
            _ => {
                // No hint or "refresh_token": try refresh_token first.
                if !self
                    .try_revoke_refresh_token(tenant, token, now, &client)
                    .await?
                {
                    self.try_revoke_access_token(tenant, token, now, &client)
                        .await?;
                }
            }
        }

        self.audit
            .record(
                AuditEventType::RefreshTokenUsed,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                None,
                Some(&client.client_id),
                Some("revocation"),
                ctx,
            )
            .await;

        Ok(())
    }

    /// Tries to revoke a refresh_token. Returns `Ok(true)` if revoked.
    ///
    /// **Returns `Ok(false)` if no matching row**. Returning `true` here would misjudge an access_token revocation
    /// request without `token_type_hint` as "already revoked as a refresh_token", returning 200 without
    /// ever trying the access_token side (RFC 7009 §2.1 requires trying other types if the hint is
    /// wrong).
    ///
    /// **Refuses unless it is the owning client** (ADR-0046. RFC 7009 §2.1). Previously this was
    /// discarded as `_client`, and as long as authentication passed, **tokens issued to other clients
    /// could be deleted**. The repository also deletes by `token_hash` alone, so this layer is the only place to check.
    ///
    /// Distinguishing missing from wrong-owner is intentional. **Missing is 200** (RFC 7009 §2.2:
    /// invalid tokens are not an error), **wrong owner is `unauthorized_client`** (§2.1:
    /// if validation fails, reject the request and say so).
    async fn try_revoke_refresh_token(
        &self,
        tenant: TenantContext,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
        client: &Client,
    ) -> Result<bool, RevocationError> {
        let hash = crypto::sha256_hex(token);
        // Check the owner before revoking. `find_by_hash` also looks at the issuing tenant, so
        // tokens issued by other tenants fall to `None` here (= treated the same as missing).
        let stored = match self
            .refresh_tokens
            .find_by_hash(tenant.tenant_id(), &hash)
            .await
        {
            Ok(Some(t)) => t,
            // Not found = not a refresh_token (might be an access_token).
            Ok(None) => return Ok(false),
            Err(e) => {
                tracing::warn!(error = %e, "failed to look up refresh token for revocation");
                return Ok(false);
            }
        };
        if stored.client_id != client.client_id {
            tracing::warn!(
                client_id = %client.client_id,
                "refresh token revocation refused: the token was issued to another client"
            );
            return Err(RevocationError::new(
                OAuthErrorCode::UnauthorizedClient,
                "the token was not issued to this client",
            ));
        }

        match self.refresh_tokens.revoke(&hash, now).await {
            Ok(revoked) => Ok(revoked > 0),
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke refresh token");
                Ok(false)
            }
        }
    }

    /// Tries to revoke an access_token (JWT). Returns `Ok(true)` if revoked.
    ///
    /// Puts it on the revocation list **after verifying signature and issuer** (T41). Back when `jti` was extracted
    /// without verification, anyone could bloat the revocation list with garbage values shaped like JWTs, and since the
    /// expiry (`exp`) was also taken at face value, cleanup never caught them.
    ///
    /// - Not an access token issued by this tenant (shape, signature, or issuer differs) -> `Ok(false)`
    ///   (might be a refresh token. RFC 7009 §2.2: invalid tokens are not an error)
    /// - Expired -> `Ok(true)` (no longer usable, so nothing to revoke. Not added to the list either)
    /// - **Not the owning client -> `unauthorized_client`** (same as the refresh token side. ADR-0046.
    ///   RFC 7009 §2.1)
    async fn try_revoke_access_token(
        &self,
        tenant: TenantContext,
        token: &str,
        now: chrono::DateTime<chrono::Utc>,
        client: &Client,
    ) -> Result<bool, RevocationError> {
        let claims = match self.access_tokens.verify_issued(tenant, token).await {
            Ok(claims) => claims,
            Err(AccessTokenRejection::Unavailable(e)) => {
                tracing::warn!(error = %e, "failed to verify access token for revocation");
                return Ok(false);
            }
            Err(_) => return Ok(false),
        };
        if claims.client_id != client.client_id {
            return Err(RevocationError::new(
                OAuthErrorCode::UnauthorizedClient,
                "the token was not issued to this client",
            ));
        }
        if claims.jti.is_empty() || self.access_tokens.is_expired(&claims) {
            return Ok(true);
        }
        let Some(expires_at) = chrono::DateTime::from_timestamp(claims.exp, 0) else {
            return Ok(false);
        };
        let revoked = RevokedAccessToken {
            jti: claims.jti,
            revoked_at: now,
            expires_at,
        };
        match self.revoked_access_tokens.revoke(&revoked).await {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke access token jti");
                Ok(false)
            }
        }
    }

    /// Looks up the client, and verifies the secret for confidential clients.
    ///
    /// Which secret to check (Basic or body) follows the registered `token_endpoint_auth_method`
    /// (consolidated in `client_authentication`. G3).
    async fn load_client(
        &self,
        tenant: TenantContext,
        credentials: &PresentedClientCredentials,
        ctx: &RequestContext,
    ) -> Result<Client, RevocationError> {
        credentials.ensure_single_method().map_err(|_| {
            RevocationError::new(
                OAuthErrorCode::InvalidRequest,
                "client credentials must be presented with a single authentication method",
            )
        })?;
        let client_id = credentials.resolve_client_id().map_err(|failure| {
            RevocationError::new(
                match failure {
                    ClientAuthFailure::ClientIdMismatch => OAuthErrorCode::InvalidRequest,
                    _ => OAuthErrorCode::InvalidClient,
                },
                "client_id is required",
            )
        })?;

        let client = self
            .clients
            .find_by_client_id(tenant.tenant_id(), &client_id)
            .await
            .map_err(|e| RevocationError::new(OAuthErrorCode::ServerError, &e.to_string()))?
            .ok_or_else(|| RevocationError::new(OAuthErrorCode::InvalidClient, "unknown client"))?;

        if !client.is_active() {
            return Err(RevocationError::new(
                OAuthErrorCode::InvalidClient,
                "client is disabled",
            ));
        }

        // Credential checking is consolidated in `client_authentication` (G3, ADR-0030).
        match self
            .client_auth
            .authenticate(tenant, &client, credentials)
            .await
        {
            // Public clients pass without authentication (RFC 7009 §2.1).
            Ok(ClientAuthOutcome::NotRequired | ClientAuthOutcome::Authenticated) => {}
            Err(ClientAuthError::Failed(_)) => {
                self.record_auth_failure(tenant, &client.client_id, ctx)
                    .await;
                return Err(RevocationError::new(
                    OAuthErrorCode::InvalidClient,
                    "client authentication failed",
                ));
            }
            Err(ClientAuthError::Internal(message)) => {
                // Internal error details are not shown to the client (outside the translation scope of `CLAUDE.md` "i18n").
                tracing::error!(error = %message, "client authentication internal error");
                return Err(RevocationError::new(
                    OAuthErrorCode::ServerError,
                    "internal server error",
                ));
            }
        }

        Ok(client)
    }

    async fn record_auth_failure(
        &self,
        tenant: TenantContext,
        client_id: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                Some(client_id),
                Some("revocation"),
                ctx,
            )
            .await;
    }
}
