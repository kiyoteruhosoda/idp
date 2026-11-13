//! Verification of access tokens (JWTs with `typ=at+jwt`) (shared by `/userinfo`, `/introspect` and `/revoke`).
//!
//! There are two levels of checks:
//!
//! 1. [`AccessTokenVerifier::verify_issued`]: **is this an access token issued by this tenant**
//!    (`typ`, `kid`, signing key, signature, `iss`). Neither the audience (`aud`) nor expiry is checked.
//!    Revocation (`/revoke`) also targets tokens with other audiences such as the admin API, so this is enough
//! 2. [`AccessTokenVerifier::verify_for_userinfo`]: in addition to 1, is it for `/userinfo`, unexpired
//!    (allowing clock skew) and not revoked. Used by `/userinfo` and `/introspect`
//!
//! The failure reason is returned as [`AccessTokenRejection`], and the caller decides how to handle it
//! (a 401, or `active: false`).

use crate::application::token::{userinfo_audience, AccessTokenClaims};
use crate::domain::clock::Clock;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::repositories::{RevokedAccessTokenRepository, SigningKeyRepository};
use crate::domain::tenant_context::TenantContext;
use jsonwebtoken::Validation;
use std::sync::Arc;

/// Why an access token is not accepted.
#[derive(Debug)]
pub enum AccessTokenRejection {
    /// Cannot be read as a JWT.
    Malformed,
    /// `typ` is not `at+jwt` (mixed up with an ID token etc.).
    NotAnAccessToken,
    /// No `kid`.
    MissingKeyId,
    /// No signing key for `kid` (another issuer, or a discarded key).
    UnknownSigningKey,
    /// Signature does not match.
    InvalidSignature,
    /// `iss` is not this tenant's issuer.
    IssuerMismatch,
    /// `aud` is not `/userinfo`.
    AudienceMismatch,
    /// Expired (beyond clock skew).
    Expired,
    /// On the revocation list.
    Revoked,
    /// Could not fetch what is needed to check (storage failure etc.).
    Unavailable(String),
}

impl AccessTokenRejection {
    /// Short reason put on the `/userinfo` 401 (a fixed string independent of the user's language).
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
    /// Base issuer. Per tenant, `<base>/<tenant_id>` is composed and `iss`/`aud` are matched strictly
    /// (ADR-0009 §6; prevents reuse of tokens issued by another tenant).
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

    /// Whether this is an access token issued by this tenant (`typ`, `kid`, signature, `iss`). Audience and expiry are not checked.
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
        // The verification algorithm is decided by **the signing key's algorithm** (RS256 / ES256). Hardcoding
        // RS256 would reject every at+jwt issued in an environment where an ES256 key is ACTIVE.
        let (decoding_key, algorithm) = jwt::decoding_key_for(&key.algorithm, &key.public_key)
            .map_err(|e| AccessTokenRejection::Unavailable(e.to_string()))?;

        // exp / aud are verified here using time from the Clock trait (to pin time in tests).
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

    /// Whether this is an unexpired, unrevoked access token for `/userinfo`.
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
        // Check the jti revocation list (F5: token revocation).
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

    /// Whether it has expired (allowing clock skew).
    pub fn is_expired(&self, claims: &AccessTokenClaims) -> bool {
        claims.exp + self.clock_skew.num_seconds() <= self.clock.now().timestamp()
    }

    fn issuer_of(&self, tenant: TenantContext) -> String {
        tenant_issuer(&self.base_issuer, tenant.tenant_id())
    }
}
