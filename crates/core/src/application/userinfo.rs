//! UserInfo use case (`GET /userinfo`, design spec §4.7).
//!
//! Verifies the Bearer Access Token (JWT / `typ=at+jwt`) and returns only the claims allowed by the scope.
//! `exp` is verified against the time from the `Clock` trait, allowing clock skew (±60 seconds).

use crate::application::access_token_verification::{AccessTokenRejection, AccessTokenVerifier};
use crate::application::dpop_proof_verification::{DpopProofFailure, DpopProofVerifier};
use crate::domain::issuer::tenant_issuer;
use crate::domain::repositories::UserRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::Scope;
use std::sync::Arc;
use uuid::Uuid;

/// Claims returned according to scope (design spec §4.7 "scope control").
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

/// The access token presented to `/userinfo` and how it was presented (RFC 9449 §7. ADR-0075 decision 8).
#[derive(Debug, Clone, Copy)]
pub enum PresentedAccessToken<'a> {
    /// `Authorization: Bearer <token>`.
    Bearer(&'a str),
    /// `Authorization: DPoP <token>` and the proof from the `DPoP` header (`None` if absent).
    Dpop {
        token: &'a str,
        proof: Option<&'a str>,
    },
}

#[derive(Debug)]
pub enum UserInfoError {
    /// Invalid token (signature, typ, iss, aud, exp, user state) -> 401.
    InvalidToken(&'static str),
    /// DPoP proof missing or invalid -> 401 (`WWW-Authenticate: DPoP error="invalid_dpop_proof"`).
    InvalidDpopProof(&'static str),
    /// Does not include the `openid` scope -> 403.
    InsufficientScope,
    Internal(String),
}

pub struct UserInfoService {
    users: Arc<dyn UserRepository>,
    /// Access token verification (signature, typ, iss, aud, exp, revocation. `access_token_verification`).
    access_tokens: Arc<AccessTokenVerifier>,
    /// Proof for tokens that carry `cnf.jkt` (ADR-0075 decision 8).
    dpop: Arc<DpopProofVerifier>,
    /// Base issuer. Used to build `{issuer}/userinfo`, compared with the proof's `htu`.
    base_issuer: String,
}

impl UserInfoService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        access_tokens: Arc<AccessTokenVerifier>,
        dpop: Arc<DpopProofVerifier>,
        base_issuer: String,
    ) -> Self {
        Self {
            users,
            access_tokens,
            dpop,
            base_issuer,
        }
    }

    pub async fn userinfo(
        &self,
        tenant: TenantContext,
        presented: PresentedAccessToken<'_>,
    ) -> Result<UserInfoClaims, UserInfoError> {
        let token = match presented {
            PresentedAccessToken::Bearer(token) | PresentedAccessToken::Dpop { token, .. } => token,
        };
        let claims = self
            .access_tokens
            .verify_for_userinfo(tenant, token)
            .await
            .map_err(|rejection| match rejection {
                AccessTokenRejection::Unavailable(e) => UserInfoError::Internal(e),
                other => UserInfoError::InvalidToken(other.reason()),
            })?;

        // DPoP (ADR-0075 decision 8): a bound token must be presented with `DPoP` and needs a proof from the same key.
        // Presenting an unbound token with `DPoP` is also refused (the presentation and the token disagree).
        match (claims.dpop_jkt(), presented) {
            (None, PresentedAccessToken::Bearer(_)) => {}
            (None, PresentedAccessToken::Dpop { .. }) => {
                return Err(UserInfoError::InvalidToken(
                    "the access token is not bound to a key; use the Bearer scheme",
                ));
            }
            (Some(_), PresentedAccessToken::Bearer(_)) => {
                return Err(UserInfoError::InvalidToken(
                    "the access token is bound to a key; use the DPoP scheme with a proof",
                ));
            }
            (Some(_), PresentedAccessToken::Dpop { proof: None, .. }) => {
                return Err(UserInfoError::InvalidDpopProof("a DPoP proof is required"));
            }
            (
                Some(bound),
                PresentedAccessToken::Dpop {
                    proof: Some(proof), ..
                },
            ) => {
                let endpoint = format!(
                    "{}/userinfo",
                    tenant_issuer(&self.base_issuer, tenant.tenant_id())
                );
                let verified = self
                    .dpop
                    .verify(proof, "GET", &endpoint, Some(token))
                    .await
                    .map_err(|failure| match failure {
                        DpopProofFailure::Rejected(r) => {
                            UserInfoError::InvalidDpopProof(r.reason())
                        }
                        DpopProofFailure::Unavailable(e) => UserInfoError::Internal(e),
                    })?;
                if verified.jkt != bound {
                    return Err(UserInfoError::InvalidDpopProof(
                        "the DPoP proof was made by another key",
                    ));
                }
            }
        }

        // Tokens issued via `client_credentials` have no user principal, so they cannot be used at `/userinfo`
        // (G4). `sub` is the client itself, and there are no user claims to return.
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
