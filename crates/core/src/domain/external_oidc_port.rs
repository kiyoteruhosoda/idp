//! Port for talking to external OpenID Providers (DIP boundary; AP10).
//!
//! The path where assay calls an external IdP **as a client**. The implementation (reqwest +
//! jsonwebtoken) is in `infrastructure::external_oidc`. The Application layer reaches outside only
//! through this trait, so tests can verify without a network (with an implementation returning a
//! fixed ID Token).
//!
//! ID Token verification (signature, `iss`, `aud`, `exp`, `nonce`) lives in the implementation, not
//! the Application layer, because verification and JWKS fetching are inseparable (the key is chosen
//! by `kid`, so fetch and check go together). The contract is that **only claims that passed
//! verification** come out of this port.
#![allow(dead_code)]

use crate::domain::error::Result;
use crate::domain::external_idp::ExternalClaims;
use crate::domain::oidc_discovery::{DiscoveryUrl, OidcDiscoveryDocument};
use async_trait::async_trait;

/// Information needed to exchange an authorization code (assembled by the Application layer from
/// `ExternalIdentityProvider`).
pub struct ExternalTokenRequest<'a> {
    pub token_endpoint: &'a str,
    pub jwks_uri: &'a str,
    /// The external IdP's issuer. Must exactly match the ID Token's `iss`.
    pub expected_issuer: &'a str,
    pub client_id: &'a str,
    /// Decrypted client secret (`None` for a public client).
    pub client_secret: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub code: &'a str,
    /// PKCE `code_verifier` (decrypted).
    pub code_verifier: &'a str,
    /// The stored `nonce`. Must match the ID Token's `nonce`.
    pub expected_nonce: &'a str,
}

#[async_trait]
pub trait ExternalOidcClient: Send + Sync {
    /// Exchanges the authorization code for an ID Token and returns the **verified** claims.
    ///
    /// On verification failure (bad signature, `iss`/`aud`/`exp`/`nonce` mismatch) returns an error
    /// and no claims. A contract shaped so that callers cannot skip verification.
    async fn exchange_code(&self, request: ExternalTokenRequest<'_>) -> Result<ExternalClaims>;
}

/// Port that fetches an external IdP's discovery document (task #77).
///
/// The destination can only be passed as a [`DiscoveryUrl`] (a type that can only be built after
/// the issuer passed the ADR-0023 decision 5 check). The implementation follows the same manners as
/// `exchange_code` — **does not follow redirects**, has a timeout — and also caps the response size
/// (so a huge response from an admin-entered target cannot eat api memory). It returns the fetched
/// value as is; matching `issuer` and checking endpoints is done by
/// [`OidcDiscoveryDocument::verify_for`].
#[async_trait]
pub trait OidcDiscoveryClient: Send + Sync {
    async fn fetch_discovery(&self, url: &DiscoveryUrl) -> Result<OidcDiscoveryDocument>;
}
