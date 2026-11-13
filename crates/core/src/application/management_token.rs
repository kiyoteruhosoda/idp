//! Access tokens for the management API (ADR-0037).
//!
//! Authorization of the API that operates assay itself (`/{tenant_id}/admin/*`) is **unified on a single access token
//! regardless of whether the actor is a person or a machine**. The admin console (web) exchanges its SSO session for a
//! management token through this service, and system clients receive one via `client_credentials` with `resource`.
//!
//! ## Why stop forwarding cookies
//!
//! Previously `/admin/*` used only the SSO session cookie forwarded by web as the credential. There was no way to call it
//! from a machine, and since cookies are ambient (the browser attaches them automatically), CSRF concerns (origin
//! checks) remained on the api side. Bearer tokens aren't ambient, so the CSRF question disappears from the api's admin surface.
//! CSRF on the browser path is closed by web with synchronizer tokens (`web::csrf`).
//!
//! ## Permissions carried by the token, and what is checked per request
//!
//! **Permissions come from the token** (`perms` claim). Re-fetching permissions on every request would make
//! putting them in the token pointless. However, **whether the actor is still usable** (user active,
//! client active) is checked every time. So a disabled admin or a stopped system client can't keep operating
//! for the token's remaining lifetime.
//!
//! `perms` is only put on tokens whose `aud` is the management API. ADR-0033's decision that permission codes
//! don't leak into tokens for other resource servers is upheld by this fixed `aud`.

use crate::application::admin_access::AdminAccessService;
use crate::application::key_service::KeyService;
use crate::application::token::{management_audience, AccessTokenClaims, SUBJECT_TYPE_CLIENT};
use crate::domain::admin_actor::AdminActor;
use crate::domain::clock::Clock;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::permission;
use crate::domain::repositories::{
    ClientRepository, RevokedAccessTokenRepository, SigningKeyRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use chrono::Duration;
use jsonwebtoken::Validation;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;

/// Result of the management API access check. Presentation only gets allowed/denied (internal reasons aren't leaked).
#[derive(Debug, PartialEq, Eq)]
pub enum ManagementAccess {
    /// Authorized. The requested management operation may proceed.
    Granted(AuthorizedPrincipal),
    /// No valid management token (not presented, tampered, expired, revoked) -> equivalent to 401.
    Unauthenticated,
    /// The token is valid but lacks the required permission -> equivalent to 403.
    Forbidden,
}

/// An authorized management actor (the minimal identity injected into Presentation handlers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPrincipal {
    /// The actor recorded in the audit log (user or client).
    pub actor: AdminActor,
    /// Display name (shown in the admin console header. `app_name` for client actors).
    pub name: Option<String>,
    /// Login identifier (`None` for client actors).
    pub preferred_username: Option<String>,
    /// Permission codes **held** by this actor as presented in the management token (the `perms` claim as-is; implications
    /// are not expanded). Authorization is already decided before reaching here, and later uses are limited to
    /// display decisions such as "what to show on screen".
    pub permission_codes: Vec<String>,
}

/// A management token issued from an SSO session.
pub struct IssuedManagementToken {
    pub access_token: String,
    pub expires_in: u64,
    /// Permission codes the actor held at issuance (used by the console to decide what to show).
    pub permission_codes: Vec<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

/// Why issuing a management token failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ManagementTokenError {
    /// No valid SSO session (not logged in, expired, or user disabled) -> equivalent to 401.
    Unauthenticated,
    Internal(String),
}

pub struct ManagementTokenService {
    admin_access: Arc<AdminAccessService>,
    keys: Arc<KeyService>,
    signing_keys: Arc<dyn SigningKeyRepository>,
    users: Arc<dyn UserRepository>,
    clients: Arc<dyn ClientRepository>,
    revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
    clock: Arc<dyn Clock>,
    base_issuer: String,
    ttl: StdDuration,
    clock_skew: Duration,
}

impl ManagementTokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admin_access: Arc<AdminAccessService>,
        keys: Arc<KeyService>,
        signing_keys: Arc<dyn SigningKeyRepository>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn ClientRepository>,
        revoked_access_tokens: Arc<dyn RevokedAccessTokenRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        ttl: StdDuration,
        clock_skew: StdDuration,
    ) -> Self {
        Self {
            admin_access,
            keys,
            signing_keys,
            users,
            clients,
            revoked_access_tokens,
            clock,
            base_issuer,
            ttl,
            clock_skew: Duration::from_std(clock_skew).expect("clock skew out of range"),
        }
    }

    /// Exchanges the SSO session for a management token (admin console path. `POST /internal/admin/token`).
    ///
    /// `Unauthenticated` if the session is invalid. If the session is valid, **a token is issued** even with zero
    /// held permissions. This lets "logged in but no permissions" be expressed as 403; falling to 403 here
    /// would leave web unable to decide to go back to the login screen.
    pub async fn issue_for_session(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
    ) -> Result<IssuedManagementToken, ManagementTokenError> {
        let grant = self
            .admin_access
            .resolve_session_grant(tenant, sso_session_id)
            .await
            .ok_or(ManagementTokenError::Unauthenticated)?;

        let access_token = self
            .sign(
                tenant,
                &grant.user_id.to_string(),
                None,
                &grant.permission_codes,
            )
            .await?;

        Ok(IssuedManagementToken {
            access_token,
            expires_in: self.ttl.as_secs(),
            permission_codes: grant.permission_codes,
            name: grant.name,
            preferred_username: grant.preferred_username,
        })
    }

    /// Verifies the management token and decides whether it satisfies the required permission codes (called from `RequirePerms`).
    ///
    /// Verification order: signature -> `typ` -> `iss` -> `aud` -> `exp` -> revocation (jti) -> actor validity -> permissions.
    /// Failure reasons are folded into two values, 401 / 403 (which stage failed isn't passed to the caller).
    pub async fn authorize(
        &self,
        tenant: TenantContext,
        bearer_token: Option<&str>,
        required_permission: &str,
    ) -> ManagementAccess {
        let principal = match self.authenticate(tenant, bearer_token).await {
            ManagementAccess::Granted(principal) => principal,
            other => return other,
        };
        if permission::satisfies(&principal.permission_codes, required_permission) {
            ManagementAccess::Granted(principal)
        } else {
            ManagementAccess::Forbidden
        }
    }

    /// Verifies the management token and returns only the actor (**permission codes aren't checked**).
    ///
    /// Used by endpoints that authorize by **the actor itself** rather than permission codes (the roster's self. ADR-0059).
    /// ⚠ Passing here alone must not allow anything ——the caller decides by looking at the actor.
    /// The result is either `Granted` or `Unauthenticated`, never `Forbidden`.
    pub async fn authenticate(
        &self,
        tenant: TenantContext,
        bearer_token: Option<&str>,
    ) -> ManagementAccess {
        let Some(token) = bearer_token.filter(|t| !t.is_empty()) else {
            return ManagementAccess::Unauthenticated;
        };
        let claims = match self.verify(tenant, token).await {
            Ok(claims) => claims,
            Err(reason) => {
                tracing::debug!(reason, "management token rejected");
                return ManagementAccess::Unauthenticated;
            }
        };

        // Whether the actor is still usable (locks out disabled admins and stopped clients).
        match self.resolve_principal(tenant, &claims).await {
            Some(principal) => ManagementAccess::Granted(principal),
            None => ManagementAccess::Unauthenticated,
        }
    }

    /// Signs a management token. `aud` is fixed to the requested tenant's management API.
    async fn sign(
        &self,
        tenant: TenantContext,
        subject: &str,
        client_id: Option<&str>,
        permission_codes: &[String],
    ) -> Result<String, ManagementTokenError> {
        let now = self.clock.now();
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        let claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: subject.to_string(),
            aud: management_audience(&issuer),
            // A user actor's management token isn't obtained via a client, so `client_id` is filled only
            // with the actor itself (when the actor is a client).
            client_id: client_id.unwrap_or_default().to_string(),
            scope: String::new(),
            exp: iat + self.ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: client_id.map(|_| SUBJECT_TYPE_CLIENT.to_string()),
            perms: Some(permission_codes.join(" ")),
            cnf: None,
        };
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| ManagementTokenError::Internal(e.to_string()))?;
        jwt::sign(
            &key.private_pem,
            &key.kid,
            "at+jwt",
            &key.algorithm,
            &claims,
        )
        .map_err(|e| ManagementTokenError::Internal(e.to_string()))
    }

    /// Verifies signature, `typ`, `iss`, `aud`, `exp` and revocation, and returns the claims.
    async fn verify(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<AccessTokenClaims, &'static str> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| "malformed token")?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err("token typ must be `at+jwt`");
        }
        let kid = header.kid.ok_or("token has no kid")?;

        let key = self
            .signing_keys
            .find_by_kid(&kid)
            .await
            .map_err(|_| "signing key lookup failed")?
            .ok_or("unknown signing key")?;
        let claims = decode_signed_claims(&key.algorithm, &key.public_key, token)?;

        let expected_issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        if claims.iss != expected_issuer {
            return Err("issuer mismatch");
        }
        // `aud` being the management API is the key. Tokens for `/userinfo` must not be carried into the management API.
        if claims.aud != management_audience(&expected_issuer) {
            return Err("audience mismatch");
        }
        let now = self.clock.now().timestamp();
        if claims.exp + self.clock_skew.num_seconds() <= now {
            return Err("token expired");
        }
        if !claims.jti.is_empty() {
            match self.revoked_access_tokens.is_revoked(&claims.jti).await {
                Ok(true) => return Err("token has been revoked"),
                Ok(false) => {}
                Err(_) => return Err("revocation lookup failed"),
            }
        }
        Ok(claims)
    }

    /// Maps the `perms` claim (space-separated) to a list of held codes.
    fn held_codes(claims: &AccessTokenClaims) -> Vec<String> {
        claims
            .perms
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// Resolves the actor from the token's `sub` and confirms it is still usable (fail-closed).
    async fn resolve_principal(
        &self,
        tenant: TenantContext,
        claims: &AccessTokenClaims,
    ) -> Option<AuthorizedPrincipal> {
        if claims.subject_is_client() {
            let client = match self
                .clients
                .find_by_client_id(tenant.tenant_id(), &claims.sub)
                .await
            {
                Ok(Some(client)) if client.is_active() => client,
                Ok(_) => return None,
                Err(e) => {
                    tracing::error!(error = %e, "failed to load client for management token");
                    return None;
                }
            };
            return Some(AuthorizedPrincipal {
                actor: AdminActor::Client {
                    id: client.id,
                    client_id: client.client_id.clone(),
                },
                name: Some(client.app_name),
                preferred_username: None,
                permission_codes: Self::held_codes(claims),
            });
        }

        let user_id = Uuid::parse_str(&claims.sub).ok()?;
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Some(AuthorizedPrincipal {
                actor: AdminActor::User(user.id),
                name: user.name,
                preferred_username: user.preferred_username,
                permission_codes: Self::held_codes(claims),
            }),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for management token");
                None
            }
        }
    }
}

/// Verifies the signature and extracts the claims (the pure part split out of `verify`).
///
/// **Verifying with the key's algorithm** is the point of this function. Signing is done by `jwt::sign` with the key's
/// algorithm (RS256 / ES256), so hard-coding one here would make **every management API return 401** the moment a key of the
/// other kind became ACTIVE —— even `/admin/signing-keys`, needed to switch keys back, would be unreachable, so
/// operations couldn't recover. It is split out from the service so this correspondence can be tested
/// per key kind.
fn decode_signed_claims(
    key_algorithm: &str,
    public_pem: &str,
    token: &str,
) -> Result<AccessTokenClaims, &'static str> {
    let (decoding_key, algorithm) =
        jwt::decoding_key_for(key_algorithm, public_pem).map_err(|_| "unusable public key")?;

    // exp / aud are verified by us with the time from the Clock trait (so tests can fix the time).
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| "signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::jwt::{generate_ec_keypair, generate_rsa_keypair};

    fn management_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://idp.example.com/t".to_string(),
            sub: "svc".to_string(),
            aud: "https://idp.example.com/t/admin".to_string(),
            client_id: "svc".to_string(),
            scope: String::new(),
            exp: 9_999_999_999,
            iat: 0,
            jti: "j".to_string(),
            sub_type: Some(SUBJECT_TYPE_CLIENT.to_string()),
            perms: Some("idp.users:read".to_string()),
            cnf: None,
        }
    }

    /// Every key kind usable for signing can be verified.
    ///
    /// `signing_keys.algorithm` has two values, `RS256` / `ES256` (DB CHECK constraint), and both can be made ACTIVE
    /// from `POST /admin/signing-keys`. If verification hard-coded one, switching to the other would take down the whole
    /// management API, and even the operation to switch keys back would be unreachable.
    #[test]
    fn every_supported_signing_algorithm_round_trips() {
        for (algorithm, (private_pem, public_pem)) in [
            ("RS256", generate_rsa_keypair().unwrap()),
            ("ES256", generate_ec_keypair().unwrap()),
        ] {
            let token = jwt::sign(
                &private_pem,
                "kid-1",
                "at+jwt",
                algorithm,
                &management_claims(),
            )
            .unwrap_or_else(|e| panic!("sign with {algorithm}: {e}"));
            let claims = decode_signed_claims(algorithm, &public_pem, &token)
                .unwrap_or_else(|e| panic!("verify {algorithm}: {e}"));
            assert_eq!(claims.perms.as_deref(), Some("idp.users:read"));
            assert!(claims.subject_is_client());
        }
    }

    /// Tokens signed with a different key don't pass (even with the same algorithm).
    #[test]
    fn a_token_signed_by_another_key_is_rejected() {
        let (private_pem, _) = generate_rsa_keypair().unwrap();
        let (_, other_public_pem) = generate_rsa_keypair().unwrap();
        let token = jwt::sign(
            &private_pem,
            "kid-1",
            "at+jwt",
            "RS256",
            &management_claims(),
        )
        .unwrap();
        assert_eq!(
            decode_signed_claims("RS256", &other_public_pem, &token).err(),
            Some("signature verification failed")
        );
    }

    /// Tokens whose `alg` disagrees with the key's algorithm don't pass
    /// (the classic attack of swapping `alg` to bypass verification is closed by the key-side algorithm).
    #[test]
    fn an_algorithm_mismatch_is_rejected() {
        let (rsa_private, _) = generate_rsa_keypair().unwrap();
        let (_, ec_public) = generate_ec_keypair().unwrap();
        let token = jwt::sign(
            &rsa_private,
            "kid-1",
            "at+jwt",
            "RS256",
            &management_claims(),
        )
        .unwrap();
        assert!(decode_signed_claims("ES256", &ec_public, &token).is_err());
    }

    #[test]
    fn the_management_audience_is_distinct_from_userinfo() {
        let issuer = "https://idp.example.com/t";
        assert_eq!(
            management_audience(issuer),
            "https://idp.example.com/t/admin"
        );
        assert_ne!(
            management_audience(issuer),
            crate::application::token::userinfo_audience(issuer)
        );
    }
}
