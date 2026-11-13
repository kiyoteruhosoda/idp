//! AuthorizationCode aggregate (design spec §3.5).
//!
//! A single-use code issued for an authorization request as the result of a completed authentication. The DB stores
//! `code_hash = SHA-256(code)`, not the plaintext.
//!
//! # Creating and using it
//!
//! - Issued only by [`AuthorizationCode::issue`] (built from the authorization request and authentication; also generates the plaintext code)
//! - Exchange at `/token` checks "the presenting party, `redirect_uri`, PKCE" with
//!   [`AuthorizationCode::redeem`] against the code the repository consumed atomically
//!
//! A code remembers only what is needed to build tokens: to whom (`client_id`),
//! where it was returned (`redirect_uri`), what (`scope`, `nonce`), with which PKCE (`code_challenge`),
//! and who authenticated and how ([`Authentication`]).

use crate::domain::auth_session::Authentication;
use crate::domain::authorization_request::{AuthorizationRequest, PkceChallenge};
use crate::domain::crypto;
use crate::domain::pkce;
use crate::domain::tenant::TenantId;
use crate::domain::values::Scope;
use chrono::{DateTime, Duration, Utc};

/// Plaintext of a code (the value the RP brings to `/token`). It is a bearer credential, so it is not shown in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCodeValue(String);

impl AuthorizationCodeValue {
    fn generate() -> Self {
        Self(crypto::random_token(32))
    }

    /// Accepts the value presented by the RP. Empty is the same as "not having one".
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    pub fn hash(&self) -> AuthorizationCodeHash {
        AuthorizationCodeHash(crypto::sha256_hex(&self.0))
    }

    /// The plaintext returned to the RP (carried in the authorization response).
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for AuthorizationCodeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationCodeValue(<redacted>)")
    }
}

/// SHA-256 of a code. The DB primary key, and also the key of the token family starting from this code (SEC8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationCodeHash(String);

impl AuthorizationCodeHash {
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The content of the authorization the code granted (the parts of the authorization request needed for token exchange).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGrant {
    client_id: String,
    redirect_uri: String,
    scope: Vec<String>,
    /// Empty string = the authorization request had no `nonce` (the claim is omitted from the ID Token entirely. ADR-0049).
    nonce: String,
    pkce: PkceChallenge,
}

impl CodeGrant {
    fn of(request: &AuthorizationRequest) -> Self {
        Self {
            client_id: request.client_id().to_string(),
            redirect_uri: request.redirect_uri().to_string(),
            scope: request.scope().to_vec(),
            nonce: request.nonce().to_string(),
            pkce: request.pkce().clone(),
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn pkce(&self) -> &PkceChallenge {
        &self.pkce
    }

    /// Whether that scope is granted.
    pub fn includes(&self, scope: Scope) -> bool {
        self.scope.iter().any(|s| s == scope.as_str())
    }

    /// Space-separated scopes (the `scope` of the token response and access token).
    pub fn scope_string(&self) -> String {
        self.scope.join(" ")
    }
}

/// Reasons to refuse the exchange (listed in the order of checking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRedemptionRejection {
    /// The code was issued to a different client.
    IssuedToAnotherClient,
    /// `redirect_uri` does not match that of the authorization request (including when omitted).
    RedirectUriMismatch,
    /// `code_verifier` does not match `code_challenge`.
    PkceMismatch,
}

/// AuthorizationCode aggregate.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    hash: AuthorizationCodeHash,
    /// The tenant that issued the code (ADR-0009 §8. Token exchange is limited to the same tenant).
    tenant_id: TenantId,
    grant: CodeGrant,
    authentication: Authentication,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Parts for rebuilding an [`AuthorizationCode`] from persistence (in column order).
///
/// ⚠ Exists **only for the Infrastructure layer (repository implementations) and tests**.
#[derive(Debug, Clone)]
pub struct AuthorizationCodeParts {
    pub hash: AuthorizationCodeHash,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub pkce: PkceChallenge,
    pub authentication: Authentication,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthorizationCode {
    /// Issues a code for an authorization request as the result of a completed authentication. The plaintext is returned only to be returned to the RP.
    pub fn issue(
        tenant_id: TenantId,
        request: &AuthorizationRequest,
        authentication: Authentication,
        now: DateTime<Utc>,
        lifetime: Duration,
    ) -> (Self, AuthorizationCodeValue) {
        let value = AuthorizationCodeValue::generate();
        let code = Self {
            hash: value.hash(),
            tenant_id,
            grant: CodeGrant::of(request),
            authentication,
            expires_at: now + lifetime,
            used_at: None,
            created_at: now,
            updated_at: now,
        };
        (code, value)
    }

    pub fn reconstitute(parts: AuthorizationCodeParts) -> Self {
        Self {
            hash: parts.hash,
            tenant_id: parts.tenant_id,
            grant: CodeGrant {
                client_id: parts.client_id,
                redirect_uri: parts.redirect_uri,
                scope: parts.scope,
                nonce: parts.nonce,
                pkce: parts.pkce,
            },
            authentication: parts.authentication,
            expires_at: parts.expires_at,
            used_at: parts.used_at,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
        }
    }

    pub fn hash(&self) -> &AuthorizationCodeHash {
        &self.hash
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn grant(&self) -> &CodeGrant {
        &self.grant
    }

    /// The authentication that granted this code (the source of the ID Token's `sub` / `auth_time` / `sid` / `acr` / `amr`).
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn used_at(&self) -> Option<DateTime<Utc>> {
        self.used_at
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Exchange checks (RFC 6749 §4.1.3, RFC 7636 §4.6). Called after the repository has handled consumption
    /// (single use, expiry, tenant). Checks run in the order client -> `redirect_uri` -> PKCE.
    pub fn redeem(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        code_verifier: &str,
    ) -> Result<(), CodeRedemptionRejection> {
        if self.grant.client_id != client_id {
            return Err(CodeRedemptionRejection::IssuedToAnotherClient);
        }
        if redirect_uri != Some(self.grant.redirect_uri.as_str()) {
            return Err(CodeRedemptionRejection::RedirectUriMismatch);
        }
        if !pkce::verify_s256(code_verifier, self.grant.pkce.challenge()) {
            return Err(CodeRedemptionRejection::PkceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_request::test_support::request;
    use crate::domain::values::AuthenticationMethod;
    use uuid::Uuid;

    /// The pair from RFC 7636 Appendix B (a pair that passes the check, separate from the challenge in `test_support::request`).
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn issued(now: DateTime<Utc>) -> (AuthorizationCode, AuthorizationCodeValue) {
        let code = AuthorizationCode::issue(
            Uuid::now_v7().into(),
            &request("app", "https://client.example.com/cb"),
            Authentication::new(
                Uuid::now_v7(),
                now,
                Some("sid".to_string()),
                Some(vec![AuthenticationMethod::Password]),
            ),
            now,
            Duration::seconds(60),
        );
        // Replace the challenge with one that passes the check (the issuing path is used as is).
        let (code, value) = code;
        let mut parts = to_parts(&code);
        parts.pkce = PkceChallenge::reconstitute(
            CHALLENGE.to_string(),
            crate::domain::values::CodeChallengeMethod::S256,
        );
        (AuthorizationCode::reconstitute(parts), value)
    }

    fn to_parts(code: &AuthorizationCode) -> AuthorizationCodeParts {
        AuthorizationCodeParts {
            hash: code.hash.clone(),
            tenant_id: code.tenant_id,
            client_id: code.grant.client_id.clone(),
            redirect_uri: code.grant.redirect_uri.clone(),
            scope: code.grant.scope.clone(),
            nonce: code.grant.nonce.clone(),
            pkce: code.grant.pkce.clone(),
            authentication: code.authentication.clone(),
            expires_at: code.expires_at,
            used_at: code.used_at,
            created_at: code.created_at,
            updated_at: code.updated_at,
        }
    }

    #[test]
    fn an_issued_code_is_stored_only_as_its_hash_and_carries_the_request() {
        let now = Utc::now();
        let (code, value) = issued(now);
        assert_eq!(code.hash(), &value.hash());
        assert!(!format!("{value:?}").contains(&value.clone().into_string()));
        assert_eq!(code.grant().client_id(), "app");
        assert_eq!(code.grant().redirect_uri(), "https://client.example.com/cb");
        assert_eq!(code.grant().nonce(), "nonce-1");
        assert!(code.grant().includes(Scope::OpenId));
        assert!(!code.grant().includes(Scope::OfflineAccess));
        assert_eq!(code.grant().scope_string(), "openid");
        assert!(!code.is_used());
        assert!(!code.is_expired_at(now));
        assert!(code.is_expired_at(now + Duration::seconds(60)));
    }

    #[test]
    fn redeem_checks_client_then_redirect_uri_then_pkce() {
        let (code, _) = issued(Utc::now());
        let cb = Some("https://client.example.com/cb");
        assert_eq!(code.redeem("app", cb, VERIFIER), Ok(()));
        // Order: if the party differs, answer "different party" even if other items also mismatch.
        assert_eq!(
            code.redeem("other", None, "x"),
            Err(CodeRedemptionRejection::IssuedToAnotherClient)
        );
        assert_eq!(
            code.redeem("app", None, VERIFIER),
            Err(CodeRedemptionRejection::RedirectUriMismatch)
        );
        assert_eq!(
            code.redeem("app", Some("https://client.example.com/other"), VERIFIER),
            Err(CodeRedemptionRejection::RedirectUriMismatch)
        );
        assert_eq!(
            code.redeem("app", cb, "wrong-verifier-wrong-verifier-wrong-verifier-1"),
            Err(CodeRedemptionRejection::PkceMismatch)
        );
    }

    #[test]
    fn presented_values_must_not_be_empty() {
        assert!(AuthorizationCodeValue::from_presented("").is_none());
        let v = AuthorizationCodeValue::from_presented("abc").expect("present");
        assert_eq!(v.hash().as_str(), crypto::sha256_hex("abc"));
    }
}
