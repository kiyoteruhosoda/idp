//! Client authentication shared by the token endpoints (`/token`, `/introspect`, `/revoke`).
//!
//! The three endpoints use the same client authentication of RFC 6749 §2.3.1 (RFC 7009 §2.1 and
//! RFC 7662 §2.1 each say "the same method as the token endpoint"). Gathering the decision in one
//! place ensures no endpoint is missed when a method is added (G3's `client_secret_post`).
//!
//! This module owns **choosing which credential to check** and **the check itself**
//! ([`ClientAuthenticator`]). Only the audit record and the shape of the error response differ per endpoint,
//! so those stay in each use case (`token` / `introspection` / `revocation`).
//!
//! The check itself is gathered here too because adding to three endpoints every time a method is added always
//! misses one somewhere (adding `private_key_jwt` made it four methods. ADR-0030).

use crate::domain::client::Client;
use crate::domain::client_assertion::{
    unverified_subject, verify_client_assertion, ClientAssertionFailure,
};
use crate::domain::clock::Clock;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::ClientAssertionReplayRepository;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{ClientType, TokenEndpointAuthMethod};
use std::sync::Arc;

/// Client credentials presented by the request.
///
/// Holds both `Authorization: Basic` and the body (`client_secret_post`); which one is used is decided
/// by the client's registered method (`token_endpoint_auth_method`).
#[derive(Debug, Clone, Default)]
pub struct PresentedClientCredentials {
    /// `(client_id, client_secret)` taken from `Authorization: Basic`.
    pub basic: Option<(String, String)>,
    /// Body `client_id` (required for public clients; also used by confidential ones with `client_secret_post`).
    pub body_client_id: Option<String>,
    /// Body `client_secret` (`client_secret_post`).
    pub body_client_secret: Option<String>,
    /// Body `client_assertion` (`private_key_jwt`. RFC 7523 §2.2).
    pub client_assertion: Option<String>,
    /// Body `client_assertion_type`. Anything other than `jwt-bearer` is rejected.
    pub client_assertion_type: Option<String>,
}

/// Why client authentication failed. The string goes into the audit log's `reason` as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthFailure {
    /// Multiple authentication methods presented in one request (forbidden by RFC 6749 §2.3.1).
    MultipleAuthMethods,
    /// The `client_id` in `Authorization: Basic` differs from the body `client_id`.
    ClientIdMismatch,
    /// Cannot identify the client_id (neither Basic nor body).
    MissingClientId,
    /// The credential for the registered method was not presented.
    MissingCredentials,
    /// Presented with a method other than the registered one (e.g. a `client_secret_post` client sends Basic).
    UnsupportedAuthMethod,
    /// Registered as confidential but no secret is stored (data inconsistency).
    ClientHasNoSecret,
    /// Registered as `private_key_jwt` but no verification key is stored (data inconsistency).
    ClientHasNoJwks,
    /// The presented secret does not match the registered hash.
    InvalidClientSecret,
    /// The client assertion failed verification (details in [`ClientAssertionFailure`]).
    InvalidAssertion(ClientAssertionFailure),
    /// An assertion with the same `jti` was presented again within its validity period (ADR-0030 decision 5).
    ReplayedAssertion,
}

impl ClientAuthFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultipleAuthMethods => "multiple_auth_methods",
            Self::ClientIdMismatch => "client_id_mismatch",
            Self::MissingClientId => "missing_client_id",
            Self::MissingCredentials => "missing_credentials",
            Self::UnsupportedAuthMethod => "unsupported_auth_method",
            Self::ClientHasNoSecret => "client_has_no_secret",
            Self::ClientHasNoJwks => "client_has_no_jwks",
            Self::InvalidClientSecret => "invalid_client_secret",
            Self::InvalidAssertion(failure) => failure.as_str(),
            Self::ReplayedAssertion => "replayed_client_assertion",
        }
    }
}

impl PresentedClientCredentials {
    /// RFC 6749 §2.3.1: a client must not use more than one authentication method in a request.
    ///
    /// Accepting both and checking only one means that with a combination like "wrong secret in Basic,
    /// correct secret in body", the request alone cannot tell which one was verified.
    pub fn ensure_single_method(&self) -> Result<(), ClientAuthFailure> {
        let presented = [
            self.basic.is_some(),
            self.body_client_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            self.client_assertion
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
        ]
        .into_iter()
        .filter(|p| *p)
        .count();
        if presented > 1 {
            return Err(ClientAuthFailure::MultipleAuthMethods);
        }
        Ok(())
    }

    /// The presented client assertion (an empty string is dropped as not presented).
    pub fn assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref().filter(|s| !s.is_empty())
    }

    /// Resolves `client_id`, preferring the Basic header. An error if it differs from the body.
    ///
    /// If neither has it, use the client assertion's (**unverified**) `sub`. RFC 7521 §4.2 allows
    /// omitting `client_id` when using an assertion, and this value is the only clue.
    /// Using an unverified value here is fine because all it decides is "which client's registered key
    /// to verify with" —— if forged, the signature won't verify with that key and it fails.
    pub fn resolve_client_id(&self) -> Result<String, ClientAuthFailure> {
        let body_id = self.body_client_id.as_deref().filter(|s| !s.is_empty());
        match (&self.basic, body_id) {
            (Some((basic_id, _)), Some(body_id)) if basic_id != body_id => {
                Err(ClientAuthFailure::ClientIdMismatch)
            }
            (Some((basic_id, _)), _) => Ok(basic_id.clone()),
            (None, Some(body_id)) => Ok(body_id.to_string()),
            (None, None) => self
                .assertion()
                .and_then(unverified_subject)
                .ok_or(ClientAuthFailure::MissingClientId),
        }
    }

    /// Chooses the credential matching the client's registered method.
    ///
    /// The choice is made by the registered value (`token_endpoint_auth_method`), not by what the request
    /// sent. Allowing coexistence such as "registered as `private_key_jwt` but a secret also works" would make
    /// registering a strong method meaningless while a weak one remains (ADR-0030 decision 2).
    pub fn select<'a>(
        &'a self,
        client: &Client,
    ) -> Result<SelectedCredential<'a>, ClientAuthFailure> {
        if client.client_type == ClientType::Public {
            return Ok(SelectedCredential::NotRequired);
        }
        let post = self.body_client_secret.as_deref().filter(|s| !s.is_empty());
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::ClientSecretBasic => {
                Self::require_secret(client)?;
                match (&self.basic, post, self.assertion()) {
                    (Some((_, secret)), _, _) => Ok(SelectedCredential::Secret(secret.as_str())),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                Self::require_secret(client)?;
                match (post, &self.basic, self.assertion()) {
                    (Some(secret), _, _) => Ok(SelectedCredential::Secret(secret)),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            TokenEndpointAuthMethod::PrivateKeyJwt => {
                // A client with no stored verification key must not pass with any assertion.
                if client.jwks.is_none() {
                    return Err(ClientAuthFailure::ClientHasNoJwks);
                }
                match (self.assertion(), &self.basic, post) {
                    (Some(assertion), _, _) => Ok(SelectedCredential::Assertion {
                        assertion,
                        assertion_type: self.client_assertion_type.as_deref(),
                    }),
                    (None, None, None) => Err(ClientAuthFailure::MissingCredentials),
                    (None, _, _) => Err(ClientAuthFailure::UnsupportedAuthMethod),
                }
            }
            // Confidential but `none` (= no authentication) is registered. The registration path can't create this,
            // but reject fail-closed so a directly edited DB row doesn't pass through.
            TokenEndpointAuthMethod::None => Err(ClientAuthFailure::UnsupportedAuthMethod),
        }
    }

    fn require_secret(client: &Client) -> Result<(), ClientAuthFailure> {
        client
            .client_secret_hash
            .as_deref()
            .map(|_| ())
            .ok_or(ClientAuthFailure::ClientHasNoSecret)
    }
}

/// The credential to check, chosen from the registered method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedCredential<'a> {
    /// No authentication needed (public client = `token_endpoint_auth_method` is `none`).
    NotRequired,
    /// Shared secret. Checked against `client.client_secret_hash`.
    Secret(&'a str),
    /// Signed assertion. Verified with `client.jwks` (ADR-0030).
    Assertion {
        assertion: &'a str,
        assertion_type: Option<&'a str>,
    },
}

/// Result of client authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthOutcome {
    /// The credential check succeeded.
    Authenticated,
    /// Public client, so no authentication was needed.
    NotRequired,
}

/// Client authentication itself (checking the [`SelectedCredential`]).
///
/// Shared by the three token endpoints. Each use case only keeps the audit event recorded on failure and
/// the shape of the error returned to the client.
pub struct ClientAuthenticator {
    hasher: Arc<dyn PasswordHasher>,
    assertions: Arc<dyn ClientAssertionReplayRepository>,
    clock: Arc<dyn Clock>,
    /// Base issuer (`https://<host>`). Candidate `aud` values for assertions are composed per tenant from this.
    base_issuer: String,
}

impl ClientAuthenticator {
    pub fn new(
        hasher: Arc<dyn PasswordHasher>,
        assertions: Arc<dyn ClientAssertionReplayRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            hasher,
            assertions,
            clock,
            base_issuer,
        }
    }

    /// Checks the presented credentials.
    ///
    /// `Err(Ok(failure))` is an authentication failure (`invalid_client` to the client),
    /// `Err(Err(message))` is an internal error (equivalent to 500). Callers only audit the former.
    pub async fn authenticate(
        &self,
        tenant: TenantContext,
        client: &Client,
        credentials: &PresentedClientCredentials,
    ) -> Result<ClientAuthOutcome, ClientAuthError> {
        match credentials
            .select(client)
            .map_err(ClientAuthError::Failed)?
        {
            SelectedCredential::NotRequired => Ok(ClientAuthOutcome::NotRequired),
            SelectedCredential::Secret(secret) => {
                let hash = client
                    .client_secret_hash
                    .as_deref()
                    .ok_or(ClientAuthError::Failed(
                        ClientAuthFailure::ClientHasNoSecret,
                    ))?;
                let ok = self
                    .hasher
                    .verify(secret, hash)
                    .map_err(|e| ClientAuthError::Internal(e.to_string()))?;
                if ok {
                    Ok(ClientAuthOutcome::Authenticated)
                } else {
                    Err(ClientAuthError::Failed(
                        ClientAuthFailure::InvalidClientSecret,
                    ))
                }
            }
            SelectedCredential::Assertion {
                assertion,
                assertion_type,
            } => {
                self.authenticate_assertion(tenant, client, assertion, assertion_type)
                    .await
            }
        }
    }

    async fn authenticate_assertion(
        &self,
        tenant: TenantContext,
        client: &Client,
        assertion: &str,
        assertion_type: Option<&str>,
    ) -> Result<ClientAuthOutcome, ClientAuthError> {
        let jwks = client
            .jwks
            .as_ref()
            .ok_or(ClientAuthError::Failed(ClientAuthFailure::ClientHasNoJwks))?;
        let verified = verify_client_assertion(
            assertion_type,
            assertion,
            &client.client_id,
            jwks,
            &self.accepted_audiences(tenant),
            self.clock.now(),
        )
        .map_err(|failure| ClientAuthError::Failed(ClientAuthFailure::InvalidAssertion(failure)))?;

        // Record the `jti` only after the signature passes. In the reverse order, the table could be bloated with
        // `jti`s of assertions whose signatures fail (it would become a table writable from outside).
        // The record is kept until `replay_guard_until` (time plus clock-skew allowance), not `exp`
        // —— so there is no gap where "it was cleaned up but is still accepted".
        let unused = self
            .assertions
            .record_if_unused(
                tenant.tenant_id(),
                &client.client_id,
                &verified.jti,
                verified.replay_guard_until,
            )
            .await
            .map_err(|e| ClientAuthError::Internal(e.to_string()))?;
        if !unused {
            return Err(ClientAuthError::Failed(
                ClientAuthFailure::ReplayedAssertion,
            ));
        }
        Ok(ClientAuthOutcome::Authenticated)
    }

    /// Values accepted as an assertion's `aud` (ADR-0030 decision 6).
    ///
    /// Both the tenant issuer and the token endpoint URL are accepted. Which one is used varies by
    /// client implementation, and both include the tenant, so an assertion meant for another tenant
    /// never passes here.
    fn accepted_audiences(&self, tenant: TenantContext) -> Vec<String> {
        let issuer = crate::domain::issuer::tenant_issuer(&self.base_issuer, tenant.tenant_id());
        vec![format!("{issuer}/token"), issuer]
    }
}

/// Failure of [`ClientAuthenticator::authenticate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthError {
    /// Authentication failure. The audit log `reason` is `failure.as_str()`.
    Failed(ClientAuthFailure),
    /// Internal error (hash check, DB). Returns the equivalent of 500 to the client.
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::client_jwks::{parse_registration_jwks, ClientJwks};
    use crate::domain::tenant::TenantId;
    use crate::domain::values::ClientStatus;
    use chrono::Utc;
    use uuid::Uuid;

    fn client(client_type: ClientType, method: TokenEndpointAuthMethod) -> Client {
        Client {
            id: Uuid::nil(),
            tenant_id: TenantId::from(Uuid::nil()),
            client_id: "cid".into(),
            client_secret_hash: (client_type == ClientType::Confidential)
                .then(|| "hash".to_string()),
            client_type,
            client_status: ClientStatus::Active,
            app_name: "app".into(),
            redirect_uris: vec![],
            grant_types: vec![],
            response_types: vec![],
            scopes: vec![],
            token_endpoint_auth_method: method,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn jwks() -> ClientJwks {
        const N: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl\
                         UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre\
                         cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_\
                         7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI\
                         Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU\
                         7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";
        parse_registration_jwks(&format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"k1","n":"{N}","e":"AQAB"}}]}}"#
        ))
        .unwrap()
    }

    fn private_key_jwt_client() -> Client {
        let mut c = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::PrivateKeyJwt,
        );
        // `private_key_jwt` clients have no secret (none is issued at registration).
        c.client_secret_hash = None;
        c.jwks = Some(jwks());
        c
    }

    fn basic() -> PresentedClientCredentials {
        PresentedClientCredentials {
            basic: Some(("cid".into(), "s3cret".into())),
            ..Default::default()
        }
    }

    fn post() -> PresentedClientCredentials {
        PresentedClientCredentials {
            body_client_id: Some("cid".into()),
            body_client_secret: Some("s3cret".into()),
            ..Default::default()
        }
    }

    fn assertion(token: &str) -> PresentedClientCredentials {
        PresentedClientCredentials {
            client_assertion: Some(token.into()),
            client_assertion_type: Some(
                crate::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE.into(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn presenting_more_than_one_method_is_rejected() {
        let both = PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            body_client_secret: Some("b".into()),
            ..Default::default()
        };
        assert_eq!(
            both.ensure_single_method(),
            Err(ClientAuthFailure::MultipleAuthMethods)
        );
        // Using a secret together with an assertion is likewise forbidden (can't tell which one authenticated).
        let secret_and_assertion = PresentedClientCredentials {
            body_client_id: Some("cid".into()),
            body_client_secret: Some("b".into()),
            client_assertion: Some("a.b.c".into()),
            ..Default::default()
        };
        assert_eq!(
            secret_and_assertion.ensure_single_method(),
            Err(ClientAuthFailure::MultipleAuthMethods)
        );
        // Putting only client_id in the body is not an authentication method, so it is allowed (the public client path).
        assert!(PresentedClientCredentials {
            basic: Some(("cid".into(), "a".into())),
            body_client_id: Some("cid".into()),
            ..Default::default()
        }
        .ensure_single_method()
        .is_ok());
    }

    #[test]
    fn client_id_comes_from_basic_and_must_match_the_body() {
        assert_eq!(basic().resolve_client_id().as_deref(), Ok("cid"));
        assert_eq!(post().resolve_client_id().as_deref(), Ok("cid"));
        assert_eq!(
            PresentedClientCredentials::default().resolve_client_id(),
            Err(ClientAuthFailure::MissingClientId)
        );
        assert_eq!(
            PresentedClientCredentials {
                basic: Some(("cid".into(), "s".into())),
                body_client_id: Some("other".into()),
                ..Default::default()
            }
            .resolve_client_id(),
            Err(ClientAuthFailure::ClientIdMismatch)
        );
    }

    /// Even a request with only an assertion and no `client_id` determines the target client
    /// (RFC 7521 §4.2). The value is unverified, so it fails if the signature doesn't pass with the chosen key.
    #[test]
    fn client_id_falls_back_to_the_unverified_assertion_subject() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"cid","sub":"cid"}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(assertion(&token).resolve_client_id().as_deref(), Ok("cid"));
    }

    #[test]
    fn the_registered_method_decides_which_credential_is_checked() {
        let basic_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretBasic,
        );
        let post_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretPost,
        );

        assert_eq!(
            basic().select(&basic_client),
            Ok(SelectedCredential::Secret("s3cret"))
        );
        assert_eq!(
            post().select(&post_client),
            Ok(SelectedCredential::Secret("s3cret"))
        );

        // A method mismatch (registered as Basic but sent in body, or vice versa) is not let through.
        assert_eq!(
            post().select(&basic_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            basic().select(&post_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            PresentedClientCredentials::default().select(&post_client),
            Err(ClientAuthFailure::MissingCredentials)
        );
    }

    /// If registered as `private_key_jwt`, even a correct secret does not pass (ADR-0030 decision 2).
    /// So registering a strong method is not made meaningless by a weak one remaining.
    #[test]
    fn a_private_key_jwt_client_cannot_fall_back_to_a_secret() {
        let client = private_key_jwt_client();
        assert_eq!(
            assertion("a.b.c").select(&client),
            Ok(SelectedCredential::Assertion {
                assertion: "a.b.c",
                assertion_type: Some(crate::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE),
            })
        );
        assert_eq!(
            basic().select(&client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            post().select(&client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
        assert_eq!(
            PresentedClientCredentials::default().select(&client),
            Err(ClientAuthFailure::MissingCredentials)
        );
    }

    /// Conversely, sending an assertion to a secret-method client does not pass either.
    #[test]
    fn a_secret_client_cannot_authenticate_with_an_assertion() {
        let basic_client = client(
            ClientType::Confidential,
            TokenEndpointAuthMethod::ClientSecretBasic,
        );
        assert_eq!(
            assertion("a.b.c").select(&basic_client),
            Err(ClientAuthFailure::UnsupportedAuthMethod)
        );
    }

    /// A `private_key_jwt` client with no stored verification key passes no assertion
    /// (fail-closed so a directly edited DB row doesn't pass through).
    #[test]
    fn a_private_key_jwt_client_without_keys_is_rejected() {
        let mut client = private_key_jwt_client();
        client.jwks = None;
        assert_eq!(
            assertion("a.b.c").select(&client),
            Err(ClientAuthFailure::ClientHasNoJwks)
        );
    }

    #[test]
    fn public_clients_need_no_credentials() {
        let public = client(ClientType::Public, TokenEndpointAuthMethod::None);
        assert_eq!(
            PresentedClientCredentials::default().select(&public),
            Ok(SelectedCredential::NotRequired)
        );
        // Sending a secret to a public client does not count as authenticated (passed through as before).
        assert_eq!(post().select(&public), Ok(SelectedCredential::NotRequired));
    }
}
