//! RP-initiated Logout use case (F4, design spec §9 extension).
//!
//! Based on the OIDC RP-initiated Logout 1.0 spec, ends the SSO session and
//! records the `sso_session.terminated` audit event.
//! Returns the information needed for front-channel notification (rendering is done by web).
//! ⚠ Does not send back-channel logout notifications (ADR-0055). RPs are notified only when an admin
//! stops a user, and that is the job of `stop_announcement` (ADR-0053).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::repositories::{
    AuthorizationCodeRepository, ClientRepository, RefreshTokenRepository, SigningKeyRepository,
    SsoSessionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use jsonwebtoken::Validation;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Verified hints extracted from `id_token_hint` (G12. OIDC RP-Initiated Logout 1.0 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdTokenHint {
    /// `sub` of the user the RP points at as the logout target.
    pub subject: String,
    /// The RP that received the ID Token (`aud`). Used as the match target for `post_logout_redirect_uri`.
    pub client_id: String,
}

/// Result of verifying `id_token_hint`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IdTokenHintOutcome {
    /// Not specified.
    Absent,
    /// Passed verification.
    Verified(VerifiedIdTokenHint),
    /// Specified but failed verification (bad signature, wrong issuer, unknown kid, not a JWT, etc.).
    Invalid,
}

/// Outcome of an RP-initiated logout.
pub enum LogoutOutcome {
    /// Logout was performed (including when there was no target session; idempotent).
    Completed(LogoutResult),
    /// The user pointed at by `id_token_hint` differs from the user of the current session, so **nothing was done**.
    ///
    /// Presentation **must not delete the browser's SSO Cookie either**. Deleting it leaves a dangling state
    /// where "the session is alive in the DB but the browser can no longer get back to it", which ends up
    /// breaking the login state of the other user we were trying to protect.
    SubjectMismatch,
}

/// Result of an RP-initiated logout. Presentation performs front-channel notification and redirect from it.
pub struct LogoutResult {
    /// Internal ID of the logged-out user (for auditing).
    pub user_id: Option<Uuid>,
    /// Front-channel logout URIs (all clients that have a `frontchannel_logout_uri`).
    pub frontchannel_uris: Vec<String>,
    /// Verified post-logout redirect URI (`None` if not specified or verification failed).
    pub post_logout_redirect_uri: Option<String>,
}

pub struct LogoutService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clients: Arc<dyn ClientRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    signing_keys: Arc<dyn SigningKeyRepository>,
    /// Used at logout to also drop refresh tokens originating from that session (ADR-0044).
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Base issuer. The front-channel logout `iss` is composed per tenant (ADR-0009 §6).
    base_issuer: String,
}

impl LogoutService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn ClientRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        signing_keys: Arc<dyn SigningKeyRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clients,
            codes,
            signing_keys,
            refresh_tokens,
            audit,
            clock,
            base_issuer,
        }
    }

    /// Handles an RP-initiated logout.
    ///
    /// - `sso_session_id`: SSO Cookie value (plaintext). `None` is treated as already logged out.
    /// - `client_id_hint`: the `client_id` parameter (used to verify post_logout_redirect_uri).
    /// - `id_token_hint`: the ID Token the RP received (G12). Signature and issuer are verified; `aud` is
    ///   used as the match target for `post_logout_redirect_uri` and `sub` to confirm "whose logout it is".
    /// - `post_logout_redirect_uri`: redirect target specified by the RP. Only registered ones are allowed.
    #[allow(clippy::too_many_arguments)]
    pub async fn logout(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
        client_id_hint: Option<&str>,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        ctx: &RequestContext,
    ) -> LogoutOutcome {
        let now = self.clock.now();

        // 1. Verify `id_token_hint` (G12). Done before touching the session.
        let hint = self.verify_id_token_hint(tenant, id_token_hint).await;

        // 2. Identify and end the SSO session.
        let user_id = if let Some(session_id) = sso_session_id.filter(|s| !s.is_empty()) {
            let hash = crypto::sha256_hex(session_id);
            let session = match self.sso_sessions.find_by_hash(&hash).await {
                Ok(Some(s)) => s,
                _ => {
                    // Unknown session or DB error -> treat as logged out and continue.
                    return LogoutOutcome::Completed(LogoutResult {
                        user_id: None,
                        frontchannel_uris: vec![],
                        post_logout_redirect_uri: None,
                    });
                }
            };
            let uid = session.user_id;
            // `sid` is derived before deleting the row (after deletion only `session_hash` is left at hand,
            // so the derivation function takes the hash rather than the row).
            let sid = session.sid();

            // Fetch the user's sub (used to match against `id_token_hint`).
            let sub = match self.users.find_by_id(uid).await {
                Ok(Some(u)) => Some(u.sub.to_string()),
                _ => None,
            };

            // **Do not end the session unless** the `sub` of `id_token_hint` matches the currently logged-in user
            // (G12). The hint is the RP saying "I want this user logged out"; dropping another person's
            // session goes against that. There is a real path where, after someone else logs in again on a
            // shared browser, a logout request for the previous user arrives.
            // If the user row cannot be read and `sub` is unavailable, a match cannot be confirmed, so do not end it
            // (requests without a hint are ended unconditionally as before).
            if let IdTokenHintOutcome::Verified(verified) = &hint {
                if sub.as_deref() != Some(verified.subject.as_str()) {
                    self.audit
                        .record(
                            AuditEventType::SsoSessionTerminated,
                            AuditResult::Failure,
                            Some(tenant.tenant_id()),
                            Some(uid),
                            Some(&verified.client_id),
                            Some("id_token_hint_subject_mismatch"),
                            ctx,
                        )
                        .await;
                    // Do not let the Cookie be deleted either (deleting it leaves a live session only in the DB).
                    return LogoutOutcome::SubjectMismatch;
                }
            }

            // Delete the SSO session.
            if let Err(e) = self.sso_sessions.delete(&hash).await {
                tracing::warn!(error = %e, "failed to delete sso session on logout");
            }

            // Revoke unconsumed authorization codes.
            if let Err(e) = self.codes.revoke_all_active_for_user(uid, now).await {
                tracing::warn!(error = %e, "failed to revoke active auth codes on logout");
            }

            // Also revoke refresh tokens issued from that session (ADR-0044).
            //
            // Without this, even though the SSO session has ended, **tokens with the same `sid` keep being
            // accepted**, and RPs and native apps that signed in with that session can keep refreshing.
            //
            // Do not stop on failure (fail-open). We are already at the stage of building the redirect, and
            // throwing midway **leaves the user stranded with a Cookie we could not delete**.
            // Treat it the same as the two above (session deletion, code revocation).
            //
            // `sid` is the one derived before deleting the row (above), used as is.
            match self
                .refresh_tokens
                .revoke_all_for_session(uid, &sid, now)
                .await
            {
                Ok(revoked) => {
                    tracing::info!(revoked, "revoked refresh tokens on logout");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to revoke refresh tokens on logout");
                }
            }

            self.audit
                .record(
                    AuditEventType::SsoSessionTerminated,
                    AuditResult::Success,
                    Some(tenant.tenant_id()),
                    Some(uid),
                    None,
                    Some("rp_initiated_logout"),
                    ctx,
                )
                .await;

            Some(uid)
        } else {
            None
        };

        // 2. Fetch all clients of the tenant and collect front-channel logout URIs
        //    (front-channel notification and redirect verification are limited to the flow's tenant).
        let clients = match self.clients.list(tenant.tenant_id()).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list clients for logout notification");
                vec![]
            }
        };

        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        // ⚠ **If no session was ended, do not return the RP list** (task #588). While it was returned,
        //    anyone without a Cookie could see the list of the tenant's RP front-channel URIs.
        let frontchannel_uris: Vec<String> = clients
            .iter()
            .filter(|_| user_id.is_some())
            .filter_map(|c| {
                c.frontchannel_logout_uri.as_ref().map(|uri| {
                    // OpenID Connect Front-Channel Logout spec: add iss as a query param.
                    let sep = if uri.contains('?') { '&' } else { '?' };
                    let encoded_iss = percent_encoding::utf8_percent_encode(
                        &issuer,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string();
                    format!("{uri}{sep}iss={encoded_iss}")
                })
            })
            .collect();

        // 3. Verify post_logout_redirect_uri.
        //
        // The RP to match against is determined from the `client_id` parameter and the `aud` of `id_token_hint` (G12).
        // The hint has passed signature verification (= an ID Token assay actually issued to that RP), so it is
        // stronger evidence than a self-declared `client_id`. If both are present and disagree, trust neither.
        let post_logout_redirect_uri = post_logout_redirect_uri
            .filter(|uri| !uri.is_empty())
            .and_then(|uri| {
                let audience = match &hint {
                    // A hint that fails verification says nothing about "whose logout, for which RP".
                    // Redirecting to a registered URI is a response to the RP, so do not return to a party we cannot verify.
                    IdTokenHintOutcome::Invalid => return None,
                    IdTokenHintOutcome::Verified(v) => Some(v.client_id.as_str()),
                    IdTokenHintOutcome::Absent => None,
                };
                let target = match (client_id_hint.filter(|c| !c.is_empty()), audience) {
                    (Some(param), Some(aud)) if param != aud => return None,
                    (Some(param), _) => Some(param),
                    (None, Some(aud)) => Some(aud),
                    (None, None) => None,
                };
                let allowed = match target {
                    Some(cid) => clients
                        .iter()
                        .find(|c| c.client_id == cid)
                        .is_some_and(|c| c.allows_post_logout_redirect_uri(uri)),
                    // Only when the RP cannot be identified, allow it if registered on any client in the tenant
                    // (the legacy behavior; kept because some RPs send neither `client_id` nor
                    // `id_token_hint`).
                    None => clients
                        .iter()
                        .any(|c| c.allows_post_logout_redirect_uri(uri)),
                };
                allowed.then(|| uri.to_string())
            });

        let _ = user_id; // suppress unused warning
        LogoutOutcome::Completed(LogoutResult {
            user_id,
            frontchannel_uris,
            post_logout_redirect_uri,
        })
    }

    /// Verifies `id_token_hint` (G12. OIDC RP-Initiated Logout 1.0 §2).
    ///
    /// **`exp` is not checked.** The hint refers to "an ID Token previously issued in this session" and is
    /// normally expired (§2 explicitly allows this). Instead, the following are checked:
    ///
    /// - `typ` is `JWT` (ID Token) — an Access Token (`at+jwt`) is not accepted as a hint.
    /// - `kid` is one of assay's signing keys (including retired ones) and the signature is valid.
    /// - `iss` matches the composed issuer **of the requesting tenant** (so an ID Token from another tenant
    ///   cannot be brought in to log out a user of a different tenant. ADR-0009 §6).
    ///
    /// Anything failing verification is treated as `Invalid`, not collapsed into `None`. The caller needs
    /// to distinguish "not specified" from "specified but not trustworthy".
    async fn verify_id_token_hint(
        &self,
        tenant: TenantContext,
        id_token_hint: Option<&str>,
    ) -> IdTokenHintOutcome {
        let Some(hint) = id_token_hint.filter(|h| !h.is_empty()) else {
            return IdTokenHintOutcome::Absent;
        };

        let Ok(header) = jsonwebtoken::decode_header(hint) else {
            return IdTokenHintOutcome::Invalid;
        };
        // `typ` is optional (RFC 7519), but ID Tokens issued by assay always carry `JWT`.
        if header.typ.as_deref().is_some_and(|t| t != "JWT") {
            return IdTokenHintOutcome::Invalid;
        }
        let Some(kid) = header.kid else {
            return IdTokenHintOutcome::Invalid;
        };
        let key = match self.signing_keys.find_by_kid(&kid).await {
            Ok(Some(k)) => k,
            Ok(None) => return IdTokenHintOutcome::Invalid,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load signing key for id_token_hint");
                return IdTokenHintOutcome::Invalid;
            }
        };
        let Ok((decoding_key, algorithm)) = jwt::decoding_key_for(&key.algorithm, &key.public_key)
        else {
            return IdTokenHintOutcome::Invalid;
        };

        let mut validation = Validation::new(algorithm);
        // Using an expired ID Token as a hint is normal operation (see above).
        validation.validate_exp = false;
        // `aud` is the RP's client_id; here it is not verified but is **a value to extract**.
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let Ok(decoded) =
            jsonwebtoken::decode::<IdTokenHintClaims>(hint, &decoding_key, &validation)
        else {
            return IdTokenHintOutcome::Invalid;
        };
        let claims = decoded.claims;
        if claims.iss != tenant_issuer(&self.base_issuer, tenant.tenant_id()) {
            return IdTokenHintOutcome::Invalid;
        }
        if claims.sub.is_empty() || claims.aud.is_empty() {
            return IdTokenHintOutcome::Invalid;
        }

        IdTokenHintOutcome::Verified(VerifiedIdTokenHint {
            subject: claims.sub,
            client_id: claims.aud,
        })
    }
}

/// Claims read from `id_token_hint`.
///
/// Defined separately from [`crate::application::token::IdTokenClaims`] used at issuance. The hint is a
/// previously issued token and arrives with the claim layout of that time. Adding required fields would
/// make old tokens "broken" and logout would stop working.
#[derive(Debug, Deserialize)]
struct IdTokenHintClaims {
    iss: String,
    sub: String,
    aud: String,
}
