//! Token issuance use case (`POST /token`, design spec §4.4, §5, §9.1).
//!
//! - `authorization_code` grant: client authentication -> atomic one-time consumption of the code ->
//!   various match checks -> PKCE S256 verification -> issue ID Token / Access Token (RS256).
//!   If the scope includes `offline_access`, a Refresh Token is issued too.
//! - `refresh_token` grant: client authentication -> Refresh Token verification -> rotation ->
//!   reuse detection -> issue new Access Token / ID Token.
//! - `client_credentials` grant (G4): client authentication -> grant permission check -> scope validation ->
//!   issue only an Access Token. It is a flow without a user, so **neither ID Token nor Refresh Token is issued**
//!   (OIDC Core defines the ID Token as "the result of end-user authentication", and it must not be issued to a principal
//!   that did not authenticate). `sub` is the client itself (`client_id`), and the `sub_type` claim makes this explicit
//!   so it is not confused with user-principal tokens.

use crate::application::application_access::{ApplicationAccessService, ApplicationGate};
use crate::application::audit::{AuditService, RequestContext};
use crate::application::client_authentication::{
    ClientAuthError, ClientAuthFailure, ClientAuthOutcome, ClientAuthenticator,
    PresentedClientCredentials,
};
use crate::application::dpop_proof_verification::{DpopProofFailure, DpopProofVerifier};
use crate::application::key_service::KeyService;
use crate::application::sign_in_history::log_history_error;
use crate::domain::application::{ApplicationAccess, BindingTarget};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authorization_code::{AuthorizationCodeValue, CodeRedemptionRejection};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::dpop::VerifiedDpopProof;
use crate::domain::error::OAuthErrorCode;
use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::pkce;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::repositories::{
    ApplicationRepository, AuthorizationCodeRepository, ClientPermissionRepository,
    ClientRepository, ProtectedResourceRepository, RefreshTokenRepository, SignInHistoryRepository,
    TenantRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength, Scope};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// ID Token claims (design spec §5.1). Optional claims are added according to scope.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    /// Included only when the authorization request had a `nonce` (OIDC Core 2 "should not be included if absent").
    /// ⚠ **Never include an empty string**: returning `""` to a party that did not send `nonce`
    /// makes strictly verifying implementations read it as "mismatch".
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub nonce: String,
    pub jti: String,
    /// SSO session identifier (OIDC Back-Channel Logout 1.0 §2.1. G5). RPs match this value against
    /// "which session the logout notification is for", and can revoke per session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// Authentication strength (ADR-0043). One of the 2 reserved words. RPs can compare it with the value requested in `acr_values`
    /// to check whether the request took effect.
    ///
    /// **`None` means "unknown", not "single factor".** It happens only when exchanging a code / refresh token
    /// issued before this claim was introduced. Do not claim by guessing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication methods actually used (RFC 8176. ADR-0043 decision 4).
    ///
    /// **Do not let it be used to judge strength.** Via an external IdP (`fed`), assay does not know what was used
    /// beyond it, so whether it was multi-factor cannot be read from the list of values. Judge by `acr`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Derives the ID Token's `acr` / `amr` from the recorded authentication methods (ADR-0043).
///
/// **If nothing is recorded, neither is included.** Reading an empty record as "authenticated with a single factor" would
/// claim something unknown. RPs can notice by the requested `acr` not coming back.
///
/// `amr` collapses duplicates (`email_otp` and `sms_otp` are both `otp` in RFC 8176).
fn authentication_claims(
    methods: Option<&Vec<AuthenticationMethod>>,
) -> (Option<String>, Option<Vec<String>>) {
    let Some(methods) = methods.filter(|m| !m.is_empty()) else {
        return (None, None);
    };
    let acr = AuthenticationStrength::from_methods(methods)
        .acr()
        .to_string();
    let mut amr: Vec<String> = Vec::with_capacity(methods.len());
    for value in methods.iter().map(|m| m.amr()) {
        if !amr.iter().any(|v| v == value) {
            amr.push(value.to_string());
        }
    }
    (Some(acr), Some(amr))
}

/// Value of the `sub_type` claim: the principal is the client itself (`client_credentials` grant. G4).
///
/// When the claim is absent, it is an end-user principal (conventional tokens). Distinguishing by **presence** rather than value
/// lets tokens issued before this claim was introduced continue to be treated as user principals.
pub const SUBJECT_TYPE_CLIENT: &str = "client";

/// Access Token claims (design spec §5.2). `aud` is fixed to `/userinfo`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// Principal kind (G4). Only tokens issued via `client_credentials` have
    /// [`SUBJECT_TYPE_CLIENT`]. Omitted = end-user principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_type: Option<String>,
    /// Permission codes for assay's own admin API (space-separated. ADR-0037).
    ///
    /// **Included only in tokens whose `aud` is [`management_audience`].** Permission codes are for protecting assay's
    /// API, not other resource servers' permission systems (ADR-0033). Fixing `aud` to
    /// the admin API removes any path for permission codes to flow into tokens for external apps.
    ///
    /// It is separated from the OIDC `scope` for the same reason. `scope` is a value used to control ID claims, and
    /// RPs may depend on its content. Mixing them would leak admin permissions into RPs' authorization decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perms: Option<String>,
    /// The key bound via DPoP (`cnf.jkt` of RFC 9449 §6.1. ADR-0075). A token with it can only be used together with
    /// a proof from that key. Omitted = not bound (Bearer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<KeyConfirmation>,
}

/// The access token's `cnf` (confirmation method of RFC 7800). assay only puts DPoP's `jkt` in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyConfirmation {
    /// The key's JWK Thumbprint (RFC 7638. base64url of SHA-256).
    pub jkt: String,
}

impl AccessTokenClaims {
    /// Fingerprint of the DPoP-bound key (`cnf.jkt`). A Bearer token if absent.
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.cnf.as_ref().map(|c| c.jkt.as_str())
    }

    /// Whether the principal is the client itself (whether the token was issued via `client_credentials`).
    pub fn subject_is_client(&self) -> bool {
        self.sub_type.as_deref() == Some(SUBJECT_TYPE_CLIENT)
    }
}

/// Builds the `aud` of an Access Token for `/userinfo` (issuer without trailing slash).
pub fn userinfo_audience(issuer: &str) -> String {
    format!("{issuer}/userinfo")
}

/// Builds the `aud` of an Access Token for assay's own admin API (ADR-0037).
///
/// The key point is making it a different value from the one for `/userinfo`. With the same `aud`, an RP could carry a token
/// received at user sign-in straight into the admin API (even though it would not pass with empty `perms`,
/// the premise "the audience matches" should not be shared with the admin side).
pub fn management_audience(issuer: &str) -> String {
    format!("{issuer}/admin")
}

#[derive(Debug, Default)]
pub struct TokenCommand {
    pub grant_type: Option<String>,
    /// For the `authorization_code` grant only.
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    /// The presented client credentials (`Authorization: Basic` / body `client_id`, `client_secret`).
    pub credentials: PresentedClientCredentials,
    /// For the `refresh_token` grant only.
    pub refresh_token: Option<String>,
    /// Scopes requested in the `client_credentials` grant (space-separated). When omitted, the default set is derived from the client's
    /// registered scopes (G4).
    pub scope: Option<String>,
    /// The requested resource indicator (RFC 8707 `resource`. ADR-0037).
    ///
    /// System clients calling assay's admin API specify `{issuer}/admin` to
    /// receive an admin token. When omitted, a token for `/userinfo` is issued as before.
    /// **The caller is made to write which one it wants** because implicitly switching what is issued based on the client's registered
    /// permissions would change the token's `aud` the moment a single permission is granted.
    pub resource: Option<String>,
    /// The proof from the `DPoP` header (RFC 9449. ADR-0075). Looked at only for `authorization_code` and `refresh_token`.
    pub dpop_proof: Option<String>,
}

/// Errors of the token endpoint (returned in RFC 6749 §5.2 format).
#[derive(Debug)]
pub struct TokenError {
    pub code: OAuthErrorCode,
    pub description: String,
}

impl TokenError {
    fn new(code: OAuthErrorCode, description: &str) -> Self {
        Self {
            code,
            description: description.to_string(),
        }
    }
}

pub struct IssuedTokens {
    pub access_token: String,
    /// Issued only for grants that authenticated a user (`authorization_code` / `refresh_token`).
    /// `None` for `client_credentials` since there is no user (G4).
    pub id_token: Option<String>,
    pub expires_in: u64,
    pub scope: String,
    /// Issued only when the `offline_access` scope is included.
    pub refresh_token: Option<String>,
    /// Whether it was bound to a key via DPoP (`token_type` is returned as `DPoP`. RFC 9449 §5).
    pub bound_to_key: bool,
}

pub struct TokenService {
    clients: Arc<dyn ClientRepository>,
    users: Arc<dyn UserRepository>,
    /// Held to look at the state of the user's **home** tenant (ADR-0009 §8). Resolution of the requested tenant
    /// is already done by presentation (`TenantResolver`), so only the home tenant is looked at here.
    tenants: Arc<dyn TenantRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    /// Admin API permission codes held by system clients (ADR-0037). Looked up only for `client_credentials`
    /// with the admin API specified in `resource`.
    client_permissions: Arc<dyn ClientPermissionRepository>,
    /// Registered audiences (values placed in `aud`. ADR-0042). Looked up only for `client_credentials`
    /// with something other than assay itself specified in `resource`.
    resources: Arc<dyn ProtectedResourceRepository>,
    /// Apps and their identities/assignments (ADR-0059). Looks up whether an admin API token may be issued to a
    /// service account without permission codes (= whether it is some app's identity), and whether an audience token may be issued
    /// (= whether it is assigned to the audience's app).
    applications: Arc<dyn ApplicationRepository>,
    /// Whether the user may use the app (ADR-0054). Rechecked not only when issuing a code but **on every refresh**
    /// (task #582), so that removed people or stopped apps do not keep getting new tokens
    /// with the refresh tokens they hold.
    application_access: Arc<ApplicationAccessService>,
    keys: Arc<KeyService>,
    /// Client authentication (secret matching, assertion verification). Per-method branching is
    /// consolidated in `client_authentication` (ADR-0030).
    client_auth: Arc<ClientAuthenticator>,
    /// DPoP proofs (ADR-0075). Used only for `authorization_code` and `refresh_token`.
    dpop: Arc<DpopProofVerifier>,
    audit: Arc<AuditService>,
    /// Sign-in history the user sees (task #879). Which apps tokens were issued to, and how refresh was used.
    sign_in_history: Arc<dyn SignInHistoryRepository>,
    clock: Arc<dyn Clock>,
    /// Base issuer (`https://<host>`). `iss` is composed per tenant as `<base>/<tenant_id>`
    /// (ADR-0009 §6. `domain::issuer::tenant_issuer`).
    base_issuer: String,
    access_token_ttl: std::time::Duration,
    /// Lifetime of access tokens for the admin API (`resource={issuer}/admin`) (ADR-0037).
    /// Kept shorter than normal access tokens.
    management_token_ttl: std::time::Duration,
    id_token_ttl: std::time::Duration,
    refresh_token_ttl: std::time::Duration,
}

impl TokenService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        users: Arc<dyn UserRepository>,
        tenants: Arc<dyn TenantRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        resources: Arc<dyn ProtectedResourceRepository>,
        applications: Arc<dyn ApplicationRepository>,
        application_access: Arc<ApplicationAccessService>,
        keys: Arc<KeyService>,
        client_auth: Arc<ClientAuthenticator>,
        dpop: Arc<DpopProofVerifier>,
        audit: Arc<AuditService>,
        sign_in_history: Arc<dyn SignInHistoryRepository>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        access_token_ttl: std::time::Duration,
        management_token_ttl: std::time::Duration,
        id_token_ttl: std::time::Duration,
        refresh_token_ttl: std::time::Duration,
    ) -> Self {
        Self {
            clients,
            users,
            tenants,
            codes,
            refresh_tokens,
            client_permissions,
            resources,
            applications,
            application_access,
            keys,
            client_auth,
            dpop,
            audit,
            sign_in_history,
            clock,
            base_issuer,
            access_token_ttl,
            management_token_ttl,
            id_token_ttl,
            refresh_token_ttl,
        }
    }

    /// Sign-in history: a used-up refresh token came again (task #879).
    async fn note_refresh_reuse(
        &self,
        stored: &RefreshToken,
        client_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        if let Some(sid) = stored.sid.as_deref() {
            log_history_error(
                self.sign_in_history
                    .record_refresh_reuse(sid, client_id, now)
                    .await,
                "refresh reuse",
            );
        }
    }

    pub async fn exchange(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        // Only `client_credentials` interprets `resource` (RFC 8707) (ADR-0037).
        // Grants that authenticated a user never issue admin tokens, so silently ignoring it would cause
        // a failure whose cause is invisible from the requesting side: "asked for an admin token, got one for `/userinfo`, and got 401 at the admin API".
        // Refuse at request time.
        if cmd
            .resource
            .as_deref()
            .is_some_and(|r| !r.trim().is_empty())
            && cmd.grant_type.as_deref() != Some("client_credentials")
        {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidTarget,
                "the `resource` parameter is only supported for the client_credentials grant",
            ));
        }
        match cmd.grant_type.as_deref() {
            Some("authorization_code") => {
                let proof = self.verify_dpop_proof(tenant, &cmd).await?;
                self.exchange_code(tenant, cmd, proof, ctx).await
            }
            Some("refresh_token") => {
                let proof = self.verify_dpop_proof(tenant, &cmd).await?;
                self.exchange_refresh_token(tenant, cmd, proof, ctx).await
            }
            Some("client_credentials") => self.issue_client_credentials(tenant, cmd, ctx).await,
            _ => Err(TokenError::new(
                OAuthErrorCode::UnsupportedGrantType,
                "grant_type must be `authorization_code`, `refresh_token` or `client_credentials`",
            )),
        }
    }

    /// Verifies the proof in the `DPoP` header (ADR-0075). `None` if absent (issued as Bearer, as before).
    ///
    /// Looked at before processing the grant. A broken proof (e.g. device clock skew) alone should not use up the authorization
    /// code: the app can rebuild and resend it.
    async fn verify_dpop_proof(
        &self,
        tenant: TenantContext,
        cmd: &TokenCommand,
    ) -> Result<Option<VerifiedDpopProof>, TokenError> {
        let Some(proof) = cmd.dpop_proof.as_deref() else {
            return Ok(None);
        };
        let token_endpoint = format!(
            "{}/token",
            tenant_issuer(&self.base_issuer, tenant.tenant_id())
        );
        match self.dpop.verify(proof, "POST", &token_endpoint, None).await {
            Ok(verified) => Ok(Some(verified)),
            Err(DpopProofFailure::Rejected(rejection)) => Err(TokenError::new(
                OAuthErrorCode::InvalidDpopProof,
                rejection.reason(),
            )),
            Err(DpopProofFailure::Unavailable(e)) => Err(internal(&e)),
        }
    }

    /// Processing of the `authorization_code` grant.
    async fn exchange_code(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        proof: Option<VerifiedDpopProof>,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. Determine client_id (Basic header takes precedence).
        let client_id = resolve_client_id(&cmd)?;

        // 2. Client existence, status and authentication (resolves only clients belonging to the flow's tenant).
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 3. Format validation of code_verifier (RFC 7636 §4.1).
        let Some(code_verifier) = cmd.code_verifier.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier is required",
            ));
        };
        if !pkce::is_valid_code_verifier(code_verifier) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code_verifier must be 43-128 characters of [A-Za-z0-9-._~]",
            ));
        }

        // 4. Atomic one-time consumption of the code.
        let Some(code) = cmd
            .code
            .as_deref()
            .and_then(AuthorizationCodeValue::from_presented)
        else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "code is required",
            ));
        };
        let now = self.clock.now();
        // The code hash is used for both consumption and the family key (`grant_hash`. SEC8), so it is computed only once.
        let code_hash = code.hash();
        let consumed = match self.codes.consume(tenant_id, &code_hash, now).await {
            Ok(c) => c,
            Err(e) => return Err(internal(&e)),
        };
        let Some(auth_code) = consumed else {
            // Distinguish why it could not be consumed (SEC8). "Expired" or "never existed" differ in meaning from
            // **a real reuse** (presenting a code already exchanged once again):
            // the former indicates RP implementation mistakes or delays, the latter a leaked code. Collapsing them into one string
            // would make attacks impossible to pick up from the audit.
            let used_code = match self.codes.find_used(tenant_id, &code_hash).await {
                Ok(v) => v,
                Err(e) => return Err(internal(&e)),
            };
            let (reason, used_code) = match used_code {
                Some(used) => {
                    // A real reuse. Revoke the token family issued by the first exchange.
                    // Since we cannot tell whether the attacker or the legitimate RP exchanged first, stopping both and
                    // forcing re-authentication is what RFC 6819 §5.2.1.1 requires.
                    let revoked = match self
                        .refresh_tokens
                        .revoke_family(tenant_id, code_hash.as_str(), now)
                        .await
                    {
                        Ok(n) => n,
                        Err(e) => return Err(internal(&e)),
                    };
                    (
                        format!("authorization code replayed; revoked {revoked} refresh token(s)"),
                        Some(used),
                    )
                }
                None => ("authorization code not found or expired".to_string(), None),
            };
            self.audit
                .record(
                    AuditEventType::AuthorizationCodeReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
                    used_code.map(|c| c.authentication().user_id()),
                    Some(&client_id),
                    Some(&reason),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "authorization code is invalid, expired, or already used",
            ));
        };
        self.audit
            .record(
                AuditEventType::AuthorizationCodeUsed,
                AuditResult::Success,
                Some(tenant_id),
                Some(auth_code.authentication().user_id()),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 5-6. Check the presenting party, redirect_uri, and PKCE S256 (the aggregate checks them in order).
        if let Err(rejection) =
            auth_code.redeem(&client_id, cmd.redirect_uri.as_deref(), code_verifier)
        {
            let description = match rejection {
                CodeRedemptionRejection::IssuedToAnotherClient => {
                    "authorization code was issued to another client"
                }
                CodeRedemptionRejection::RedirectUriMismatch => {
                    "redirect_uri does not match the authorization request"
                }
                CodeRedemptionRejection::PkceMismatch => "PKCE verification failed",
            };
            return Err(TokenError::new(OAuthErrorCode::InvalidGrant, description));
        }
        let grant = auth_code.grant();
        let authentication = auth_code.authentication();

        // 7. Check the user's status.
        let user = self.load_active_user(authentication.user_id(), ctx).await?;

        // 8. Issue tokens (the scope carries over AuthorizationCodes.scope).
        let has_offline = grant.includes(Scope::OfflineAccess);
        let has = |s: Scope| grant.includes(s);
        let scope_str = grant.scope_string();
        let iat = now.timestamp();
        // `iss` is composed per tenant (ADR-0009 §6). Bound to the issuing tenant (= the flow's tenant).
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let (code_acr, code_amr) =
            authentication_claims(authentication.methods().map(<[_]>::to_vec).as_ref());
        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            auth_time: authentication.auth_time().timestamp(),
            nonce: grant.nonce().to_string(),
            jti: Uuid::new_v4().to_string(),
            sid: authentication.sso_sid().map(str::to_string),
            acr: code_acr,
            amr: code_amr,
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: None,
            // User sign-in tokens are not for the admin API (ADR-0037).
            perms: None,
            // If a proof is attached, bind to that key (ADR-0075 decision 1).
            cnf: proof
                .as_ref()
                .map(|p| KeyConfirmation { jkt: p.jkt.clone() }),
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 9. Issue a Refresh Token (only with the offline_access scope).
        let refresh_token_plain = if has_offline {
            let plain = crypto::random_token(32);
            let rt = RefreshToken {
                token_hash: crypto::sha256_hex(&plain),
                parent_hash: None,
                // The root of the token family derived from this grant (authorization code) (SEC8).
                // It is carried over to descendants by rotation, and can be revoked all at once with the same key from
                // reuse detection of either code or refresh.
                grant_hash: Some(code_hash.as_str().to_string()),
                tenant_id,
                user_id: authentication.user_id(),
                client_id: client_id.clone(),
                scope: grant.scope().to_vec(),
                // The ID Token's `sid` (G5). Carried over by rotation too, pointing to the same session as the logout_token.
                sid: authentication.sso_sid().map(str::to_string),
                // The ID Token's `acr` / `amr` (ADR-0043). Refresh does not redo authentication, so
                // the claimed strength does not change either. Carried over by rotation, like `sid`.
                authentication_methods: authentication.methods().map(<[_]>::to_vec),
                // The ID Token's `auth_time`. Refresh keeps claiming "the time of the last sign-in" (task #584).
                auth_time: Some(authentication.auth_time()),
                // Bind to the same key as the access token (ADR-0075 decision 1).
                dpop_jkt: proof.as_ref().map(|p| p.jkt.clone()),
                expires_at: now + chrono::Duration::from_std(self.refresh_token_ttl).unwrap(),
                revoked_at: None,
                created_at: now,
            };
            if let Err(e) = self.refresh_tokens.create(&rt).await {
                return Err(internal(&e));
            }
            self.audit
                .record(
                    AuditEventType::RefreshTokenIssued,
                    AuditResult::Success,
                    Some(tenant_id),
                    Some(authentication.user_id()),
                    Some(&client_id),
                    None,
                    ctx,
                )
                .await;
            Some(plain)
        } else {
            None
        };

        // Sign-in history: entered this app with this sign-in (task #879).
        if let Some(sid) = authentication.sso_sid() {
            log_history_error(
                self.sign_in_history
                    .record_app_issue(
                        authentication.user_id(),
                        tenant_id,
                        sid,
                        &client_id,
                        now,
                        has_offline,
                    )
                    .await,
                "app issue",
            );
        }

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(authentication.user_id()),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: Some(id_token),
            expires_in: self.access_token_ttl.as_secs(),
            scope: scope_str,
            refresh_token: refresh_token_plain,
            bound_to_key: proof.is_some(),
        })
    }

    /// Processing of the `refresh_token` grant (rotation + reuse detection).
    async fn exchange_refresh_token(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        proof: Option<VerifiedDpopProof>,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. Determine and authenticate client_id.
        let client_id = resolve_client_id(&cmd)?;
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 2. Extract the refresh_token parameter.
        let Some(rt_plain) = cmd.refresh_token.as_deref().filter(|v| !v.is_empty()) else {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidRequest,
                "refresh_token is required",
            ));
        };
        let rt_hash = crypto::sha256_hex(rt_plain);
        let now = self.clock.now();

        // 3. Token lookup (including the issuing tenant match. Tokens issued by other tenants are not resolved).
        let stored = match self.refresh_tokens.find_by_hash(tenant_id, &rt_hash).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "refresh_token not found",
                ));
            }
            Err(e) => return Err(internal(&e)),
        };

        // 4. Check client_id match.
        if stored.client_id != client_id {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token was issued to another client",
            ));
        }

        // 4b. DPoP binding (ADR-0075 decision 7). ⚠ **Check before reuse detection**: even if someone without the key
        //     presents a stolen token, do not let them revoke the whole family and stop the owner's app.
        //     If an unbound token comes with a proof, bind to that key from the new token on
        //     (so apps updated to a DPoP-enabled version can migrate without signing in again).
        let bound_jkt = match (stored.dpop_jkt.as_deref(), proof.as_ref()) {
            (Some(_), None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidDpopProof,
                    "this refresh_token is bound to a key; a DPoP proof is required",
                ));
            }
            (Some(bound), Some(p)) if bound != p.jkt => {
                self.audit
                    .record(
                        AuditEventType::RefreshTokenKeyMismatch,
                        AuditResult::Failure,
                        Some(tenant_id),
                        Some(stored.user_id),
                        Some(&client_id),
                        Some("refresh token presented with a DPoP proof of another key; nothing revoked"),
                        ctx,
                    )
                    .await;
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "refresh_token is bound to another key",
                ));
            }
            (Some(bound), Some(_)) => Some(bound.to_string()),
            (None, Some(p)) => Some(p.jkt.clone()),
            (None, None) => None,
        };

        // 5. Reuse detection: if a new token was already issued from the same token, revoke the whole chain.
        let already_rotated = match self.refresh_tokens.exists_by_parent_hash(&rt_hash).await {
            Ok(v) => v,
            Err(e) => return Err(internal(&e)),
        };
        if already_rotated {
            // This token was already rotated -> possible reuse attack.
            // Revoking only the presented token would let **descendants** rotated from it survive
            // (if the attacker exchanged first, the attacker's side remains). Revoke the whole family derived from the same grant,
            // and make the legitimate RP re-authenticate too (SEC8. RFC 6819 §5.2.2.3 / OAuth 2.1).
            // If revocation fails, return 500 and fail (previously this was swallowed as best-effort, but
            // the state "reuse detected but nothing revoked" must not be returned as success).
            let revoked = match self
                .refresh_tokens
                .revoke_family(tenant_id, &stored.family_hash(), now)
                .await
            {
                Ok(n) => n,
                Err(e) => return Err(internal(&e)),
            };
            self.audit
                .record(
                    AuditEventType::RefreshTokenReuseDetected,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(stored.user_id),
                    Some(&client_id),
                    Some(&format!(
                        "refresh token already rotated; revoked {revoked} token(s) in the grant family"
                    )),
                    ctx,
                )
                .await;
            self.note_refresh_reuse(&stored, &client_id, now).await;
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token has already been used",
            ));
        }

        // 6. Validity check (revoked, expired).
        if !stored.is_valid_at(now) {
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "refresh_token is revoked or expired",
            ));
        }

        // 7. Check the user's status.
        let user = self.load_active_user(stored.user_id, ctx).await?;

        // 7b. May this app still be used (ADR-0054. task #582)? After being unassigned or after the app was
        //     stopped, new tokens kept being issued until expiry with the refresh tokens held.
        //     When refusing, stop the tokens issued under that permission along with the family (the next attempt gets the same answer).
        //     During staged rollout (`record_only`) `check` lets it through, giving the same answer as code issuance.
        if let ApplicationGate::Denied { .. } = self
            .application_access
            .check(tenant_id, &client_id, stored.user_id, ctx)
            .await
        {
            if let Err(e) = self
                .refresh_tokens
                .revoke_family(tenant_id, &stored.family_hash(), now)
                .await
            {
                return Err(internal(&e));
            }
            return Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "the user may no longer use this application",
            ));
        }

        // 8. Revoke the old token (rotation). ⚠ **Only the side that revoked it continues** (task #586).
        //    If 2 requests come concurrently with the same token, both pass the reuse detection above (whether a child exists). If the revocation count
        //    is 0, the other one used it first: stop the whole family as reuse (even if a stolen token races the legitimate
        //    RP, do not let it create a parallel live chain).
        match self.refresh_tokens.revoke(&rt_hash, now).await {
            Ok(1..) => {}
            Ok(0) => {
                let revoked = match self
                    .refresh_tokens
                    .revoke_family(tenant_id, &stored.family_hash(), now)
                    .await
                {
                    Ok(n) => n,
                    Err(e) => return Err(internal(&e)),
                };
                self.audit
                    .record(
                        AuditEventType::RefreshTokenReuseDetected,
                        AuditResult::Failure,
                        Some(tenant_id),
                        Some(stored.user_id),
                        Some(&client_id),
                        Some(&format!(
                            "refresh token was rotated concurrently; revoked {revoked} token(s) in the grant family"
                        )),
                        ctx,
                    )
                    .await;
                self.note_refresh_reuse(&stored, &client_id, now).await;
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "refresh_token has already been used",
                ));
            }
            Err(e) => return Err(internal(&e)),
        }

        // 9. Issue new tokens.
        let has = |s: Scope| stored.scope.iter().any(|v| v == s.as_str());
        let scope_str = stored.scope.join(" ");
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);

        let (refreshed_acr, refreshed_amr) =
            authentication_claims(stored.authentication_methods.as_ref());
        let id_claims = IdTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: client_id.clone(),
            exp: iat + self.id_token_ttl.as_secs() as i64,
            iat,
            // Authentication was not redone, so the time of the original sign-in is kept (task #584). Using "now" would let
            // RPs' "re-authenticate within N minutes" imposed via `auth_time` be bypassed just by repeating refreshes.
            auth_time: stored.auth_time_or_issued().timestamp(),
            nonce: String::new(), // nonce is not needed in the refresh grant
            jti: Uuid::new_v4().to_string(),
            // Keeps pointing to the session established by the original authorization (the value carried over by rotation. G5).
            sid: stored.sid.clone(),
            // Authentication was not redone, so the strength claimed by the original authorization is carried over as is.
            acr: refreshed_acr,
            amr: refreshed_amr,
            email: has(Scope::Email).then(|| user.email.clone()),
            email_verified: has(Scope::Email).then_some(user.email_verified),
            preferred_username: has(Scope::Profile)
                .then(|| user.preferred_username.clone())
                .flatten(),
            name: has(Scope::Profile).then(|| user.name.clone()).flatten(),
        };
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            sub: user.sub.to_string(),
            aud: userinfo_audience(&issuer),
            client_id: client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + self.access_token_ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: None,
            // User sign-in tokens are not for the admin API (ADR-0037).
            perms: None,
            // For a bound refresh token, the same key; for an unbound one with a proof attached,
            // that key (decision 7. Checked above).
            cnf: bound_jkt.clone().map(|jkt| KeyConfirmation { jkt }),
        };
        let id_token = self.sign_id_token(&id_claims).await?;
        let access_token = self.sign_access_token(&access_claims).await?;

        // 10. Issue a new Refresh Token (rotation).
        let new_rt_plain = crypto::random_token(32);
        let new_rt = RefreshToken {
            token_hash: crypto::sha256_hex(&new_rt_plain),
            parent_hash: Some(rt_hash.clone()),
            // Carry over the family identifier (SEC8). For pre-migration rows (`grant_hash` is NULL),
            // the hash of the presented token becomes the root of the new family.
            grant_hash: Some(stored.family_hash()),
            tenant_id,
            user_id: stored.user_id,
            client_id: client_id.clone(),
            scope: stored.scope.clone(),
            sid: stored.sid.clone(),
            authentication_methods: stored.authentication_methods.clone(),
            auth_time: Some(stored.auth_time_or_issued()),
            dpop_jkt: bound_jkt.clone(),
            expires_at: stored.expires_at, // TTL is carried over (not slid)
            revoked_at: None,
            created_at: now,
        };
        if let Err(e) = self.refresh_tokens.create(&new_rt).await {
            return Err(internal(&e));
        }

        // Sign-in history: record the party that sent the refresh (for an app's server, that server) (task #879).
        if let Some(sid) = stored.sid.as_deref() {
            log_history_error(
                self.sign_in_history
                    .record_refresh_use(
                        sid,
                        &client_id,
                        now,
                        ctx.ip_address.as_deref(),
                        ctx.user_agent.as_deref(),
                    )
                    .await,
                "refresh use",
            );
        }
        self.audit
            .record(
                AuditEventType::RefreshTokenUsed,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::RefreshTokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(stored.user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: Some(id_token),
            expires_in: self.access_token_ttl.as_secs(),
            scope: scope_str,
            refresh_token: Some(new_rt_plain),
            bound_to_key: bound_jkt.is_some(),
        })
    }

    /// Processing of the `client_credentials` grant (G4. RFC 6749 §4.4).
    ///
    /// It is a flow without a user, so only an Access Token is issued, with neither ID Token nor Refresh Token.
    /// `sub` is the client itself, and `sub_type` makes it distinguishable from user-principal tokens
    /// (`/userinfo` rejects this token, and `/introspect` looks at the client's status).
    async fn issue_client_credentials(
        &self,
        tenant: TenantContext,
        cmd: TokenCommand,
        ctx: &RequestContext,
    ) -> Result<IssuedTokens, TokenError> {
        let tenant_id = tenant.tenant_id();
        // 1. Client existence, status and authentication. `authenticate_client` lets public clients through, so
        //    here the grant permission check (`allows_client_credentials`) also enforces confidential.
        let client_id = resolve_client_id(&cmd)?;
        let client = self.load_active_client(tenant, &client_id, ctx).await?;
        self.authenticate_client(tenant, &client, &cmd, ctx).await?;

        // 2. Check grant permission. Only confidential clients that registered `client_credentials`.
        if !client.allows_client_credentials() {
            self.audit
                .record(
                    AuditEventType::ClientAuthenticationFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    None,
                    Some(&client_id),
                    Some("client_credentials_not_allowed"),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::UnauthorizedClient,
                "client is not allowed to use the client_credentials grant",
            ));
        }

        // 3. Determine and validate the scope. When omitted, the default set is derived from the client's registered scopes.
        let scopes = resolve_client_credentials_scopes(&client, cmd.scope.as_deref())?;
        let scope_str = scopes.join(" ");

        // 4. The app for which this service account is the identity (ADR-0059 decision 1).
        //    ⚠ **Stopping an app also stops the service account that is its identity** (ADR-0060). So that a stopped app's
        //    server does not keep hitting other apps' APIs or assay under its own name.
        //    ⚠ However, **an admin token for reading its own directory (self) is still issued.** The directory is the endpoint that answers a stopped app
        //    "everyone `blocked`"; blocking it would keep RPs from learning about the stop through periodic reconciliation.
        let own_application = self
            .applications
            .find_by_binding_target(
                tenant_id,
                BindingTarget::ServiceAccount {
                    client_row_id: client.id,
                },
            )
            .await
            .map_err(|e| internal(&e))?;
        let own_application_disabled = own_application
            .as_ref()
            .is_some_and(|application| !application.is_active());

        // 5. Determine the destination (`resource`) (RFC 8707. ADR-0037 / ADR-0042). Only when assay's own admin API
        //    is requested is an admin token issued with the client's permission codes in `perms`.
        //    Otherwise the registered audiences (`resources`) are looked up, and if allowed it goes into `aud`.
        //    If neither, `invalid_target`: **tokens are not issued to destinations this authorization server does not know**.
        let now = self.clock.now();
        let iat = now.timestamp();
        let issuer = tenant_issuer(&self.base_issuer, tenant_id);
        let management_aud = management_audience(&issuer);
        // Admin tokens are shorter-lived than normal access tokens (ADR-0037 decision 2). `perms` is read
        // from the token, so this lifetime is the upper bound of "from revoking a permission until it actually takes effect".
        let requested_resource = cmd.resource.as_deref().map(str::trim);
        if own_application_disabled && requested_resource != Some(management_aud.as_str()) {
            self.audit
                .record(
                    AuditEventType::ClientAuthenticationFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    None,
                    Some(&client_id),
                    Some("own_application_disabled"),
                    ctx,
                )
                .await;
            return Err(TokenError::new(
                OAuthErrorCode::UnauthorizedClient,
                "the application this service account belongs to is disabled",
            ));
        }
        let (audience, perms, ttl) = match requested_resource {
            None | Some("") => (userinfo_audience(&issuer), None, self.access_token_ttl),
            Some(requested) if requested == management_aud => {
                // For the identity of a stopped app, nothing is included even with permission codes. Only the directory (self) passes.
                let codes = if own_application_disabled {
                    Vec::new()
                } else {
                    self.client_permissions
                        .list_codes_for_client(client.id)
                        .await
                        .map_err(|e| internal(&e))?
                };
                // Admin tokens may be issued only to (1) clients holding at least one permission code, or
                // (2) clients **bound as some app's identity (service account)**
                // (ADR-0059). For (2) `perms` stays empty, and only endpoints decided by the identity pass
                // (`/admin/applications/self/users`): tenant-wide permissions do not increase.
                //
                // Not issued to clients that are neither. It would be a token for which everything is 403,
                // creating the hardest-to-trace failure, "obtained but nothing passes".
                if codes.is_empty() && own_application.is_none() {
                    self.audit
                        .record(
                            AuditEventType::ClientAuthenticationFailed,
                            AuditResult::Failure,
                            Some(tenant_id),
                            None,
                            Some(&client_id),
                            Some("no_management_permissions"),
                            ctx,
                        )
                        .await;
                    return Err(TokenError::new(
                        OAuthErrorCode::InvalidTarget,
                        "client holds no management permissions for the requested resource",
                    ));
                }
                (
                    management_aud,
                    Some(codes.join(" ")),
                    self.management_token_ttl,
                )
            }
            // Registered audiences (ADR-0042). What goes into `aud` here is **the name of the called side**,
            // not where assay connects. `perms` is not included: what may be done there
            // is decided by the resource server using `client_id` (ADR-0033).
            Some(requested) => {
                let found = self
                    .resources
                    .find_by_uri(tenant_id, requested)
                    .await
                    .map_err(|e| internal(&e))?;
                // "Not registered", "disabled" and "not permitted" are **not distinguished in the response**.
                // Distinguishing would let brute force discover "which audiences are registered". Diagnosis is done via the audit.
                //
                // It may be issued only when the audience is active, is **some app's `resource` identity**, that app is
                // active, and the requesting service account is **assigned to that app**
                // (ADR-0059 decision 6). "Which service accounts may use this API" is listed among
                // the app's "using principals".
                let issuable = match found {
                    None => Err("unknown_resource"),
                    Some(resource) if !resource.is_active() => Err("resource_disabled"),
                    Some(resource) => match self
                        .applications
                        .find_by_binding_target(
                            tenant_id,
                            BindingTarget::Resource {
                                resource_id: resource.id,
                            },
                        )
                        .await
                        .map_err(|e| internal(&e))?
                    {
                        None => Err("resource_not_bound_to_an_application"),
                        // The allow/deny rule is `admits_service_account`, the same as the account screen (ADR-0065).
                        // For a stopped app, assignments are not looked up.
                        Some(application) if !application.is_active() => {
                            Err(application.admits_service_account(false).reason())
                        }
                        Some(application) => {
                            let assigned = self
                                .applications
                                .is_service_account_assigned(application.id, client.id)
                                .await
                                .map_err(|e| internal(&e))?;
                            match application.admits_service_account(assigned) {
                                ApplicationAccess::Allowed => Ok(resource),
                                // The audit reason keeps the existing wording (`service_account_not_assigned`).
                                ApplicationAccess::NotAssigned => {
                                    Err("service_account_not_assigned")
                                }
                                denied => Err(denied.reason()),
                            }
                        }
                    },
                };
                let resource = match issuable {
                    Ok(resource) => resource,
                    Err(reason) => {
                        self.audit
                            .record(
                                AuditEventType::ClientAuthenticationFailed,
                                AuditResult::Failure,
                                Some(tenant_id),
                                None,
                                Some(&client_id),
                                Some(reason),
                                ctx,
                            )
                            .await;
                        return Err(TokenError::new(
                            OAuthErrorCode::InvalidTarget,
                            "the requested resource is not served by this authorization server",
                        ));
                    }
                };
                // Put **the registered string** in `aud` (not the requested spelling). The table's collation
                // is case-insensitive, so a request for `API://x` finds the `api://x` row. Returning the request as is
                // would miss on resource servers that compare by exact match with the registered value (ADR-0042 "do not normalize").
                (resource.resource_uri, None, self.access_token_ttl)
            }
        };

        // 6. Issue the Access Token (no ID Token or Refresh Token).
        let access_claims = AccessTokenClaims {
            iss: issuer.clone(),
            // No user, so the principal is the client itself (operational convention of RFC 6749 §4.4).
            sub: client.client_id.clone(),
            aud: audience,
            client_id: client.client_id.clone(),
            scope: scope_str.clone(),
            exp: iat + ttl.as_secs() as i64,
            iat,
            jti: Uuid::new_v4().to_string(),
            sub_type: Some(SUBJECT_TYPE_CLIENT.to_string()),
            perms,
            // Machine (server) tokens are not bound via DPoP (ADR-0075 decision 1).
            cnf: None,
        };
        let access_token = self.sign_access_token(&access_claims).await?;

        self.audit
            .record(
                AuditEventType::TokenIssued,
                AuditResult::Success,
                Some(tenant_id),
                // No user, so no user_id is kept (the client itself is the principal).
                None,
                Some(&client.client_id),
                Some("grant=client_credentials"),
                ctx,
            )
            .await;

        Ok(IssuedTokens {
            access_token,
            id_token: None,
            expires_in: ttl.as_secs(),
            scope: scope_str,
            refresh_token: None,
            bound_to_key: false,
        })
    }

    async fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "JWT", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    async fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, TokenError> {
        let key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| internal(&e))?;
        jwt::sign(&key.private_pem, &key.kid, "at+jwt", &key.algorithm, claims)
            .map_err(|e| internal(&e))
    }

    /// Client authentication (design spec §4.4, RFC 6749 §2.3.1).
    ///
    /// Both the choice of credentials to check (Basic / body / assertion) and the check itself are
    /// consolidated in `client_authentication` (G3, ADR-0030). This only handles audit recording.
    async fn authenticate_client(
        &self,
        tenant: TenantContext,
        client: &Client,
        cmd: &TokenCommand,
        ctx: &RequestContext,
    ) -> Result<(), TokenError> {
        match self
            .client_auth
            .authenticate(tenant, client, &cmd.credentials)
            .await
        {
            // Public clients (`none`) pass without authentication.
            Ok(ClientAuthOutcome::NotRequired | ClientAuthOutcome::Authenticated) => Ok(()),
            Err(ClientAuthError::Failed(failure)) => Err(self
                .client_auth_failed(tenant, &client.client_id, failure.as_str(), ctx)
                .await),
            Err(ClientAuthError::Internal(message)) => Err(internal(&message)),
        }
    }

    async fn load_active_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
        ctx: &RequestContext,
    ) -> Result<Client, TokenError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            Ok(Some(c)) if c.is_active() => Ok(c),
            Ok(Some(_)) => Err(self
                .client_auth_failed(tenant, client_id, "client_not_active", ctx)
                .await),
            Ok(None) => Err(self
                .client_auth_failed(tenant, client_id, "unknown_client", ctx)
                .await),
            Err(e) => Err(internal(&e)),
        }
    }

    /// Whether the user may be issued tokens (common to both grants. Both code exchange and refresh go through this).
    ///
    /// In addition to the user's own status, also checks that **the home tenant is `ACTIVE`** (ADR-0009 §8).
    /// Disabling a tenant is an operation that stops that organization's use, and it would not count as stopped if refreshing
    /// with issued refresh tokens kept working. The disabled tenant's own `/{tenant_id}/token` is
    /// stopped with 404 by `TenantResolver`, but `/{tenant_id}/token` of **other tenants** where that user participates as a guest
    /// is alive, and only this check blocks it.
    ///
    /// **Looks at the DB every time without a cache.** This is a revocation-like check, and disabling should take effect immediately
    /// (putting it in the tenant resolution TTL cache would let refreshes pass for up to the TTL). Token
    /// issuance already reads client, code/token, user and signing key, so one more primary-key lookup is enough.
    async fn load_active_user(
        &self,
        user_id: uuid::Uuid,
        _ctx: &RequestContext,
    ) -> Result<crate::domain::user::User, TokenError> {
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(Some(_)) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "user is not active",
                ))
            }
            Ok(None) => {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidGrant,
                    "user no longer exists",
                ))
            }
            Err(e) => return Err(internal(&e)),
        };
        match self.tenants.find_by_id(user.tenant_id).await {
            Ok(Some(home)) if home.is_active() => Ok(user),
            // Missing (deleted with the tenant) and `DISABLED` are not distinguished. From the RP's view both are
            // "can no longer issue for this user", handled the same.
            Ok(_) => Err(TokenError::new(
                OAuthErrorCode::InvalidGrant,
                "the user's home tenant is not active",
            )),
            Err(e) => Err(internal(&e)),
        }
    }

    async fn client_auth_failed(
        &self,
        tenant: TenantContext,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) -> TokenError {
        self.audit
            .record(
                AuditEventType::ClientAuthenticationFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                Some(client_id),
                Some(reason),
                ctx,
            )
            .await;
        TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication failed",
        )
    }
}

/// Resolves client_id with the Basic header taking precedence.
fn resolve_client_id(cmd: &TokenCommand) -> Result<String, TokenError> {
    // RFC 6749 §2.3.1: multiple authentication methods must not be used in one request (G3). Rejected before looking up the client.
    cmd.credentials.ensure_single_method().map_err(|_| {
        TokenError::new(
            OAuthErrorCode::InvalidRequest,
            "client credentials must be presented with a single authentication method",
        )
    })?;
    match cmd.credentials.resolve_client_id() {
        Ok(client_id) => Ok(client_id),
        Err(ClientAuthFailure::ClientIdMismatch) => Err(TokenError::new(
            OAuthErrorCode::InvalidRequest,
            "client_id mismatch between Authorization header and body",
        )),
        Err(_) => Err(TokenError::new(
            OAuthErrorCode::InvalidClient,
            "client authentication is required",
        )),
    }
}

/// Decides the scope of `client_credentials` (G4).
///
/// - With a request: all must be a subset of the client's registered scopes (same exact-match check as `/authorize`).
/// - Without a request: the default is the registered scopes **minus user-oriented scopes**. `openid` is
///   a scope requesting "end-user authentication", and `profile` / `email` refer to user claims,
///   meaningless in tokens without a user. `offline_access` is a Refresh Token request, and
///   this grant can re-present credentials (= no need to refresh), so it is always rejected.
fn resolve_client_credentials_scopes(
    client: &Client,
    requested: Option<&str>,
) -> Result<Vec<String>, TokenError> {
    let user_bound = [
        Scope::OpenId.as_str(),
        Scope::Profile.as_str(),
        Scope::Email.as_str(),
    ];
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let scopes: Vec<String> = raw.split_whitespace().map(str::to_string).collect();
            if scopes.iter().any(|s| s == Scope::OfflineAccess.as_str()) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "offline_access is not available for the client_credentials grant",
                ));
            }
            // User-oriented scopes are rejected even if requested. Dropping them when omitted but letting explicit requests
            // through would allow issuing **tokens that claim user claims without a user**.
            if scopes.iter().any(|s| user_bound.contains(&s.as_str())) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "user-bound scopes are not available for the client_credentials grant",
                ));
            }
            if !client.allows_scopes(&scopes) {
                return Err(TokenError::new(
                    OAuthErrorCode::InvalidScope,
                    "requested scope exceeds the scopes registered for this client",
                ));
            }
            Ok(scopes)
        }
        None => Ok(client
            .scopes
            .iter()
            .filter(|s| {
                s.as_str() != Scope::OfflineAccess.as_str() && !user_bound.contains(&s.as_str())
            })
            .cloned()
            .collect()),
    }
}

fn internal<E: std::fmt::Display>(e: &E) -> TokenError {
    tracing::error!(error = %e, "token endpoint internal error");
    TokenError {
        code: OAuthErrorCode::ServerError,
        description: "internal server error".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};

    /// ADR-0043 decision 3. When nothing is recorded, nothing is claimed by guessing.
    #[test]
    fn no_record_means_no_acr() {
        assert_eq!(authentication_claims(None), (None, None));
        // An empty record is treated the same (there is no authentication that "verified nothing").
        assert_eq!(authentication_claims(Some(&vec![])), (None, None));
    }

    #[test]
    fn acr_and_amr_come_from_the_recorded_methods() {
        let (acr, amr) = authentication_claims(Some(&vec![
            AuthenticationMethod::Password,
            AuthenticationMethod::Totp,
        ]));
        assert_eq!(
            acr.as_deref(),
            Some(crate::domain::values::ACR_MULTI_FACTOR)
        );
        assert_eq!(amr, Some(vec!["pwd".to_string(), "otp".to_string()]));

        let (acr, amr) = authentication_claims(Some(&vec![AuthenticationMethod::Password]));
        assert_eq!(
            acr.as_deref(),
            Some(crate::domain::values::ACR_SINGLE_FACTOR)
        );
        assert_eq!(amr, Some(vec!["pwd".to_string()]));
    }

    /// `email_otp` and `sms_otp` are both `otp` in RFC 8176. The same value is not listed twice.
    #[test]
    fn amr_folds_duplicates() {
        let (_, amr) = authentication_claims(Some(&vec![
            AuthenticationMethod::EmailOtp,
            AuthenticationMethod::SmsOtp,
        ]));
        assert_eq!(amr, Some(vec!["otp".to_string()]));
    }

    /// External IdPs do not count as a second factor (ADR-0008). `fed` appears in `amr`, but `acr` does not rise:
    /// this is where the reason `amr` must not be used to judge strength shows.
    #[test]
    fn an_external_idp_login_is_not_multi_factor() {
        let (acr, amr) = authentication_claims(Some(&vec![AuthenticationMethod::ExternalIdp]));
        assert_eq!(
            acr.as_deref(),
            Some(crate::domain::values::ACR_SINGLE_FACTOR)
        );
        assert_eq!(amr, Some(vec!["fed".to_string()]));
    }
    use chrono::TimeZone;

    fn client_with_scopes(scopes: &[&str]) -> Client {
        let now = chrono::Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        Client {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from(Uuid::from_u128(2)),
            client_id: "svc".to_string(),
            client_secret_hash: None,
            client_type: ClientType::Confidential,
            client_status: ClientStatus::Active,
            app_name: "svc".to_string(),
            redirect_uris: vec![],
            grant_types: vec!["client_credentials".to_string()],
            response_types: vec!["code".to_string()],
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// The only registrable scopes are the 4 OIDC values (`validate_scopes`), all of which are user-oriented or
    /// `offline_access`. So **`client_credentials` tokens have an empty scope**.
    /// Business permissions are decided by apps by looking at `sub` (= `client_id`) (ADR-0033).
    #[test]
    fn client_credentials_tokens_carry_no_scope() {
        // The minimal form registrable as a system client.
        let client = client_with_scopes(&["openid"]);
        assert!(resolve_client_credentials_scopes(&client, None)
            .unwrap()
            .is_empty());

        // Same with all 4 values that a client also used for users may register.
        let client = client_with_scopes(&["openid", "profile", "email", "offline_access"]);
        assert!(resolve_client_credentials_scopes(&client, None)
            .unwrap()
            .is_empty());
    }

    /// Unregistered scopes are rejected (same exact-match check as `/authorize`).
    ///
    /// The only registrable scopes are now the 4 OIDC values (ADR-0033), so only rows registered
    /// before the restriction reach this check. The gatekeeper is kept, so rows of that form are rejected too.
    /// **Writing it with user-oriented scopes makes the gatekeeper one level up reject first, and this check is not reached.**
    #[test]
    fn requested_scope_must_be_a_subset_of_the_registered_scopes() {
        // The form registered before ADR-0033 (cannot be registered now).
        let client = client_with_scopes(&["openid", "reports.read"]);
        let err = resolve_client_credentials_scopes(&client, Some("reports.write"))
            .expect_err("unregistered scope is rejected");
        assert_eq!(err.code, OAuthErrorCode::InvalidScope);
    }

    /// User-oriented scopes are rejected even if requested. Dropping them when omitted but letting explicit requests through
    /// would allow issuing **tokens that claim user claims without a user**.
    #[test]
    fn user_bound_scopes_are_rejected_even_when_registered() {
        let client = client_with_scopes(&["openid", "profile", "email"]);
        for requested in ["openid", "profile", "email", "openid profile"] {
            let err = resolve_client_credentials_scopes(&client, Some(requested))
                .expect_err("user-oriented scope is rejected");
            assert_eq!(
                err.code,
                OAuthErrorCode::InvalidScope,
                "requested={requested}"
            );
        }
    }

    /// `offline_access` is always rejected in this grant (credentials can be re-presented, so no need to refresh).
    #[test]
    fn offline_access_is_rejected_even_when_registered() {
        let client = client_with_scopes(&["openid", "offline_access"]);
        let err = resolve_client_credentials_scopes(&client, Some("offline_access"))
            .expect_err("offline_access is rejected");
        assert_eq!(err.code, OAuthErrorCode::InvalidScope);
    }

    /// A scope of only empty string / whitespace is treated the same as "omitted" (no 400 for an empty form field).
    #[test]
    fn blank_scope_is_treated_as_omitted() {
        let client = client_with_scopes(&["openid"]);
        assert!(resolve_client_credentials_scopes(&client, Some("   "))
            .unwrap()
            .is_empty());
    }

    /// Only `client_credentials` tokens have `sub_type`; when omitted it is read as a user principal
    /// (compatibility with tokens issued before this claim was introduced).
    #[test]
    fn subject_type_distinguishes_client_tokens_from_end_user_tokens() {
        let mut claims = AccessTokenClaims {
            iss: "https://idp.example.com/t".to_string(),
            sub: "svc".to_string(),
            aud: "https://idp.example.com/t/userinfo".to_string(),
            client_id: "svc".to_string(),
            scope: String::new(),
            exp: 0,
            iat: 0,
            jti: "j".to_string(),
            sub_type: Some(SUBJECT_TYPE_CLIENT.to_string()),
            perms: None,
            cnf: None,
        };
        assert!(claims.subject_is_client());
        claims.sub_type = None;
        assert!(!claims.subject_is_client());
    }
}
