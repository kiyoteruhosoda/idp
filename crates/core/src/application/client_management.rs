//! Client (RP) registration and management use case (design spec §9.3, Progress A1).
//!
//! Only tenant admins (`idp.tenant.admin`; `idp.system.admin` accepted as an alternative) run it. `client_id` is assigned automatically; `client_secret` is issued
//! for confidential clients and **the plaintext is returned only the first time (and on reissue)**. The DB stores only an argon2 hash
//! (reusing the existing `PasswordHasher`). Every change is recorded in `audit_log`.
//!
//! Redirect URIs support exact matching and multiple registrations; fragments and wildcards are forbidden (§2.3).
//! `Clients.scopes`, used for the subset check of requested scopes, is limited to the set of supported OIDC scopes.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::account::AccountRef;
use crate::domain::account_note::normalize_account_note;
use crate::domain::admin_actor::AdminActor;
use crate::domain::application::{
    Application, ApplicationAssignment, ApplicationBinding, BindingTarget,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::client_jwks::{parse_registration_jwks, ClientJwks};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::paging::{PageRequest, PagedResult};
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{AccountNoteRepository, ApplicationRepository, ClientRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{
    ApplicationStatus, AssignmentMode, ClientStatus, ClientType, GrantType, Scope,
    TokenEndpointAuthMethod,
};
use std::sync::Arc;

/// Byte length of an issued client_id (twice as many characters in lowercase hex).
const CLIENT_ID_BYTES: usize = 16;
/// Byte length of an issued client_secret (256 bits).
const CLIENT_SECRET_BYTES: usize = 32;
/// Default number of items per page of the client list (G7).
pub const DEFAULT_PAGE_LIMIT: i64 = 50;
/// Maximum number of items per page of the client list (prevents oversized fetches).
pub const MAX_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Clone)]
pub struct RegisterClientCommand {
    pub app_name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    /// Defaults to true when omitted. Public clients require PKCE, so false is coerced to true.
    /// Whether server-to-server (M2M) integration may use the `client_credentials` grant (G4. default false).
    /// Public clients can't keep credentials secret, so it stays disabled even if requested.
    pub allow_client_credentials: bool,
    /// Client authentication method for confidential clients (G3). `None` means the default `private_key_jwt`
    /// (ADR-0036). However, a request with `jwks` also `None` would be "a client with no means of authentication",
    /// so it is stopped with a 400 instead of falling back to the default. Not applied to public clients (always `none`).
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// Verification keys for `private_key_jwt` (JWK Set JSON. ADR-0030). Required when choosing that method,
    /// and cannot be specified with other methods.
    pub jwks: Option<String>,
    /// Redirect destinations after RP-initiated logout (optional). F4.
    pub post_logout_redirect_uris: Vec<String>,
    /// front-channel logout URI (optional). F4.
    pub frontchannel_logout_uri: Option<String>,
    /// back-channel logout URI (optional). F4.
    pub backchannel_logout_uri: Option<String>,
    /// Admin note (optional. ADR-0065). ⚠ **Only service accounts can have one** ——a note is the account's
    /// history, not a setting of the integration. Empty (whitespace only) means no note.
    pub note: Option<String>,
}

/// Partial update command. Fields that are `None` are not changed.
#[derive(Debug, Clone, Default)]
pub struct UpdateClientCommand {
    pub app_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub status: Option<ClientStatus>,
    /// Redirect destinations after RP-initiated logout (`Some(vec![])` deletes). F4.
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// front-channel logout URI (`Some(None)` deletes). F4.
    pub frontchannel_logout_uri: Option<Option<String>>,
    /// back-channel logout URI (`Some(None)` deletes). F4.
    pub backchannel_logout_uri: Option<Option<String>>,
    /// Allowing the `client_credentials` grant (G4). Not applied to public clients.
    pub allow_client_credentials: Option<bool>,
    /// Change of client authentication method (G3). Confidential clients only.
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// Replacement of the `private_key_jwt` verification keys (ADR-0030). Key rotation is done by listing
    /// old and new in this set.
    pub jwks: Option<String>,
}

/// Registration result. `client_secret` is returned in plaintext only for confidential clients (only the hash is stored).
pub struct RegisteredClient {
    pub client: Client,
    pub client_secret: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct ClientManagementService {
    clients: Arc<dyn ClientRepository>,
    /// Used to open the registered RP as an application (ADR-0054).
    applications: Arc<dyn ApplicationRepository>,
    /// Writes the admin note at the same time as creating the service account (ADR-0065).
    notes: Arc<dyn AccountNoteRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl ClientManagementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        applications: Arc<dyn ApplicationRepository>,
        notes: Arc<dyn AccountNoteRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            clients,
            applications,
            notes,
            hasher,
            audit,
            clock,
            ids,
        }
    }

    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterClientCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<RegisteredClient, ClientManagementError> {
        let app_name = validate_app_name(cmd.app_name)?;
        // Only system clients (no user) can register without a redirect_uri (ADR-0032). This exception exists so a
        // caller with no browser redirect destination isn't forced to make up a URL it never uses.
        let system_client =
            cmd.allow_client_credentials && cmd.client_type == ClientType::Confidential;
        let redirect_uris = validate_redirect_uris(&cmd.redirect_uris, system_client)?;
        validate_single_usage(system_client, &redirect_uris)?;
        let scopes = validate_scopes(&cmd.scopes)?;
        // Logout URIs go through the same checks as redirect URIs (SEC2).
        let post_logout_redirect_uris =
            validate_post_logout_redirect_uris(&cmd.post_logout_redirect_uris)?;
        let frontchannel_logout_uri =
            validate_frontchannel_logout_uri(cmd.frontchannel_logout_uri)?;
        let backchannel_logout_uri = validate_backchannel_logout_uri(cmd.backchannel_logout_uri)?;
        // The note is validated **before** creating the client (if too long, nothing is created; same as user creation. ADR-0063).
        let note = match cmd.note.as_deref() {
            Some(raw) => normalize_account_note(raw).map_err(ClientManagementError::Validation)?,
            None => None,
        };
        if note.is_some() && !system_client {
            return Err(ClientManagementError::Validation(MessageKey::new(
                "api-account-note-needs-service-account",
            )));
        }

        // Decide the authentication method and secret according to the client type.
        // public: no authentication, no secret. confidential: issue a secret + choose how it is presented (G3).
        // PKCE (S256) is required unconditionally by `/authorize` and `/token` regardless of type (there's no per-client
        // setting; SEC12 removed "settings that are never actually read").
        // `private_key_jwt` has no shared secret (ADR-0030). Not issuing a secret both avoids keeping an unused
        // secret in the DB and avoids the coexistence of "registered as private_key_jwt but a secret also
        // works".
        let (auth_method, secret_plain, secret_hash, jwks) = match cmd.client_type {
            ClientType::Public => {
                if cmd.jwks.is_some() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-jwks-not-applicable",
                    )));
                }
                (TokenEndpointAuthMethod::None, None, None, None)
            }
            ClientType::Confidential => {
                // A request with neither method nor verification keys would, with the default `private_key_jwt`, become a client
                // with no means of authentication. Returning only "verification keys required" here wouldn't explain the reason to a
                // caller who never wrote `private_key_jwt`, so the default is included in the response (ADR-0036).
                if cmd.token_endpoint_auth_method.is_none() && cmd.jwks.is_none() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-auth-method-unspecified",
                    )));
                }
                let method = validate_confidential_auth_method(cmd.token_endpoint_auth_method)?;
                let jwks = validate_jwks_for_method(method, cmd.jwks.as_deref())?;
                if method == TokenEndpointAuthMethod::PrivateKeyJwt {
                    (method, None, None, jwks)
                } else {
                    let plain = crate::domain::crypto::random_token(CLIENT_SECRET_BYTES);
                    let hash = self
                        .hasher
                        .hash(&plain)
                        .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
                    (method, Some(plain), Some(hash), jwks)
                }
            }
        };

        let now = self.clock.now();
        let client = Client {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            client_id: crate::domain::crypto::random_hex(CLIENT_ID_BYTES),
            client_secret_hash: secret_hash,
            client_type: cmd.client_type,
            client_status: ClientStatus::Active,
            app_name,
            // User login via the browser is Authorization Code Flow only (design spec §5).
            // `client_credentials` is an additional permission for M2M, accepted only for confidential clients (G4).
            grant_types: grant_types_for(
                cmd.client_type,
                cmd.allow_client_credentials,
                !redirect_uris.is_empty(),
            ),
            redirect_uris,
            response_types: vec!["code".to_string()],
            scopes,
            token_endpoint_auth_method: auth_method,
            jwks,
            post_logout_redirect_uris,
            frontchannel_logout_uri,
            backchannel_logout_uri,
            created_at: now,
            updated_at: now,
        };

        self.clients.create(&client).await.map_err(|e| match e {
            // The only DB unique constraint violation is a duplicate client_id within the tenant (no other unique keys).
            DomainError::Conflict(_) => {
                ClientManagementError::Conflict(MessageKey::new("api-client-id-conflict"))
            }
            other => ClientManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::ClientRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                actor.audit_note().as_deref(),
                ctx,
            )
            .await;

        // Admin note (ADR-0065). Same row and same audit shape as writing it from the account screen
        // (the content is not kept in the audit).
        if let Some(text) = note.as_deref() {
            self.notes
                .save(
                    tenant.tenant_id(),
                    AccountRef::ServiceAccount {
                        client_row_id: client.id,
                    },
                    text,
                    actor.user_id(),
                    now,
                )
                .await
                .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
            self.audit
                .record(
                    AuditEventType::AccountNoteUpdated,
                    AuditResult::Success,
                    Some(tenant.tenant_id()),
                    actor.user_id(),
                    actor.client_id(),
                    Some(&format!("service_account={}", client.client_id)),
                    ctx,
                )
                .await;
        }

        self.open_as_application(tenant, &client, actor, ctx).await;

        Ok(RegisteredClient {
            client,
            client_secret: secret_plain,
        })
    }

    /// Opens the registered RP as **one application + one OIDC binding** (ADR-0054). The same shape the migration
    /// (`0054_applications`) gave the existing 23 is applied to new RPs too.
    ///
    /// ⚠ **If not opened, the RP falls outside "who may use it".** The check lets clients without an application
    /// pass through, so a merely registered RP would stay **open to everyone**, and that it's open would show nowhere
    /// on screen ——the very shape ADR-0054 avoided even by making "individual" the default.
    ///
    /// Only **RPs that users enter through a browser** are opened. `client_credentials` service accounts
    /// (ADR-0038) have no users entering and the check never runs ——it would just add applications with empty rosters.
    ///
    /// ⚠ **Even on failure, registration is returned as successful.** The client is already created, and returning a failure
    /// here would mean "an error, yet the RP exists". The application can be created later from the screen.
    async fn open_as_application(
        &self,
        tenant: TenantContext,
        client: &Client,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) {
        if !client.allows_grant_type(GrantType::AuthorizationCode) {
            return;
        }
        let now = self.clock.now();
        let application = Application {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            display_name: client.app_name.clone(),
            status: ApplicationStatus::Active,
            // ⚠ The default is "individual" (ADR-0054 decision 3). So forgetting to restrict doesn't leave it open to everyone.
            assignment_mode: AssignmentMode::Individual,
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.applications.create(&application).await {
            tracing::error!(error = %e, client_id = %client.client_id,
                "failed to open the registered client as an application");
            return;
        }
        if let Err(e) = self
            .applications
            .add_binding(&ApplicationBinding {
                id: self.ids.new_id(),
                application_id: application.id,
                target: BindingTarget::Oidc {
                    client_row_id: client.id,
                },
                created_at: now,
            })
            .await
        {
            tracing::error!(error = %e, client_id = %client.client_id,
                "failed to bind the registered client to its application");
            return;
        }
        // Assign the person who created it. ⚠ Without this, the application would admit **nobody** right after registration.
        // When a machine registers it, there's no one to assign, so nothing is done (the roster is filled from the screen).
        if let Some(user_id) = actor.user_id() {
            if let Err(e) = self
                .applications
                .assign(&ApplicationAssignment {
                    id: self.ids.new_id(),
                    application_id: application.id,
                    principal: AccountRef::User { user_id },
                    assigned_at: now,
                    assigned_by: Some(user_id),
                })
                .await
            {
                tracing::error!(error = %e, "failed to assign the creator to the new application");
            }
        }
        self.audit
            .record(
                AuditEventType::ApplicationRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                Some(&format!("application={}", application.id)),
                ctx,
            )
            .await;
    }

    pub async fn list(&self, tenant: TenantContext) -> Result<Vec<Client>, ClientManagementError> {
        self.clients
            .list(tenant.tenant_id())
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))
    }

    /// Returns one page of registered clients (G7). `limit` / `offset` take unvalidated requested values,
    /// clamp them into the allowed range and attach the **applied values** to the result.
    /// Returns one page and the total count. `grant_type` is a filter that splits the console list into
    /// "integrations" and "service accounts" (ADR-0038).
    ///
    /// The purpose itself isn't an argument, to keep ADR-0032's "the purpose is not in the api model".
    /// `authorization_code` and `client_credentials` never coexist in one client
    /// (ADR-0032 Revised), so a single grant splits them exclusively.
    pub async fn list_page(
        &self,
        tenant: TenantContext,
        grant_type: Option<GrantType>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<Client>, ClientManagementError> {
        let request = PageRequest::clamped(limit, offset, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
        let page = self
            .clients
            .list_page(tenant.tenant_id(), grant_type, request)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;
        Ok(PagedResult::new(page, request))
    }

    pub async fn get(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ClientManagementError> {
        self.load(tenant, client_id).await
    }

    /// Logically deletes a client (ADR-0035).
    ///
    /// The entity is kept and its state set to `DELETED`. Issued authorization codes, tokens, consents and audit logs are
    /// linked by `client_id`, so deleting the entity would make it impossible to trace "which app it was" in the audit.
    /// **The purpose of deletion is to make it unusable, not to erase records.**
    ///
    /// It becomes unusable immediately when the state changes —— authorization, tokens and introspection are
    /// gated by `is_active()`, so `DELETED` is rejected just like `DISABLED`.
    pub async fn delete(
        &self,
        tenant: TenantContext,
        client_id: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ClientManagementError> {
        let mut client = self.load(tenant, client_id).await?;
        client.client_status = ClientStatus::Deleted;
        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                actor.audit_note().as_deref(),
                ctx,
            )
            .await;
        Ok(())
    }

    pub async fn update(
        &self,
        tenant: TenantContext,
        client_id: &str,
        cmd: UpdateClientCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Client, ClientManagementError> {
        let mut client = self.load(tenant, client_id).await?;
        // Remember this to check the preconditions (secret / verification keys present) imposed only on **switching** the method.
        // Also so updates that don't change the method (fixing app_name etc.) don't rewrite credentials.
        let method_before = client.token_endpoint_auth_method;

        if let Some(app_name) = cmd.app_name {
            client.app_name = validate_app_name(app_name)?;
        }
        // Whether redirect_uri may be empty depends on whether `client_credentials` is allowed, so judge by the post-update shape
        // (so the combination of removing the permission and also clearing the URIs in this update doesn't pass). ADR-0032.
        let allows_client_credentials = cmd
            .allow_client_credentials
            .unwrap_or_else(|| client.allows_client_credentials())
            && client.client_type == ClientType::Confidential;
        if let Some(redirect_uris) = cmd.redirect_uris {
            client.redirect_uris =
                validate_redirect_uris(&redirect_uris, allows_client_credentials)?;
        } else {
            // Even updates that don't touch URIs check whether the post-update shape holds. So an update that only removes
            // `client_credentials` doesn't leave "a client that can do nothing" without a redirect_uri either
            // (grant_types would become empty). ADR-0032 decision 2.
            validate_redirect_uris(&client.redirect_uris, allows_client_credentials)?;
        }
        validate_single_usage(allows_client_credentials, &client.redirect_uris)?;
        if let Some(scopes) = cmd.scopes {
            client.scopes = validate_scopes(&scopes)?;
        }
        if let Some(status) = cmd.status {
            // Logical deletion is only done by the dedicated delete path (`delete`) (ADR-0035). Passing it through here
            // would allow an irreversible deletion without leaving the `client.deleted` audit record
            // (deleted clients are dropped by `load`, so this update path couldn't come back to them either).
            if status == ClientStatus::Deleted {
                return Err(ClientManagementError::Validation(MessageKey::new(
                    "api-client-status-invalid",
                )));
            }
            client.client_status = status;
        }
        // Updates go through the same checks as registration (SEC2; passing registration is pointless if an update can replace it).
        if let Some(uris) = cmd.post_logout_redirect_uris {
            client.post_logout_redirect_uris = validate_post_logout_redirect_uris(&uris)?;
        }
        if let Some(uri) = cmd.frontchannel_logout_uri {
            client.frontchannel_logout_uri = validate_frontchannel_logout_uri(uri)?;
        }
        if let Some(uri) = cmd.backchannel_logout_uri {
            client.backchannel_logout_uri = validate_backchannel_logout_uri(uri)?;
        }
        // grant_types is a value derived from the registration, not an independent setting (ADR-0032).
        // Recomputing it on every update prevents combinations that don't match reality, such as
        // `authorization_code` remaining after redirect_uri was cleared.
        client.grant_types = grant_types_for(
            client.client_type,
            allows_client_credentials,
            !client.redirect_uris.is_empty(),
        );
        // Changing the authentication method is confidential-only (G3). Public clients have no secret, so it is fixed to `none`,
        // and a request is refused rather than silently ignored (no "thought I changed it but it didn't" state).
        if let Some(method) = cmd.token_endpoint_auth_method {
            if client.client_type != ClientType::Confidential {
                return Err(ClientManagementError::Validation(MessageKey::new(
                    "api-client-auth-method-public",
                )));
            }
            client.token_endpoint_auth_method = validate_confidential_auth_method(Some(method))?;
        }
        // Replacing verification keys (ADR-0030). Checked after applying the method so it can be specified together with a method change.
        if let Some(raw) = cmd.jwks.as_deref() {
            if client.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt {
                return Err(ClientManagementError::Validation(MessageKey::new(
                    "api-client-jwks-not-applicable",
                )));
            }
            client.jwks = Some(parse_jwks(raw)?);
        }
        let switched = client.token_endpoint_auth_method != method_before;
        match client.token_endpoint_auth_method {
            TokenEndpointAuthMethod::PrivateKeyJwt => {
                // Switching to `private_key_jwt` without verification keys would leave the client unable to authenticate
                // with any credential. The keys may be existing ones or the ones specified now.
                if client.jwks.is_none() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-jwks-required",
                    )));
                }
                // On switching, drop the shared secret that will no longer be read. To go back to a secret method,
                // reissue with `rotate_secret`. Updates that don't change the method don't touch it
                // (so a secret reissued in preparation for switching isn't erased by an unrelated update).
                if switched {
                    client.client_secret_hash = None;
                }
            }
            // Switching to a secret method needs a secret to check against. Switching without one would make authentication
            // impossible, so they must reissue (`rotate_secret`) first and then switch.
            TokenEndpointAuthMethod::ClientSecretBasic
            | TokenEndpointAuthMethod::ClientSecretPost => {
                if switched && client.client_secret_hash.is_none() {
                    return Err(ClientManagementError::Validation(MessageKey::new(
                        "api-client-auth-method-needs-secret",
                    )));
                }
                // Secret methods hold no verification keys (don't leave keys that are never read).
                client.jwks = None;
            }
            // public (`none`). Holds no credentials.
            TokenEndpointAuthMethod::None => client.jwks = None,
        }

        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                actor.audit_note().as_deref(),
                ctx,
            )
            .await;

        Ok(client)
    }

    /// Reissues client_secret (confidential only). Returns the new plaintext; the DB only updates the hash.
    pub async fn rotate_secret(
        &self,
        tenant: TenantContext,
        client_id: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(Client, String), ClientManagementError> {
        let mut client = self.load(tenant, client_id).await?;
        if client.client_type != ClientType::Confidential {
            return Err(ClientManagementError::Validation(MessageKey::new(
                "api-client-secret-public",
            )));
        }

        let plain = crate::domain::crypto::random_token(CLIENT_SECRET_BYTES);
        client.client_secret_hash = Some(
            self.hasher
                .hash(&plain)
                .map_err(|e| ClientManagementError::Internal(e.to_string()))?,
        );

        self.clients
            .update(&client)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::ClientSecretRotated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                actor.audit_note().as_deref(),
                ctx,
            )
            .await;

        Ok((client, plain))
    }

    /// Reads the target of an admin operation. **Logically deleted ones are treated as absent** (ADR-0035).
    ///
    /// Dropping them once here makes get, update, secret reissue and delete all return 404.
    /// Writing `is_deleted()` per path would let only the paths that forgot it operate on deleted clients.
    async fn load(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ClientManagementError> {
        self.clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
            .map_err(|e| ClientManagementError::Internal(e.to_string()))?
            .filter(|c| !c.is_deleted())
            .ok_or(ClientManagementError::NotFound)
    }
}

/// Validates the client authentication method of a confidential client (G3).
///
/// Defaults to `private_key_jwt` when omitted (ADR-0036). OIDC Registration 1.0's default is `client_secret_basic`,
/// but falling back to that would silently turn "registrations that didn't state a method" into shared-secret clients. The
/// stronger one is the default, and choosing the weaker one must be explicit. `none` (= no authentication) can't be chosen
/// for confidential —— if it could, a client that anyone can call `/token` with while holding a secret could be created
/// from the admin UI.
fn validate_confidential_auth_method(
    requested: Option<TokenEndpointAuthMethod>,
) -> Result<TokenEndpointAuthMethod, ClientManagementError> {
    match requested {
        None => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        Some(TokenEndpointAuthMethod::ClientSecretBasic) => {
            Ok(TokenEndpointAuthMethod::ClientSecretBasic)
        }
        Some(TokenEndpointAuthMethod::ClientSecretPost) => {
            Ok(TokenEndpointAuthMethod::ClientSecretPost)
        }
        Some(TokenEndpointAuthMethod::PrivateKeyJwt) => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        Some(TokenEndpointAuthMethod::None) => Err(ClientManagementError::Validation(
            MessageKey::new("api-client-auth-method-invalid"),
        )),
    }
}

/// Matches the verification keys at registration against the chosen authentication method (ADR-0030).
///
/// Required for `private_key_jwt`, refused otherwise (silently discarding them would tell an admin who thought they
/// registered keys that "it was registered").
fn validate_jwks_for_method(
    method: TokenEndpointAuthMethod,
    raw: Option<&str>,
) -> Result<Option<ClientJwks>, ClientManagementError> {
    match (method, raw) {
        (TokenEndpointAuthMethod::PrivateKeyJwt, Some(raw)) => Ok(Some(parse_jwks(raw)?)),
        (TokenEndpointAuthMethod::PrivateKeyJwt, None) => Err(ClientManagementError::Validation(
            MessageKey::new("api-client-jwks-required"),
        )),
        (_, Some(_)) => Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-jwks-not-applicable",
        ))),
        (_, None) => Ok(None),
    }
}

fn parse_jwks(raw: &str) -> Result<ClientJwks, ClientManagementError> {
    parse_registration_jwks(raw).map_err(|e| ClientManagementError::Validation(e.message_key()))
}

/// Don't give one client two purposes (ADR-0032 decision 3).
///
/// If `client_credentials` and redirect_uri coexist, the screen's "purpose" can't represent that state,
/// and merely opening and saving in the console would silently drop one. By not allowing unrepresentable states,
/// the purpose is uniquely determined by the registration. Separating per purpose also separates revocation scope and audit granularity in incidents.
///
/// **Refused unconditionally on both registration and update.** ADR-0032 had put a grace in `update` that "lets updates
/// through for rows where both already coexist" (otherwise a leaked client couldn't be set to DISABLED),
/// but it was removed on 2026-08-27 after confirming no such rows exist in either prod or stg
/// (ADR-0032 Revised). Keeping the grace would keep the check dependent on "the current shape".
fn validate_single_usage(
    allows_client_credentials: bool,
    redirect_uris: &[String],
) -> Result<(), ClientManagementError> {
    if allows_client_credentials && !redirect_uris.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-usage-conflict",
        )));
    }
    Ok(())
}

/// Decides the set of grant_types given to a client (G4).
///
/// `authorization_code` is the basic permission shared by all clients. `client_credentials` is added only for confidential
/// clients when an admin explicitly enables it (not added for public clients even if requested). `refresh_token`
/// is controlled by consent to the `offline_access` scope and not narrowed by grant_types (as before).
fn grant_types_for(
    client_type: ClientType,
    allow_client_credentials: bool,
    has_redirect_uris: bool,
) -> Vec<String> {
    let mut grants = Vec::new();
    // The authorization flow can't work for a client without redirect_uri (`/authorize` matches the requested
    // redirect_uri against the registered values). Adding it would only leave an unusable permission, so it isn't added.
    if has_redirect_uris {
        grants.push(GrantType::AuthorizationCode.as_str().to_string());
    }
    if allow_client_credentials && client_type == ClientType::Confidential {
        grants.push(GrantType::ClientCredentials.as_str().to_string());
    }
    grants
}

fn validate_app_name(app_name: String) -> Result<String, ClientManagementError> {
    let trimmed = app_name.trim().to_string();
    if trimmed.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-app-name-empty",
        )));
    }
    Ok(trimmed)
}

/// Validates redirect URIs. At least one, no duplicates, and each URI satisfies the constraints of §2.3.
fn validate_redirect_uris(
    uris: &[String],
    system_client: bool,
) -> Result<Vec<String>, ClientManagementError> {
    if uris.is_empty() {
        // Allowing empty for non-system clients would create "a client that can do nothing", usable for neither
        // the authorization flow nor `client_credentials`.
        return if system_client {
            Ok(Vec::new())
        } else {
            Err(ClientManagementError::Validation(MessageKey::new(
                "api-client-redirect-uris-empty",
            )))
        };
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        validate_redirect_uri(uri)?;
        if !seen.insert(uri.as_str()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                "api-client-redirect-uri-duplicate",
                uri,
            )));
        }
        out.push(uri.clone());
    }
    Ok(out)
}

/// Bundle of translation keys for validation errors per URI kind.
///
/// `MessageKey` keys are limited to static strings (dynamic keys silently increase missing translations), so
/// the validation logic is shared while only the wording is swapped per kind.
struct UriMessageKeys {
    invalid: &'static str,
    scheme: &'static str,
    fragment: &'static str,
    wildcard: &'static str,
    duplicate: &'static str,
}

const REDIRECT_URI_KEYS: UriMessageKeys = UriMessageKeys {
    invalid: "api-client-redirect-uri-invalid",
    scheme: "api-client-redirect-uri-scheme",
    fragment: "api-client-redirect-uri-fragment",
    wildcard: "api-client-redirect-uri-wildcard",
    duplicate: "api-client-redirect-uri-duplicate",
};

/// Key bundle for logout URIs (`post_logout_redirect_uris` / `frontchannel_logout_uri` /
/// `backchannel_logout_uri`).
const LOGOUT_URI_KEYS: UriMessageKeys = UriMessageKeys {
    invalid: "api-client-logout-uri-invalid",
    scheme: "api-client-logout-uri-scheme",
    fragment: "api-client-logout-uri-fragment",
    wildcard: "api-client-logout-uri-wildcard",
    duplicate: "api-client-logout-uri-duplicate",
};

/// Constraints on a single redirect URI (design spec §2.3): absolute http(s) URL, no fragment, no wildcard.
fn validate_redirect_uri(uri: &str) -> Result<(), ClientManagementError> {
    validate_absolute_web_uri(uri, &REDIRECT_URI_KEYS).map(|_| ())
}

/// Validates absolute http(s) URL, no fragment, no wildcard, and returns the parsed URL.
fn validate_absolute_web_uri(
    uri: &str,
    keys: &UriMessageKeys,
) -> Result<url::Url, ClientManagementError> {
    if uri.contains('*') {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.wildcard,
            uri,
        )));
    }
    let parsed = url::Url::parse(uri).map_err(|_| {
        ClientManagementError::Validation(MessageKey::with_value(keys.invalid, uri))
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.scheme,
            uri,
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            keys.fragment,
            uri,
        )));
    }
    Ok(parsed)
}

/// Validates `post_logout_redirect_uris` (SEC2). Zero entries are allowed (feature not used).
///
/// They are browser redirect destinations with the same risks as `redirect_uris` (open redirect,
/// scheme abuse), so the same constraints apply.
fn validate_post_logout_redirect_uris(
    uris: &[String],
) -> Result<Vec<String>, ClientManagementError> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(uris.len());
    for uri in uris {
        let uri = uri.trim();
        if uri.is_empty() {
            continue;
        }
        validate_absolute_web_uri(uri, &LOGOUT_URI_KEYS)?;
        if !seen.insert(uri.to_string()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                LOGOUT_URI_KEYS.duplicate,
                uri,
            )));
        }
        out.push(uri.to_string());
    }
    Ok(out)
}

/// Validates `frontchannel_logout_uri` (SEC2). An empty string is treated as "not set".
///
/// It is a URL the browser loads in an iframe, so the same constraints as redirect destinations suffice
/// (the IdP's server doesn't connect to it, so it's not SSRF).
fn validate_frontchannel_logout_uri(
    uri: Option<String>,
) -> Result<Option<String>, ClientManagementError> {
    let Some(uri) = uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    validate_absolute_web_uri(&uri, &LOGOUT_URI_KEYS)?;
    Ok(Some(uri))
}

/// Validates `backchannel_logout_uri` (SEC2). An empty string is treated as "not set".
///
/// **It is the only outbound URI the api POSTs to from the server side**, and if a tenant admin could register any
/// destination it would be an authenticated blind SSRF (reaching cloud metadata or internal admin APIs).
/// In addition to the same format constraints as redirect destinations, address literals such as private, loopback
/// and link-local are refused.
///
/// Note this is a check at registration time and can't prevent reaching internal addresses via DNS resolution
/// (including DNS rebinding). Deployments that need it closed should also use egress control at the front proxy.
fn validate_backchannel_logout_uri(
    uri: Option<String>,
) -> Result<Option<String>, ClientManagementError> {
    let Some(uri) = uri.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    validate_absolute_web_uri(&uri, &LOGOUT_URI_KEYS)?;
    if is_internal_destination(&uri) {
        return Err(ClientManagementError::Validation(MessageKey::with_value(
            "api-client-backchannel-logout-uri-internal-host",
            &uri,
        )));
    }
    Ok(Some(uri))
}

/// Validates scopes. At least one, only known OIDC scopes, including `openid`, and no duplicates.
fn validate_scopes(scopes: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if scopes.is_empty() {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-scopes-empty",
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for scope in scopes {
        Scope::parse(scope).map_err(|_| {
            ClientManagementError::Validation(MessageKey::with_value(
                "api-client-scope-unsupported",
                scope,
            ))
        })?;
        if !seen.insert(scope.as_str()) {
            return Err(ClientManagementError::Validation(MessageKey::with_value(
                "api-client-scope-duplicate",
                scope,
            )));
        }
    }
    if !scopes.iter().any(|s| s == Scope::OpenId.as_str()) {
        return Err(ClientManagementError::Validation(MessageKey::new(
            "api-client-scopes-missing-openid",
        )));
    }
    Ok(scopes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_redirect_uris() {
        assert!(validate_redirect_uri("https://app.example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/cb").is_ok());
    }

    #[test]
    fn rejects_bad_redirect_uris() {
        assert!(validate_redirect_uri("https://app.example.com/cb#frag").is_err());
        assert!(validate_redirect_uri("https://app.example.com/*").is_err());
        assert!(validate_redirect_uri("ftp://app.example.com/cb").is_err());
        assert!(validate_redirect_uri("not-a-url").is_err());
        assert!(validate_redirect_uri("/relative/path").is_err());
    }

    #[test]
    fn rejects_empty_and_duplicate_redirect_uris() {
        // Clients doing user login need at least one (the authorization flow can't work with none).
        assert!(validate_redirect_uris(&[], false).is_err());
        assert!(validate_redirect_uris(
            &[
                "https://a.example.com/cb".to_string(),
                "https://a.example.com/cb".to_string(),
            ],
            false
        )
        .is_err());
    }

    /// ADR-0032: system clients (no user) have no browser redirect destination, so empty is allowed.
    #[test]
    fn system_clients_may_omit_redirect_uris() {
        assert_eq!(
            validate_redirect_uris(&[], true).expect("empty is ok"),
            Vec::<String>::new()
        );
        // The exception only "allows empty"; checks on specified URIs aren't loosened.
        assert!(validate_redirect_uris(&["not-a-url".to_string()], true).is_err());
    }

    /// ADR-0032 decision 3: don't give one client two purposes.
    #[test]
    fn a_client_cannot_be_both_a_login_client_and_a_system_client() {
        let uris = vec!["https://a.example.com/cb".to_string()];
        // User-login-only and system-only pass.
        assert!(validate_single_usage(false, &uris).is_ok());
        assert!(validate_single_usage(true, &[]).is_ok());
        // Both together are refused —— don't allow a state the screen's "purpose" can't represent.
        assert!(validate_single_usage(true, &uris).is_err());
    }

    /// grant_types are derived from "what can actually be done" (ADR-0032).
    #[test]
    fn grant_types_follow_what_the_client_can_actually_do() {
        // User login only.
        assert_eq!(
            grant_types_for(ClientType::Confidential, false, true),
            vec!["authorization_code".to_string()]
        );
        // System only —— no redirect_uri, so `authorization_code` isn't added.
        assert_eq!(
            grant_types_for(ClientType::Confidential, true, false),
            vec!["client_credentials".to_string()]
        );
        // Both.
        assert_eq!(
            grant_types_for(ClientType::Confidential, true, true),
            vec![
                "authorization_code".to_string(),
                "client_credentials".to_string()
            ]
        );
        // Public clients can't keep secrets, so `client_credentials` isn't added even if allowed.
        assert_eq!(
            grant_types_for(ClientType::Public, true, true),
            vec!["authorization_code".to_string()]
        );
    }

    #[test]
    fn scopes_must_be_known_include_openid_and_unique() {
        assert!(validate_scopes(&["openid".to_string(), "email".to_string()]).is_ok());
        assert!(validate_scopes(&["email".to_string()]).is_err()); // no openid
        assert!(validate_scopes(&["openid".to_string(), "admin".to_string()]).is_err()); // unknown
        assert!(validate_scopes(&["openid".to_string(), "openid".to_string()]).is_err()); // duplicate
        assert!(validate_scopes(&[]).is_err());
    }

    #[test]
    fn app_name_is_trimmed_and_non_empty() {
        assert_eq!(validate_app_name("  App  ".to_string()).unwrap(), "App");
        assert!(validate_app_name("   ".to_string()).is_err());
    }

    // ── SEC2: validating logout URIs ────────────────────────────────────────

    #[test]
    fn post_logout_redirect_uris_follow_the_redirect_uri_rules() {
        // Zero entries mean "feature not used", so allowed. Empty strings are ignored.
        assert!(validate_post_logout_redirect_uris(&[]).unwrap().is_empty());
        assert!(validate_post_logout_redirect_uris(&["  ".to_string()])
            .unwrap()
            .is_empty());

        assert_eq!(
            validate_post_logout_redirect_uris(&[
                " https://app.example.com/after-logout ".to_string()
            ])
            .unwrap(),
            vec!["https://app.example.com/after-logout".to_string()]
        );

        for bad in [
            "https://app.example.com/x#frag",
            "https://app.example.com/*",
            "javascript:alert(1)",
            "not-a-url",
        ] {
            assert!(
                validate_post_logout_redirect_uris(&[bad.to_string()]).is_err(),
                "{bad} must be rejected"
            );
        }
        assert!(validate_post_logout_redirect_uris(&[
            "https://a.example.com/out".to_string(),
            "https://a.example.com/out".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn frontchannel_logout_uri_is_validated_and_empty_means_unset() {
        assert_eq!(validate_frontchannel_logout_uri(None).unwrap(), None);
        assert_eq!(
            validate_frontchannel_logout_uri(Some("  ".to_string())).unwrap(),
            None
        );
        assert_eq!(
            validate_frontchannel_logout_uri(Some("https://app.example.com/fc".to_string()))
                .unwrap(),
            Some("https://app.example.com/fc".to_string())
        );
        assert!(validate_frontchannel_logout_uri(Some("file:///etc/passwd".to_string())).is_err());
        // The browser only loads it, so even a private destination isn't SSRF (not refused).
        assert!(
            validate_frontchannel_logout_uri(Some("http://127.0.0.1:9000/fc".to_string())).is_ok()
        );
    }

    #[test]
    fn backchannel_logout_uri_rejects_internal_destinations() {
        assert_eq!(validate_backchannel_logout_uri(None).unwrap(), None);
        assert_eq!(
            validate_backchannel_logout_uri(Some("https://rp.example.com/bc".to_string())).unwrap(),
            Some("https://rp.example.com/bc".to_string())
        );
        // Dotless names (service names on the same network) are recognizably internal, so refused (task #585).
        assert!(validate_backchannel_logout_uri(Some("http://rp:3000/bc".to_string())).is_err());

        for bad in [
            // Cloud instance metadata (link-local).
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/internal",
            "http://localhost/internal",
            "http://app.LOCALHOST/internal",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/admin",
            "http://100.64.0.1/admin",
            "http://0.0.0.0/",
            "http://[::1]/internal",
            "http://[fd00::1]/internal",
            "http://[fe80::1]/internal",
            "http://[::ffff:127.0.0.1]/internal",
        ] {
            assert!(
                validate_backchannel_logout_uri(Some(bad.to_string())).is_err(),
                "{bad} must be rejected as an internal destination"
            );
        }
    }
}
