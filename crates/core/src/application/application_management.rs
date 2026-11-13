//! App management (registration, stopping, bindings, user assignment) (ADR-0054).
//!
//! It is a separate service from client management (`client_management`) because **they deal with different layers**.
//! That one holds "how to connect via OIDC"; this one holds "what app it is to users, and
//! who may use it". Mixing them would make a SAML branch sprout inside client management the day
//! SAML is added.
//!
//! Decisions are made in this Application layer and only results go to Presentation (CLAUDE.md "Permission management").

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::account::{AccountLocator, AccountRef};
use crate::domain::admin_actor::AdminActor;
use crate::domain::application::{
    validate_display_name, Application, ApplicationAccess, ApplicationAssignment,
    ApplicationBinding, AssignedServiceAccount, AssignedUser, BindingTarget,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::repositories::{
    ApplicationRepository, ClientRepository, ProtectedResourceRepository,
    SamlServiceProviderRepository, TenantMemberQuery,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::{TenantMember, TenantMemberFilter};
use crate::domain::values::{ApplicationStatus, AssignmentMode, GrantType};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Read limit when listing "people who can get in now".
///
/// ⚠ **Cutting off here leaves the roster incomplete.** It is the copy source when switching from "everyone" to "individual",
/// so when exceeded, it is not cut silently: [`CurrentUsers::truncated`] is set to tell the screen.
pub const MAX_CURRENT_USERS: i64 = 500;

#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationManagementError {
    /// The app, binding or user does not exist in the requested tenant.
    NotFound,
    /// Invalid input (display name empty or too long etc.).
    Invalid(MessageKey),
    /// That counterparty is already another app's identity (the inserted value is that app's display name).
    Conflict(MessageKey),
    Internal(String),
}

/// One list row (app + aggregates the screen needs).
///
/// Counting happens here so that **the whole roster need not be read just to show a head count on screen**.
pub struct ApplicationSummary {
    pub application: Application,
    /// Connected authentication methods (with display names).
    pub bindings: Vec<BindingSummary>,
    /// Number assigned. `EVERYONE` apps have no rows, so it is 0 (the screen varies by mode).
    pub assigned_count: i64,
}

/// Shape for showing one identity on screen.
pub struct BindingSummary {
    pub binding: ApplicationBinding,
    /// The value people recognize. `clients.client_id` for login and service accounts, `entity_id` for SAML,
    /// `resource_uri` for an audience. `None` if the counterparty is gone.
    pub identifier: Option<String>,
    /// The counterparty's registered name (`clients.app_name` / `display_name` of the SP or audience).
    pub display_name: Option<String>,
}

/// An identity to add (interpretation of the admin API request; ADR-0059).
///
/// Counterparties are referenced by **values people know** (`client_id`, the audience URI). Only SAML SPs are
/// referenced by internal ID, because `entity_id` is URL-shaped and awkward in a path (as in ADR-0054).
pub enum NewBinding {
    /// An OIDC client for login (`authorization_code`).
    Oidc { client_id: String },
    /// A SAML SP.
    Saml { service_provider_id: Uuid },
    /// A service account (a client with only `client_credentials`).
    ServiceAccount { client_id: String },
    /// The audience (`aud`) of the app's API.
    Resource { resource_uri: String },
}

/// One identity candidate (ADR-0067). One row of the list the screen uses to "pick a counterparty".
///
/// Candidates are picked from **everything registered in the tenant** that fits the kind (login =
/// `authorization_code` clients, service account = clients with only `client_credentials`, SAML SPs,
/// audiences). Kind matching uses the same predicate as [`ApplicationManagementService::bind`],
/// so nothing appears as a candidate that cannot then be bound.
pub struct BindingCandidate {
    pub target: BindingTarget,
    /// Value sent when binding (the counterparty of [`NewBinding`]). `client_id` for login and service
    /// accounts, the SP's internal ID for SAML, the URI for an audience.
    pub reference: String,
    /// The value people recognize (`client_id`, `entity_id`, the audience URI).
    pub identifier: String,
    /// The counterparty's registered name (`clients.app_name` / `display_name` of the SP or audience).
    pub display_name: String,
    /// The app that currently holds this counterparty as an identity (`None` if it belongs nowhere).
    /// ⚠ When picked, this is what the "move from this app" confirmation is based on.
    pub owner: Option<Application>,
}

/// App details (identities and the principals that use it).
pub struct ApplicationDetail {
    pub application: Application,
    pub bindings: Vec<BindingSummary>,
    /// Assigned people.
    pub assigned: Vec<AssignedUser>,
    /// Assigned service accounts (decision 5 of ADR-0059).
    pub assigned_service_accounts: Vec<AssignedServiceAccount>,
}

/// A principal to assign (interpretation of the admin API request; decision 5 of ADR-0059).
///
/// People are referenced by internal ID, service accounts by `client_id` (a value people know).
pub enum NewAssignment {
    User { user_id: Uuid },
    ServiceAccount { client_id: String },
}

/// "People who can get in now": the copy source before switching `EVERYONE` to `INDIVIDUAL`.
pub struct CurrentUsers {
    pub members: Vec<TenantMember>,
    /// Total head count (before cutting at [`MAX_CURRENT_USERS`]).
    pub total: i64,
    /// Whether it was cut at the limit. ⚠ **If set, the screen must say "not everyone could be shown".**
    pub truncated: bool,
}

/// One app seen from one account (ADR-0063 / ADR-0065).
pub struct AccountApplication {
    pub application: Application,
    /// Whether this account can use it now. Decided by the same rule as the decision (code issuance for people,
    /// token issuance for service accounts): ⚠ if the screen answered by a different rule, "shown as usable but cannot get in" would happen.
    pub access: ApplicationAccess,
    /// The date and time of an individual assignment, if any. Shown even for `EVERYONE` apps if the row remains.
    pub assigned_at: Option<DateTime<Utc>>,
}

/// Input for a new app.
pub struct NewApplication {
    pub display_name: String,
    /// ⚠ The default is [`AssignmentMode::Individual`] (decision 3 of ADR-0054). The caller states it explicitly.
    pub assignment_mode: AssignmentMode,
    /// Whether to assign the creator at the same time. ⚠ **The screen has it checked from the start**:
    /// right after creating an "individual" app nobody can get in, so the creator must not end up locked out.
    pub assign_creator: bool,
}

pub struct ApplicationManagementService {
    applications: Arc<dyn ApplicationRepository>,
    clients: Arc<dyn ClientRepository>,
    service_providers: Arc<dyn SamlServiceProviderRepository>,
    resources: Arc<dyn ProtectedResourceRepository>,
    members: Arc<dyn TenantMemberQuery>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl ApplicationManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applications: Arc<dyn ApplicationRepository>,
        clients: Arc<dyn ClientRepository>,
        service_providers: Arc<dyn SamlServiceProviderRepository>,
        resources: Arc<dyn ProtectedResourceRepository>,
        members: Arc<dyn TenantMemberQuery>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            applications,
            clients,
            service_providers,
            resources,
            members,
            audit,
            clock,
            ids,
        }
    }

    /// Lists apps (ascending display name).
    pub async fn list(
        &self,
        tenant: TenantContext,
    ) -> Result<Vec<ApplicationSummary>, ApplicationManagementError> {
        let applications = self
            .applications
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)?;
        // Clients are read **only once**. Re-fetching per binding would scan apps x clients
        // (growing quadratically as apps increase).
        let clients = self
            .clients
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)?;
        let mut summaries = Vec::with_capacity(applications.len());
        for application in applications {
            let bindings = self
                .summarize_bindings(tenant, application.id, &clients)
                .await?;
            let assigned_count = self
                .applications
                .count_assignments(application.id)
                .await
                .map_err(map_repo_error)?;
            summaries.push(ApplicationSummary {
                application,
                bindings,
                assigned_count,
            });
        }
        Ok(summaries)
    }

    /// List of apps one account can use (ascending display name; ADR-0063 / ADR-0065).
    ///
    /// What "use" means differs by kind, so which apps are listed and the eligibility rule are decided by kind too:
    ///
    /// | Kind | Apps listed | Eligibility |
    /// |---|---|---|
    /// | Person | those with a login identity (OIDC / SAML) | [`Application::admits`] (same as code issuance) |
    /// | Service account | those with an audience (`resource`) identity | [`Application::admits_service_account`] (same as token issuance) |
    ///
    /// Apps without an identity are not destinations for that kind: listing them as "unusable" would mislead.
    pub async fn account_applications(
        &self,
        tenant: TenantContext,
        account: AccountLocator<'_>,
    ) -> Result<Vec<AccountApplication>, ApplicationManagementError> {
        let account = match account {
            AccountLocator::User { user_id } => {
                self.require_member(tenant, user_id).await?;
                AccountRef::User { user_id }
            }
            AccountLocator::ServiceAccount { client_id } => {
                // Integrations (login clients) are not "this tenant's service accounts" (deleted ones are
                // dropped by `load_client`).
                let client = self.load_client(tenant, client_id).await?;
                if !client.is_service_account() {
                    return Err(ApplicationManagementError::NotFound);
                }
                AccountRef::ServiceAccount {
                    client_row_id: client.id,
                }
            }
        };
        let applications = self
            .applications
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)?;
        let assignments = self
            .applications
            .list_account_assignments(tenant.tenant_id(), account)
            .await
            .map_err(map_repo_error)?;
        let mut rows = Vec::with_capacity(applications.len());
        for application in applications {
            let bindings = self
                .applications
                .list_bindings(application.id)
                .await
                .map_err(map_repo_error)?;
            let usable = bindings.iter().any(|b| match account {
                AccountRef::User { .. } => matches!(
                    b.target,
                    BindingTarget::Oidc { .. } | BindingTarget::Saml { .. }
                ),
                AccountRef::ServiceAccount { .. } => {
                    matches!(b.target, BindingTarget::Resource { .. })
                }
            });
            if !usable {
                continue;
            }
            let assigned_at = assignments
                .iter()
                .find(|a| a.application_id == application.id)
                .map(|a| a.assigned_at);
            let access = match account {
                AccountRef::User { .. } => application.admits(assigned_at.is_some()),
                AccountRef::ServiceAccount { .. } => {
                    application.admits_service_account(assigned_at.is_some())
                }
            };
            rows.push(AccountApplication {
                application,
                access,
                assigned_at,
            });
        }
        Ok(rows)
    }

    /// Details of one app.
    pub async fn detail(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<ApplicationDetail, ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let clients = self
            .clients
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)?;
        let bindings = self.summarize_bindings(tenant, id, &clients).await?;
        let assigned = self
            .applications
            .list_assigned_users(id)
            .await
            .map_err(map_repo_error)?;
        let assigned_service_accounts = self
            .applications
            .list_assigned_service_accounts(id)
            .await
            .map_err(map_repo_error)?;
        Ok(ApplicationDetail {
            application,
            bindings,
            assigned,
            assigned_service_accounts,
        })
    }

    /// Registers an app.
    pub async fn create(
        &self,
        tenant: TenantContext,
        input: NewApplication,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Application, ApplicationManagementError> {
        let display_name = validate_display_name(&input.display_name)
            .map_err(ApplicationManagementError::Invalid)?;
        let now = self.clock.now();
        let application = Application {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            display_name,
            status: ApplicationStatus::Active,
            assignment_mode: input.assignment_mode,
            created_at: now,
            updated_at: now,
        };
        self.applications
            .create(&application)
            .await
            .map_err(map_repo_error)?;

        self.record(
            AuditEventType::ApplicationRegistered,
            tenant,
            &application,
            actor,
            None,
            ctx,
        )
        .await;

        // Assign the creator. ⚠ Dropping this would make an app that **nobody can get in** right after being
        // created as "individual". A non-human actor (machine) has nobody to assign, so nothing is done.
        if input.assign_creator {
            if let Some(user_id) = actor.user_id() {
                self.assign(
                    tenant,
                    application.id,
                    NewAssignment::User { user_id },
                    actor,
                    ctx,
                )
                .await?;
            }
        }
        Ok(application)
    }

    /// Changes display name, status and assignment mode.
    ///
    /// ⚠ **Whether the roster is non-empty when switching to "individual" is not checked here.** Whether saving it empty
    /// (= letting nobody in) is acceptable is a human decision, so the screen asks for confirmation. Refusing here would
    /// block the legitimate procedure "first stop everyone, then add people one by one".
    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        tenant: TenantContext,
        id: Uuid,
        display_name: &str,
        status: ApplicationStatus,
        assignment_mode: AssignmentMode,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Application, ApplicationManagementError> {
        let display_name =
            validate_display_name(display_name).map_err(ApplicationManagementError::Invalid)?;
        let before = self.load(tenant, id).await?;
        // The returned bool is not used to decide "nonexistent". MySQL's `rows_affected` counts **rows whose values changed**,
        // so an update changing nothing returns 0 and would turn an existing row into a 404.
        self.applications
            .update(
                tenant.tenant_id(),
                id,
                &display_name,
                status,
                assignment_mode,
                self.clock.now(),
            )
            .await
            .map_err(map_repo_error)?;

        let after = self.load(tenant, id).await?;
        self.record(
            AuditEventType::ApplicationUpdated,
            tenant,
            &after,
            actor,
            Some(&format!(
                "status={} mode={} (was status={} mode={})",
                after.status.as_str(),
                after.assignment_mode.as_str(),
                before.status.as_str(),
                before.assignment_mode.as_str()
            )),
            ctx,
        )
        .await;
        Ok(after)
    }

    /// Deletes an app (bindings and assignments go with it).
    ///
    /// ⚠ **The attached `clients` / `saml_service_providers` are not deleted.** An app is
    /// "a grouping as seen by users", not the connection settings themselves. Only the grouping and roster go,
    /// and the RP stays connected (= falls outside the decision).
    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let deleted = self
            .applications
            .delete(tenant.tenant_id(), id)
            .await
            .map_err(map_repo_error)?;
        if !deleted {
            return Err(ApplicationManagementError::NotFound);
        }
        self.record(
            AuditEventType::ApplicationDeleted,
            tenant,
            &application,
            actor,
            None,
            ctx,
        )
        .await;
        Ok(())
    }

    /// Adds an identity (ADR-0059).
    ///
    /// ⚠ **Match the kind against the counterparty's nature.** Binding a `client_credentials` client for login
    /// would let login decisions pass straight through without looking at the app. Conversely, binding a login client
    /// as a service account would let a user's access token read the self roster.
    ///
    /// `move_from` is permission that "if this counterparty is another app's identity, it may be moved from that app"
    /// (ADR-0067). ⚠ **The source app is named explicitly**: accepting only "may move" would, if the owner changed between
    /// confirmation and submission, silently take it from an app that was never confirmed. If the named
    /// app is not the current owner, it refuses with the current owner's name (409).
    pub async fn bind(
        &self,
        tenant: TenantContext,
        id: Uuid,
        request: NewBinding,
        move_from: Option<Uuid>,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ApplicationBinding, ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let (target, identifier) = match request {
            NewBinding::Oidc { client_id } => {
                let client = self.load_client(tenant, &client_id).await?;
                if !client.allows_grant_type(GrantType::AuthorizationCode) {
                    return Err(ApplicationManagementError::Invalid(MessageKey::new(
                        "api-application-binding-oidc-needs-login-client",
                    )));
                }
                (
                    BindingTarget::Oidc {
                        client_row_id: client.id,
                    },
                    client.client_id,
                )
            }
            NewBinding::ServiceAccount { client_id } => {
                let client = self.load_client(tenant, &client_id).await?;
                if !client.is_service_account() {
                    return Err(ApplicationManagementError::Invalid(MessageKey::new(
                        "api-application-binding-needs-service-account",
                    )));
                }
                (
                    BindingTarget::ServiceAccount {
                        client_row_id: client.id,
                    },
                    client.client_id,
                )
            }
            NewBinding::Saml {
                service_provider_id,
            } => {
                let provider = match self
                    .service_providers
                    .find_by_id(tenant.tenant_id(), service_provider_id)
                    .await
                {
                    Ok(Some(provider)) => provider,
                    Ok(None) => return Err(ApplicationManagementError::NotFound),
                    Err(e) => return Err(ApplicationManagementError::Internal(e.to_string())),
                };
                (
                    BindingTarget::Saml {
                        service_provider_id: provider.id,
                    },
                    provider.entity_id,
                )
            }
            NewBinding::Resource { resource_uri } => {
                let resource = match self
                    .resources
                    .find_by_uri(tenant.tenant_id(), resource_uri.trim())
                    .await
                {
                    Ok(Some(resource)) => resource,
                    Ok(None) => return Err(ApplicationManagementError::NotFound),
                    Err(e) => return Err(ApplicationManagementError::Internal(e.to_string())),
                };
                (
                    BindingTarget::Resource {
                        resource_id: resource.id,
                    },
                    resource.resource_uri,
                )
            }
        };
        self.add_binding(
            tenant,
            &application,
            target,
            &identifier,
            move_from,
            actor,
            ctx,
        )
        .await
    }

    /// Identity candidates (ADR-0067). Those already identities of this app are excluded (already bound).
    ///
    /// Ordered by kind (login OIDC, SAML, service account, audience), then ascending display name.
    /// Logically deleted clients are not shown ([`Self::bind`] also treats them as "absent").
    pub async fn binding_candidates(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<Vec<BindingCandidate>, ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let tenant_id = tenant.tenant_id();
        let applications = self
            .applications
            .list(tenant_id)
            .await
            .map_err(map_repo_error)?;
        // Counterparty -> current owner. Read the tenant's bindings once instead of per app.
        let bindings = self
            .applications
            .list_tenant_bindings(tenant_id)
            .await
            .map_err(map_repo_error)?;
        let owner_of = |target: BindingTarget| -> Option<Application> {
            let binding = bindings.iter().find(|b| b.target == target)?;
            applications
                .iter()
                .find(|a| a.id == binding.application_id)
                .cloned()
        };

        let mut login = Vec::new();
        let mut service_accounts = Vec::new();
        for client in self.clients.list(tenant_id).await.map_err(map_repo_error)? {
            if client.is_deleted() {
                continue;
            }
            // Kind matching uses the same predicate as `bind`. ⚠ If one is rewritten, change the other too.
            let target = if client.is_service_account() {
                BindingTarget::ServiceAccount {
                    client_row_id: client.id,
                }
            } else if client.allows_grant_type(GrantType::AuthorizationCode) {
                BindingTarget::Oidc {
                    client_row_id: client.id,
                }
            } else {
                continue;
            };
            let candidate = BindingCandidate {
                target,
                reference: client.client_id.clone(),
                identifier: client.client_id,
                display_name: client.app_name,
                owner: owner_of(target),
            };
            match target {
                BindingTarget::ServiceAccount { .. } => service_accounts.push(candidate),
                _ => login.push(candidate),
            }
        }
        let saml = self
            .service_providers
            .list_for_tenant(tenant_id)
            .await
            .map_err(map_repo_error)?
            .into_iter()
            .map(|provider| {
                let target = BindingTarget::Saml {
                    service_provider_id: provider.id,
                };
                BindingCandidate {
                    target,
                    reference: provider.id.to_string(),
                    identifier: provider.entity_id,
                    display_name: provider.display_name,
                    owner: owner_of(target),
                }
            })
            .collect::<Vec<_>>();
        let resources = self
            .resources
            .list(tenant_id)
            .await
            .map_err(map_repo_error)?
            .into_iter()
            .map(|resource| {
                let target = BindingTarget::Resource {
                    resource_id: resource.id,
                };
                BindingCandidate {
                    target,
                    reference: resource.resource_uri.clone(),
                    identifier: resource.resource_uri,
                    display_name: resource.display_name,
                    owner: owner_of(target),
                }
            })
            .collect::<Vec<_>>();

        let mut candidates = Vec::new();
        for mut group in [login, saml, service_accounts, resources] {
            group.retain(|c| c.owner.as_ref().map(|o| o.id) != Some(application.id));
            group.sort_by(|a, b| {
                a.display_name
                    .cmp(&b.display_name)
                    .then_with(|| a.identifier.cmp(&b.identifier))
            });
            candidates.extend(group);
        }
        Ok(candidates)
    }

    /// Removes a binding.
    pub async fn unbind(
        &self,
        tenant: TenantContext,
        id: Uuid,
        binding_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let removed = self
            .applications
            .remove_binding(id, binding_id)
            .await
            .map_err(map_repo_error)?;
        if !removed {
            return Err(ApplicationManagementError::NotFound);
        }
        self.record(
            AuditEventType::ApplicationBindingRemoved,
            tenant,
            &application,
            actor,
            Some(&format!("binding={binding_id}")),
            ctx,
        )
        .await;
        Ok(())
    }

    /// Assigns a principal (idempotent; decision 5 of ADR-0059).
    ///
    /// - Person: ⚠ **must be a member of the requested tenant.** Do not let other tenants' user ids be brought in
    /// - Service account: ⚠ **must be a client with only `client_credentials`.** Assigning a login client
    ///   does nothing (audience tokens can only be obtained via `client_credentials`), yet on screen
    ///   it would look "usable"
    pub async fn assign(
        &self,
        tenant: TenantContext,
        id: Uuid,
        request: NewAssignment,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let (principal, audit_client_id) = match request {
            NewAssignment::User { user_id } => {
                self.require_member(tenant, user_id).await?;
                (AccountRef::User { user_id }, None)
            }
            NewAssignment::ServiceAccount { client_id } => {
                let client = self.load_client(tenant, &client_id).await?;
                if !client.is_service_account() {
                    return Err(ApplicationManagementError::Invalid(MessageKey::new(
                        "api-application-assignment-needs-service-account",
                    )));
                }
                (
                    AccountRef::ServiceAccount {
                        client_row_id: client.id,
                    },
                    Some(client.client_id),
                )
            }
        };

        self.applications
            .assign(&ApplicationAssignment {
                id: self.ids.new_id(),
                application_id: id,
                principal,
                assigned_at: self.clock.now(),
                assigned_by: actor.user_id(),
            })
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ApplicationAssigned,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                // The `user_id` / `client_id` columns are the **target** principal. The acting principal goes to the reason field.
                principal.user_id(),
                audit_client_id.as_deref(),
                Some(&audit_reason(&application, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Removes a person's assignment (no error even if unassigned).
    pub async fn unassign_user(
        &self,
        tenant: TenantContext,
        id: Uuid,
        user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        self.applications
            .unassign(id, AccountRef::User { user_id })
            .await
            .map_err(map_repo_error)?;
        self.audit
            .record(
                AuditEventType::ApplicationUnassigned,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(&audit_reason(&application, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Removes a service account's assignment (no error even if unassigned).
    ///
    /// ⚠ Logically deleted clients can also be removed (so assignments of deleted clients do not linger on screen).
    pub async fn unassign_service_account(
        &self,
        tenant: TenantContext,
        id: Uuid,
        client_id: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        let client = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id.trim())
            .await
        {
            Ok(Some(client)) => client,
            Ok(None) => return Err(ApplicationManagementError::NotFound),
            Err(e) => return Err(ApplicationManagementError::Internal(e.to_string())),
        };
        self.applications
            .unassign(
                id,
                AccountRef::ServiceAccount {
                    client_row_id: client.id,
                },
            )
            .await
            .map_err(map_repo_error)?;
        self.audit
            .record(
                AuditEventType::ApplicationUnassigned,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                None,
                Some(&client.client_id),
                Some(&audit_reason(&application, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Returns "people who can get in now".
    ///
    /// The **copy source** when switching from "everyone" to "individual". Switching without showing it
    /// would lock everyone out the moment it is saved with an empty roster.
    pub async fn current_users(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<CurrentUsers, ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        match application.assignment_mode {
            // "Everyone" = all members of the tenant. ⚠ Users of other tenants are not included.
            AssignmentMode::Everyone => {
                let page = self
                    .members
                    .search(&TenantMemberFilter {
                        tenant_id: tenant.tenant_id(),
                        user_id: None,
                        search: None,
                        limit: MAX_CURRENT_USERS,
                        offset: 0,
                    })
                    .await
                    .map_err(map_repo_error)?;
                let truncated = page.total > page.members.len() as i64;
                Ok(CurrentUsers {
                    members: page.members,
                    total: page.total,
                    truncated,
                })
            }
            // If already "individual", the copy target is the roster itself. The screen just shows the assignment list.
            AssignmentMode::Individual => Ok(CurrentUsers {
                members: Vec::new(),
                total: 0,
                truncated: false,
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_binding(
        &self,
        tenant: TenantContext,
        application: &Application,
        target: BindingTarget,
        identifier: &str,
        move_from: Option<Uuid>,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ApplicationBinding, ApplicationManagementError> {
        // ⚠ If it is already **another** app's identity, refuse with that app's name. With just "it is connected",
        // people would have to go searching for which app to remove it from. If it is the same app, do nothing (idempotent).
        if let Some(owner) = self
            .applications
            .find_by_binding_target(tenant.tenant_id(), target)
            .await
            .map_err(map_repo_error)?
        {
            if owner.id == application.id {
                if let Some(existing) = self
                    .applications
                    .list_bindings(application.id)
                    .await
                    .map_err(map_repo_error)?
                    .into_iter()
                    .find(|b| b.target == target)
                {
                    return Ok(existing);
                }
            }
            // Move only when the app named as the source is the current owner (ADR-0067).
            if move_from == Some(owner.id) {
                return self
                    .move_binding(tenant, &owner, application, target, identifier, actor, ctx)
                    .await;
            }
            return Err(already_bound(&owner));
        }
        let binding = ApplicationBinding {
            id: self.ids.new_id(),
            application_id: application.id,
            target,
            created_at: self.clock.now(),
        };
        if let Err(e) = self.applications.add_binding(&binding).await {
            // Between our read and write, another request bound the same counterparty.
            if matches!(e, DomainError::Conflict(_)) {
                if let Ok(Some(owner)) = self
                    .applications
                    .find_by_binding_target(tenant.tenant_id(), target)
                    .await
                {
                    return Err(already_bound(&owner));
                }
            }
            return Err(map_repo_error(e));
        }
        self.record(
            AuditEventType::ApplicationBindingAdded,
            tenant,
            application,
            actor,
            Some(&format!(
                "kind={} target={identifier}",
                binding.target.kind()
            )),
            ctx,
        )
        .await;
        Ok(binding)
    }

    /// Moves another app's (`from`) identity to this app (`to`) (ADR-0067).
    ///
    /// ⚠ **Do not split remove + add into two steps.** Failing in between would leave the counterparty in no app, and
    /// for a login counterparty, outside the decision (passing straight through; a consequence of ADR-0054). Reattach in one repository statement.
    /// The audit is also one row (`application_binding.moved`), keeping both the source and the destination.
    #[allow(clippy::too_many_arguments)]
    async fn move_binding(
        &self,
        tenant: TenantContext,
        from: &Application,
        to: &Application,
        target: BindingTarget,
        identifier: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ApplicationBinding, ApplicationManagementError> {
        let existing = self
            .applications
            .list_bindings(from.id)
            .await
            .map_err(map_repo_error)?
            .into_iter()
            .find(|b| b.target == target);
        let now = self.clock.now();
        let moved = match existing {
            Some(binding) => self
                .applications
                .move_binding(binding.id, from.id, to.id, now)
                .await
                .map_err(map_repo_error)?
                .then_some(binding),
            None => None,
        };
        let Some(binding) = moved else {
            // Between reading and moving, another request removed or moved it. Answer again with the current owner
            // (if there is no owner anymore, the request naming a source is stale).
            return match self
                .applications
                .find_by_binding_target(tenant.tenant_id(), target)
                .await
                .map_err(map_repo_error)?
            {
                Some(owner) => Err(already_bound(&owner)),
                None => Err(ApplicationManagementError::Conflict(MessageKey::new(
                    "api-application-conflict",
                ))),
            };
        };
        self.record(
            AuditEventType::ApplicationBindingMoved,
            tenant,
            to,
            actor,
            Some(&format!(
                "kind={} target={identifier} from_application={}",
                target.kind(),
                from.id
            )),
            ctx,
        )
        .await;
        Ok(ApplicationBinding {
            application_id: to.id,
            created_at: now,
            ..binding
        })
    }

    /// Expands identities into the on-screen shape. `clients` is a list the caller read only once
    /// (it only looks up names from `clients.id`, so it is not re-read per binding).
    async fn summarize_bindings(
        &self,
        tenant: TenantContext,
        application_id: Uuid,
        clients: &[Client],
    ) -> Result<Vec<BindingSummary>, ApplicationManagementError> {
        let bindings = self
            .applications
            .list_bindings(application_id)
            .await
            .map_err(map_repo_error)?;
        let mut summaries = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let (identifier, display_name) = match binding.target {
                BindingTarget::Oidc { client_row_id }
                | BindingTarget::ServiceAccount { client_row_id } => clients
                    .iter()
                    .find(|c| c.id == client_row_id)
                    .map(|c| (Some(c.client_id.clone()), Some(c.app_name.clone())))
                    .unwrap_or((None, None)),
                BindingTarget::Saml {
                    service_provider_id,
                } => match self
                    .service_providers
                    .find_by_id(tenant.tenant_id(), service_provider_id)
                    .await
                    .map_err(map_repo_error)?
                {
                    Some(sp) => (Some(sp.entity_id), Some(sp.display_name)),
                    None => (None, None),
                },
                BindingTarget::Resource { resource_id } => match self
                    .resources
                    .find_by_id(tenant.tenant_id(), resource_id)
                    .await
                    .map_err(map_repo_error)?
                {
                    Some(resource) => (Some(resource.resource_uri), Some(resource.display_name)),
                    None => (None, None),
                },
            };
            summaries.push(BindingSummary {
                binding,
                identifier,
                display_name,
            });
        }
        Ok(summaries)
    }

    /// Resolves a client in the requested tenant by `client_id`.
    async fn load_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ApplicationManagementError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id.trim())
            .await
        {
            // Logically deleted (ADR-0035) is treated as "absent". Connecting a supposedly deleted client to a new app
            // would bring along an unknown app's identity if it were revived.
            Ok(Some(client)) if !client.is_deleted() => Ok(client),
            Ok(_) => Err(ApplicationManagementError::NotFound),
            Err(e) => Err(ApplicationManagementError::Internal(e.to_string())),
        }
    }

    async fn require_member(
        &self,
        tenant: TenantContext,
        user_id: Uuid,
    ) -> Result<(), ApplicationManagementError> {
        let page = self
            .members
            .search(&TenantMemberFilter {
                tenant_id: tenant.tenant_id(),
                user_id: Some(user_id),
                search: None,
                limit: 1,
                offset: 0,
            })
            .await
            .map_err(map_repo_error)?;
        if page.members.is_empty() {
            return Err(ApplicationManagementError::NotFound);
        }
        Ok(())
    }

    async fn load(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<Application, ApplicationManagementError> {
        match self.applications.find_by_id(tenant.tenant_id(), id).await {
            Ok(Some(application)) => Ok(application),
            Ok(None) => Err(ApplicationManagementError::NotFound),
            Err(e) => Err(ApplicationManagementError::Internal(e.to_string())),
        }
    }

    async fn record(
        &self,
        event: AuditEventType,
        tenant: TenantContext,
        application: &Application,
        actor: &AdminActor,
        extra: Option<&str>,
        ctx: &RequestContext,
    ) {
        let reason = match extra {
            Some(extra) => format!("{} {extra}", audit_reason(application, actor)),
            None => audit_reason(application, actor),
        };
        self.audit
            .record(
                event,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&reason),
                ctx,
            )
            .await;
    }
}

/// `reason` of the audit log (no PII).
///
/// Carries the **id**, not the display name. Names change later, and the moment they change past rows would no longer link up.
fn audit_reason(application: &Application, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("application={} {note}", application.id),
        None => format!("application={}", application.id),
    }
}

/// "Already the identity of ○○".
fn already_bound(owner: &Application) -> ApplicationManagementError {
    ApplicationManagementError::Conflict(MessageKey::with_value(
        "api-application-binding-conflict",
        owner.display_name.clone(),
    ))
}

fn map_repo_error(e: DomainError) -> ApplicationManagementError {
    match e {
        // A conflict where the counterparty's app name could not be looked up (the named guidance comes from `already_bound`).
        DomainError::Conflict(_) => {
            ApplicationManagementError::Conflict(MessageKey::new("api-application-conflict"))
        }
        DomainError::InvalidValue(_) => {
            ApplicationManagementError::Invalid(MessageKey::new("api-application-invalid"))
        }
        DomainError::NotFound => ApplicationManagementError::NotFound,
        other => ApplicationManagementError::Internal(other.to_string()),
    }
}
