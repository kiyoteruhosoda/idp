//! Decides "may this user use this app" (ADR-0054).
//!
//! # The decision comes **after** authentication
//!
//! Who it is is unknown until authentication, so the assignment decision comes after it. This is not an
//! implementation convenience but a necessity of order, which is why refusals are shown on assay's screen instead
//! of returning to the RP: to the user it is "I got in and was then kicked out", and a silent rejection is indistinguishable from an outage.
//!
//! # Staged rollout (`APPLICATION_ASSIGNMENT_ENFORCEMENT`)
//!
//! Do not refuse right away. First ship to production with `record_only` and accumulate "people who came without an
//! assignment" in the audit log (every migration gap shows up here). Switch to `enforce` once the log is quiet.
//! ⚠ **Switch by setting, not by code.** Swapping code would need a deploy to roll back.
//!
//! The setting is **decided by the tenant** (ADR-0058 §4). Tenants whose rosters are ready can move to `enforce`.
//! ⚠ The value is looked up for the tenant on every use ([`EffectiveTenantSettings`]). Reading the startup `Config`
//! would make every tenant run on the global value.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::application::{Application, ApplicationAccess, BindingTarget};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::ApplicationRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use std::sync::Arc;
use uuid::Uuid;

/// Decision result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationGate {
    /// May pass.
    Allowed,
    /// Refuse (returned only under `enforce`). Holds the app name for display on screen.
    Denied {
        application_name: String,
        access: ApplicationAccess,
    },
}

impl ApplicationGate {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

pub struct ApplicationAccessService {
    applications: Arc<dyn ApplicationRepository>,
    audit: Arc<AuditService>,
    settings: Arc<dyn EffectiveTenantSettings>,
}

impl ApplicationAccessService {
    pub fn new(
        applications: Arc<dyn ApplicationRepository>,
        audit: Arc<AuditService>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            applications,
            audit,
            settings,
        }
    }

    /// Resolves the app from the OIDC `client_id`.
    ///
    /// Used both by authentication policy targets (`conditions.application_ids`) and by [`Self::check`] below.
    /// A client without a binding yet is `None`: it is pre-migration or a migration gap, not "no assignment".
    pub async fn resolve_for_oidc_client(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>, DomainError> {
        self.applications
            .find_by_oidc_client_id(tenant_id, client_id)
            .await
    }

    /// Returns only the resolved app's id (a thin route for authentication policy evaluation).
    ///
    /// A client without an app is `None`. Policies with `conditions.application_ids` **do not match**
    /// (per the existing rule that conditions without evaluation input fall to "no match").
    pub async fn policy_target_for_oidc_client(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Uuid>, DomainError> {
        Ok(self
            .resolve_for_oidc_client(tenant_id, client_id)
            .await?
            .map(|application| application.id))
    }

    /// Resolves the app from a SAML SP (`application_bindings.kind = 'saml'`).
    ///
    /// Looked up by the SP's **row id**, not the entityID. The SP is re-fetched by id right before issuance
    /// (`SamlSsoService::resume`), so using the same key avoids mix-ups even if the entityID is rewritten mid-flow.
    /// An SP without a binding is `None`, as with OIDC (pre-migration or a migration gap).
    pub async fn resolve_for_saml_service_provider(
        &self,
        tenant_id: TenantId,
        service_provider_id: Uuid,
    ) -> Result<Option<Application>, DomainError> {
        self.applications
            .find_by_binding_target(
                tenant_id,
                BindingTarget::Saml {
                    service_provider_id,
                },
            )
            .await
    }

    /// Decides for an OIDC RP and, if needed, leaves one audit log row (called where codes are issued).
    pub async fn check(
        &self,
        tenant_id: TenantId,
        client_id: &str,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> ApplicationGate {
        let application = self.resolve_for_oidc_client(tenant_id, client_id).await;
        self.judge(tenant_id, application, client_id, user_id, ctx)
            .await
    }

    /// Decides for a SAML SP (called where assertions are issued; decision 6 of ADR-0054).
    ///
    /// Rules, audit and staged rollout are exactly as with OIDC. The audit row's counterparty column holds the SP's
    /// entityID (the same value as `saml_response.issued`, so they can be matched with the same query).
    pub async fn check_saml(
        &self,
        tenant_id: TenantId,
        service_provider_id: Uuid,
        sp_entity_id: &str,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> ApplicationGate {
        let application = self
            .resolve_for_saml_service_provider(tenant_id, service_provider_id)
            .await;
        self.judge(tenant_id, application, sp_entity_id, user_id, ctx)
            .await
    }

    /// Decides for the resolved app and, if needed, leaves one audit log row.
    ///
    /// `party` is the counterparty name put in the audit row and structured log (`client_id` for OIDC, entityID for SAML).
    ///
    /// **If the app cannot be resolved, let it pass.** Treating pre-migration or migration-gap clients the same as
    /// "no assignment" would make misses look like "correctly refused" (a consequence of ADR-0054).
    ///
    /// Query failures (DB outage) also pass. **Locking everyone out** when the gatekeeper fails is out of proportion to
    /// what this gate protects; a warning goes to the structured log.
    async fn judge(
        &self,
        tenant_id: TenantId,
        application: Result<Option<Application>, DomainError>,
        party: &str,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> ApplicationGate {
        let application = match application {
            Ok(Some(application)) => application,
            Ok(None) => {
                tracing::debug!(
                    party = %party,
                    "relying party is not bound to an application; assignment check skipped"
                );
                return ApplicationGate::Allowed;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    party = %party,
                    "failed to resolve the application for an assignment check"
                );
                return ApplicationGate::Allowed;
            }
        };

        let assigned = if application.needs_assignment_lookup() {
            match self.applications.is_assigned(application.id, user_id).await {
                Ok(assigned) => assigned,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        application_id = %application.id,
                        "failed to read an application assignment"
                    );
                    return ApplicationGate::Allowed;
                }
            }
        } else {
            false
        };

        let access = application.admits(assigned);
        if access.is_allowed() {
            return ApplicationGate::Allowed;
        }

        // Fetch the setting only once it comes to refusing (no extra query for the majority that pass straight through).
        // If it cannot be fetched, fall to "record only": like the query failure above, do not lock everyone out
        // when the gatekeeper fails.
        let enforcement = match self.settings.assignment_enforcement(tenant_id).await {
            Ok(enforcement) => enforcement,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to resolve APPLICATION_ASSIGNMENT_ENFORCEMENT; recording only"
                );
                AssignmentEnforcement::RecordOnly
            }
        };

        // `record_only` is recorded as success (= passed). To count before and after the switch with the same query,
        // the kind is not split; `result` is.
        let enforced = enforcement == AssignmentEnforcement::Enforce;
        self.audit
            .record(
                AuditEventType::ApplicationAccessDenied,
                if enforced {
                    AuditResult::Failure
                } else {
                    AuditResult::Success
                },
                Some(tenant_id),
                Some(user_id),
                Some(party),
                Some(&format!(
                    "application={} reason={} enforcement={}",
                    application.id,
                    access.reason(),
                    enforcement.as_str()
                )),
                ctx,
            )
            .await;

        if enforced {
            ApplicationGate::Denied {
                application_name: application.display_name,
                access,
            }
        } else {
            // The record-only period. The number passing here is exactly "the migration gap".
            tracing::warn!(
                application_id = %application.id,
                reason = access.reason(),
                "application access would have been denied (record-only)"
            );
            ApplicationGate::Allowed
        }
    }
}

#[cfg(test)]
pub mod test_support {
    //! A test implementation without the decision entry point.
    //!
    //! `CodeIssuanceService` always holds a decider, but many tests around code issuance do not care about
    //! app assignment. So a single implementation where "there are no apps" = **the decision passes through**
    //! lives here, so each test does not copy its own empty implementation.

    use super::*;
    use crate::domain::account::AccountRef;
    use crate::domain::application::{
        ApplicationAssignment, ApplicationBinding, AssignedServiceAccount, AssignedUser,
        BindingTarget,
    };
    use crate::domain::error::Result;
    use crate::domain::values::{ApplicationStatus, AssignmentMode};
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};

    /// A repository with no apps (every query returns empty).
    pub struct NoApplications;

    #[async_trait]
    impl ApplicationRepository for NoApplications {
        async fn create(&self, _application: &Application) -> Result<()> {
            Ok(())
        }
        async fn find_by_id(&self, _tenant_id: TenantId, _id: Uuid) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn find_by_oidc_client_id(
            &self,
            _tenant_id: TenantId,
            _client_id: &str,
        ) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn find_by_saml_entity_id(
            &self,
            _tenant_id: TenantId,
            _entity_id: &str,
        ) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn find_by_binding_target(
            &self,
            _tenant_id: TenantId,
            _target: BindingTarget,
        ) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn list(&self, _tenant_id: TenantId) -> Result<Vec<Application>> {
            Ok(Vec::new())
        }
        async fn update(
            &self,
            _tenant_id: TenantId,
            _id: Uuid,
            _display_name: &str,
            _status: ApplicationStatus,
            _assignment_mode: AssignmentMode,
            _updated_at: DateTime<Utc>,
        ) -> Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _tenant_id: TenantId, _id: Uuid) -> Result<bool> {
            Ok(false)
        }
        async fn list_bindings(&self, _application_id: Uuid) -> Result<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn add_binding(&self, _binding: &ApplicationBinding) -> Result<()> {
            Ok(())
        }
        async fn remove_binding(&self, _application_id: Uuid, _binding_id: Uuid) -> Result<bool> {
            Ok(false)
        }
        async fn move_binding(
            &self,
            _binding_id: Uuid,
            _from_application_id: Uuid,
            _to_application_id: Uuid,
            _moved_at: DateTime<Utc>,
        ) -> Result<bool> {
            Ok(false)
        }
        async fn list_tenant_bindings(
            &self,
            _tenant_id: TenantId,
        ) -> Result<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn is_assigned(&self, _application_id: Uuid, _user_id: Uuid) -> Result<bool> {
            Ok(false)
        }
        async fn is_service_account_assigned(
            &self,
            _application_id: Uuid,
            _client_row_id: Uuid,
        ) -> Result<bool> {
            Ok(false)
        }
        async fn list_assigned_service_accounts(
            &self,
            _application_id: Uuid,
        ) -> Result<Vec<AssignedServiceAccount>> {
            Ok(Vec::new())
        }
        async fn list_assigned_users(&self, _application_id: Uuid) -> Result<Vec<AssignedUser>> {
            Ok(Vec::new())
        }
        async fn list_account_assignments(
            &self,
            _tenant_id: TenantId,
            _account: crate::domain::account::AccountRef,
        ) -> Result<Vec<crate::domain::application::AccountAssignment>> {
            Ok(Vec::new())
        }
        async fn count_assignments(&self, _application_id: Uuid) -> Result<i64> {
            Ok(0)
        }
        async fn assign(&self, _assignment: &ApplicationAssignment) -> Result<()> {
            Ok(())
        }
        async fn unassign(&self, _application_id: Uuid, _principal: AccountRef) -> Result<()> {
            Ok(())
        }
    }

    /// A decider without apps (= the decision passes through).
    pub fn allow_everything(audit: Arc<AuditService>) -> Arc<ApplicationAccessService> {
        Arc::new(ApplicationAccessService::new(
            Arc::new(NoApplications),
            audit,
            crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                crate::domain::effective_tenant_settings::APPLICATION_ASSIGNMENT_ENFORCEMENT,
                "enforce",
            )]),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::NoApplications;
    use super::*;
    use crate::application::tenant_settings::testing::{
        tenant_settings as settings_fixture, tenant_settings_with_global,
    };
    use crate::domain::account::AccountRef;
    use crate::domain::application::{
        ApplicationAssignment, ApplicationBinding, AssignedServiceAccount, AssignedUser,
        BindingTarget,
    };
    use crate::domain::audit::AuditEvent;
    use crate::domain::clock::Clock;
    use crate::domain::effective_tenant_settings::APPLICATION_ASSIGNMENT_ENFORCEMENT;
    use crate::domain::error::Result;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::values::{ApplicationStatus, AssignmentMode};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 9, 15, 0, 0, 0).unwrap()
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    #[async_trait]
    impl AuditLogSink for RecordingSink {
        async fn record(&self, event: &AuditEvent) -> Result<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    /// A repository holding a single "individual" app with no assignments.
    struct OneIndividualApplication {
        application: Application,
        assigned: bool,
    }

    #[async_trait]
    impl ApplicationRepository for OneIndividualApplication {
        async fn create(&self, _application: &Application) -> Result<()> {
            Ok(())
        }
        async fn find_by_id(&self, _tenant_id: TenantId, _id: Uuid) -> Result<Option<Application>> {
            Ok(Some(self.application.clone()))
        }
        async fn find_by_oidc_client_id(
            &self,
            _tenant_id: TenantId,
            _client_id: &str,
        ) -> Result<Option<Application>> {
            Ok(Some(self.application.clone()))
        }
        async fn find_by_saml_entity_id(
            &self,
            _tenant_id: TenantId,
            _entity_id: &str,
        ) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn find_by_binding_target(
            &self,
            _tenant_id: TenantId,
            _target: BindingTarget,
        ) -> Result<Option<Application>> {
            Ok(None)
        }
        async fn list(&self, _tenant_id: TenantId) -> Result<Vec<Application>> {
            Ok(vec![self.application.clone()])
        }
        async fn update(
            &self,
            _tenant_id: TenantId,
            _id: Uuid,
            _display_name: &str,
            _status: ApplicationStatus,
            _assignment_mode: AssignmentMode,
            _updated_at: DateTime<Utc>,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn delete(&self, _tenant_id: TenantId, _id: Uuid) -> Result<bool> {
            Ok(true)
        }
        async fn list_bindings(&self, _application_id: Uuid) -> Result<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn add_binding(&self, _binding: &ApplicationBinding) -> Result<()> {
            Ok(())
        }
        async fn remove_binding(&self, _application_id: Uuid, _binding_id: Uuid) -> Result<bool> {
            Ok(true)
        }
        async fn move_binding(
            &self,
            _binding_id: Uuid,
            _from_application_id: Uuid,
            _to_application_id: Uuid,
            _moved_at: DateTime<Utc>,
        ) -> Result<bool> {
            Ok(false)
        }
        async fn list_tenant_bindings(
            &self,
            _tenant_id: TenantId,
        ) -> Result<Vec<ApplicationBinding>> {
            Ok(Vec::new())
        }
        async fn is_assigned(&self, _application_id: Uuid, _user_id: Uuid) -> Result<bool> {
            Ok(self.assigned)
        }
        async fn is_service_account_assigned(
            &self,
            _application_id: Uuid,
            _client_row_id: Uuid,
        ) -> Result<bool> {
            Ok(false)
        }
        async fn list_assigned_service_accounts(
            &self,
            _application_id: Uuid,
        ) -> Result<Vec<AssignedServiceAccount>> {
            Ok(Vec::new())
        }
        async fn list_assigned_users(&self, _application_id: Uuid) -> Result<Vec<AssignedUser>> {
            Ok(Vec::new())
        }
        async fn list_account_assignments(
            &self,
            _tenant_id: TenantId,
            _account: crate::domain::account::AccountRef,
        ) -> Result<Vec<crate::domain::application::AccountAssignment>> {
            Ok(Vec::new())
        }
        async fn count_assignments(&self, _application_id: Uuid) -> Result<i64> {
            Ok(0)
        }
        async fn assign(&self, _assignment: &ApplicationAssignment) -> Result<()> {
            Ok(())
        }
        async fn unassign(&self, _application_id: Uuid, _principal: AccountRef) -> Result<()> {
            Ok(())
        }
    }

    fn application(mode: AssignmentMode, status: ApplicationStatus) -> Application {
        Application {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from(Uuid::from_u128(2)),
            display_name: "photonest".to_string(),
            status,
            assignment_mode: mode,
            created_at: FixedClock.now(),
            updated_at: FixedClock.now(),
        }
    }

    fn service(
        repo: Arc<dyn ApplicationRepository>,
        enforcement: AssignmentEnforcement,
    ) -> (ApplicationAccessService, Arc<RecordingSink>) {
        service_with_settings(
            repo,
            tenant_settings_with_global(&[(
                APPLICATION_ASSIGNMENT_ENFORCEMENT,
                enforcement.as_str(),
            )]),
        )
    }

    /// Builds the real resolution (tenant row > built-in default) with only the given tenant rows.
    ///
    /// ⚠ Use this when testing different values per tenant. A resolver with only the global value makes a test
    /// that "passes even when reading the global value".
    fn tenant_settings(
        rows: &[(TenantId, &str, &str)],
    ) -> Arc<crate::application::tenant_settings::TenantSettingsService> {
        let fixture = settings_fixture();
        for (tenant_id, key, value) in rows {
            fixture.set_tenant(*tenant_id, key, value);
        }
        fixture.service
    }

    fn service_with_settings(
        repo: Arc<dyn ApplicationRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> (ApplicationAccessService, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock)));
        (ApplicationAccessService::new(repo, audit, settings), sink)
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// Pre-migration or migration-gap clients (no binding) pass. Refusing here would make misses look like
    /// "correctly refused".
    #[tokio::test]
    async fn a_client_without_an_application_is_let_through() {
        let (svc, sink) = service(Arc::new(NoApplications), AssignmentEnforcement::Enforce);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(gate, ApplicationGate::Allowed);
        // Not refused, so no audit row either (do not mix it into the rows counting migration gaps).
        assert!(sink.events.lock().unwrap().is_empty());
    }

    /// During the "record only" period, it passes even without an assignment, but is still audited:
    /// the count accumulated here is exactly the migration gap.
    #[tokio::test]
    async fn record_only_lets_the_user_through_but_leaves_a_row() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, sink) = service(repo, AssignmentEnforcement::RecordOnly);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(gate, ApplicationGate::Allowed);
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            AuditEventType::ApplicationAccessDenied
        );
        // The passing side is success, so before and after the switch can be counted with the same query.
        assert_eq!(events[0].result, AuditResult::Success);
    }

    #[tokio::test]
    async fn enforce_denies_and_carries_the_application_name() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, sink) = service(repo, AssignmentEnforcement::Enforce);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(
            gate,
            ApplicationGate::Denied {
                application_name: "photonest".to_string(),
                access: ApplicationAccess::NotAssigned,
            }
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events[0].result, AuditResult::Failure);
    }

    #[tokio::test]
    async fn an_assigned_user_passes() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: true,
        });
        let (svc, sink) = service(repo, AssignmentEnforcement::Enforce);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(gate, ApplicationGate::Allowed);
        assert!(sink.events.lock().unwrap().is_empty());
    }

    /// An "everyone" app passes without looking up assignments.
    #[tokio::test]
    async fn everyone_passes_without_a_row() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Everyone, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, _) = service(repo, AssignmentEnforcement::Enforce);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(gate, ApplicationGate::Allowed);
    }

    /// Whether to refuse is decided by the tenant (ADR-0058 §4). Put different values in 2 tenants and check the same
    /// "person without an assignment" is handled by each tenant's value; with only 1 tenant it would pass even when
    /// reading the global value.
    #[tokio::test]
    async fn each_tenant_decides_whether_to_enforce() {
        let enforcing = TenantId::from(Uuid::from_u128(10));
        let recording = TenantId::from(Uuid::from_u128(11));
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, sink) = service_with_settings(
            repo,
            tenant_settings(&[
                (enforcing, APPLICATION_ASSIGNMENT_ENFORCEMENT, "enforce"),
                (recording, APPLICATION_ASSIGNMENT_ENFORCEMENT, "record_only"),
            ]),
        );
        let user = Uuid::from_u128(3);

        let denied = svc.check(enforcing, "client-a", user, &ctx()).await;
        assert!(matches!(denied, ApplicationGate::Denied { .. }));
        let allowed = svc.check(recording, "client-a", user, &ctx()).await;
        assert_eq!(allowed, ApplicationGate::Allowed);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].tenant_id, Some(enforcing));
        assert_eq!(events[0].result, AuditResult::Failure);
        assert_eq!(events[1].tenant_id, Some(recording));
        assert_eq!(events[1].result, AuditResult::Success);
    }

    /// A tenant without rows defaults to "record only". ⚠ Falling to refusing without a roster would lock everyone out.
    #[tokio::test]
    async fn a_tenant_without_a_row_only_records() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, sink) = service_with_settings(repo, tenant_settings(&[]));
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(gate, ApplicationGate::Allowed);
        assert_eq!(sink.events.lock().unwrap()[0].result, AuditResult::Success);
    }

    /// Even when the setting cannot be fetched (stored value corrupted), nobody is locked out. It passes with only a record.
    #[tokio::test]
    async fn an_unreadable_setting_records_instead_of_locking_everyone_out() {
        let t = TenantId::from(Uuid::from_u128(2));
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Individual, ApplicationStatus::Active),
            assigned: false,
        });
        let (svc, sink) = service_with_settings(
            repo,
            tenant_settings(&[(t, APPLICATION_ASSIGNMENT_ENFORCEMENT, "enforce-ish")]),
        );
        let gate = svc.check(t, "client-a", Uuid::from_u128(3), &ctx()).await;
        assert_eq!(gate, ApplicationGate::Allowed);
        assert_eq!(sink.events.lock().unwrap()[0].result, AuditResult::Success);
    }

    /// A stopped app is refused regardless of assignment mode.
    #[tokio::test]
    async fn a_disabled_application_denies_even_in_everyone_mode() {
        let repo = Arc::new(OneIndividualApplication {
            application: application(AssignmentMode::Everyone, ApplicationStatus::Disabled),
            assigned: true,
        });
        let (svc, _) = service(repo, AssignmentEnforcement::Enforce);
        let gate = svc
            .check(
                TenantId::from(Uuid::from_u128(2)),
                "client-a",
                Uuid::from_u128(3),
                &ctx(),
            )
            .await;
        assert_eq!(
            gate,
            ApplicationGate::Denied {
                application_name: "photonest".to_string(),
                access: ApplicationAccess::Disabled,
            }
        );
    }
}
