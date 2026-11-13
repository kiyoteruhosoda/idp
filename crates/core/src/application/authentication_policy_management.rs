//! Authentication policy management (CRUD) use case (user authentication & authentication policy spec §7).
//!
//! A tenant admin (`idp.tenant.admin`; checked by Presentation's `RequirePerms`) creates, updates and
//! deletes the authentication policies of their own tenant. Validation is completed in this Application
//! layer and only the result is returned to Presentation. Every change is recorded in `audit_log`
//! (`authentication_policy.created` / `.updated` / `.deleted`; same spec §21).
//!
//! Policy **evaluation** is done by the login use cases (`login.rs` / `passkey_authentication.rs`)
//! with a pure domain function (`evaluate_policies`). This service only manages the rules (SRP).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::{
    AuthenticationPolicy, PolicyConditions, PolicyEffect, RequiredMethods, TimeWindow,
};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::repositories::AuthenticationPolicyRepository;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// Per-policy limit for condition lists (application_ids / user_ids). Evaluation scans every entry
/// on the login hot path, so unbounded growth is prevented.
const MAX_CONDITION_ENTRIES: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticationPolicyManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

type PolicyResult<T> = Result<T, AuthenticationPolicyManagementError>;

/// Input for create/update (converted from the Presentation DTO in the Application layer).
#[derive(Debug, Clone)]
pub struct AuthenticationPolicyDraft {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method` (invalid values are a Validation error).
    pub effect: String,
    /// What `require_specific_method` requires (`None` for other effects. AP3).
    pub effect_params: Option<RequiredMethods>,
    /// Target applications (`applications.id`. ADR-0054 decision 5). Empty = all applications.
    pub application_ids: Vec<Uuid>,
    pub user_ids: Vec<Uuid>,
    /// Network zones (CIDR notation. AP3).
    pub ip_cidrs: Vec<String>,
    /// Applicable time windows (AP3).
    pub time_windows: Vec<TimeWindow>,
    /// `acr_values` condition of the authorization request (AP3).
    pub requested_acr: Vec<String>,
}

pub struct AuthenticationPolicyManagementService {
    policies: Arc<dyn AuthenticationPolicyRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl AuthenticationPolicyManagementService {
    pub fn new(
        policies: Arc<dyn AuthenticationPolicyRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            policies,
            audit,
            clock,
            ids,
        }
    }

    /// Returns all of the tenant's policies (including disabled ones) in ascending priority order.
    pub async fn list(&self, tenant: TenantContext) -> PolicyResult<Vec<AuthenticationPolicy>> {
        self.policies
            .list_for_tenant(tenant.tenant_id())
            .await
            .map_err(internal)
    }

    /// Creates a policy. A duplicate `(tenant, policy_code)` is `Conflict`.
    pub async fn create(
        &self,
        tenant: TenantContext,
        draft: AuthenticationPolicyDraft,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> PolicyResult<AuthenticationPolicy> {
        let now = self.clock.now();
        let policy = AuthenticationPolicy {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            created_at: now,
            updated_at: now,
            ..validated(draft, now)?
        };
        self.policies.create(&policy).await.map_err(map_conflict)?;
        self.record(
            AuditEventType::AuthenticationPolicyCreated,
            tenant,
            actor,
            &policy.policy_code,
            ctx,
        )
        .await;
        Ok(policy)
    }

    /// Updates a policy by replacing every field. A missing target (including another tenant's) is `NotFound`.
    pub async fn update(
        &self,
        tenant: TenantContext,
        id: Uuid,
        draft: AuthenticationPolicyDraft,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> PolicyResult<AuthenticationPolicy> {
        let now = self.clock.now();
        let existing = self
            .policies
            .find_by_id(tenant.tenant_id(), id)
            .await
            .map_err(internal)?
            .ok_or(AuthenticationPolicyManagementError::NotFound)?;
        let policy = AuthenticationPolicy {
            id: existing.id,
            tenant_id: existing.tenant_id,
            created_at: existing.created_at,
            updated_at: now,
            ..validated(draft, now)?
        };
        let updated = self.policies.update(&policy).await.map_err(map_conflict)?;
        if !updated {
            // Race: another admin deleted it after our find.
            return Err(AuthenticationPolicyManagementError::NotFound);
        }
        self.record(
            AuditEventType::AuthenticationPolicyUpdated,
            tenant,
            actor,
            &policy.policy_code,
            ctx,
        )
        .await;
        Ok(policy)
    }

    /// Deletes a policy. A missing target (including another tenant's) is `NotFound`.
    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> PolicyResult<()> {
        let existing = self
            .policies
            .find_by_id(tenant.tenant_id(), id)
            .await
            .map_err(internal)?
            .ok_or(AuthenticationPolicyManagementError::NotFound)?;
        let deleted = self
            .policies
            .delete(tenant.tenant_id(), id)
            .await
            .map_err(internal)?;
        if !deleted {
            return Err(AuthenticationPolicyManagementError::NotFound);
        }
        self.record(
            AuditEventType::AuthenticationPolicyDeleted,
            tenant,
            actor,
            &existing.policy_code,
            ctx,
        )
        .await;
        Ok(())
    }

    async fn record(
        &self,
        event: AuditEventType,
        tenant: TenantContext,
        actor: &AdminActor,
        policy_code: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("policy={policy_code}")),
                ctx,
            )
            .await;
    }
}

/// Validates the input and maps it onto the mutable part of the entity (`id` / `tenant_id` / `created_at` are set by the caller).
fn validated(
    draft: AuthenticationPolicyDraft,
    now: chrono::DateTime<chrono::Utc>,
) -> PolicyResult<AuthenticationPolicy> {
    AuthenticationPolicy::validate_code(&draft.policy_code).map_err(|_| {
        AuthenticationPolicyManagementError::Validation(MessageKey::new(
            "api-auth-policy-code-invalid",
        ))
    })?;
    AuthenticationPolicy::validate_name(&draft.policy_name).map_err(|_| {
        AuthenticationPolicyManagementError::Validation(MessageKey::new(
            "api-auth-policy-name-invalid",
        ))
    })?;
    let effect = PolicyEffect::parse(&draft.effect).map_err(|_| {
        AuthenticationPolicyManagementError::Validation(MessageKey::new(
            "api-auth-policy-effect-invalid",
        ))
    })?;
    AuthenticationPolicy::validate_effect_params(effect, draft.effect_params.as_ref()).map_err(
        |_| {
            AuthenticationPolicyManagementError::Validation(MessageKey::new(
                "api-auth-policy-effect-params-invalid",
            ))
        },
    )?;
    if draft.application_ids.len() > MAX_CONDITION_ENTRIES
        || draft.user_ids.len() > MAX_CONDITION_ENTRIES
        || draft.ip_cidrs.len() > MAX_CONDITION_ENTRIES
        || draft.time_windows.len() > MAX_CONDITION_ENTRIES
        || draft.requested_acr.len() > MAX_CONDITION_ENTRIES
        || draft
            .requested_acr
            .iter()
            .any(|a| a.trim().is_empty() || a.len() > 255)
    {
        return Err(AuthenticationPolicyManagementError::Validation(
            MessageKey::new("api-auth-policy-conditions-invalid"),
        ));
    }
    let conditions = PolicyConditions {
        application_ids: draft.application_ids,
        user_ids: draft.user_ids,
        ip_cidrs: draft.ip_cidrs,
        time_windows: draft.time_windows,
        requested_acr: draft.requested_acr,
    };
    // Reject malformed CIDRs and time windows before saving (a broken condition silently becomes
    // "no match" at evaluation time, leaving a deny policy ineffective).
    conditions.validate().map_err(|_| {
        AuthenticationPolicyManagementError::Validation(MessageKey::new(
            "api-auth-policy-conditions-invalid",
        ))
    })?;
    Ok(AuthenticationPolicy {
        id: Uuid::nil(),
        tenant_id: Uuid::nil().into(),
        policy_code: draft.policy_code,
        policy_name: draft.policy_name.trim().to_string(),
        priority: draft.priority,
        enabled: draft.enabled,
        effect,
        effect_params: draft.effect_params,
        conditions,
        created_at: now,
        updated_at: now,
    })
}

fn internal(e: DomainError) -> AuthenticationPolicyManagementError {
    AuthenticationPolicyManagementError::Internal(e.to_string())
}

fn map_conflict(e: DomainError) -> AuthenticationPolicyManagementError {
    match e {
        DomainError::Conflict(_) => AuthenticationPolicyManagementError::Conflict(MessageKey::new(
            "api-auth-policy-code-conflict",
        )),
        other => internal(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()
    }

    fn test_tenant() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn draft(code: &str) -> AuthenticationPolicyDraft {
        AuthenticationPolicyDraft {
            effect_params: None,
            ip_cidrs: Vec::new(),
            time_windows: Vec::new(),
            requested_acr: Vec::new(),
            policy_code: code.to_string(),
            policy_name: format!("policy {code}"),
            priority: 10,
            enabled: true,
            effect: "deny".to_string(),
            application_ids: vec![Uuid::from_u128(0x0199_0000_0000_7000_8000_0000_0000_0001)],
            user_ids: vec![],
        }
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct SeqIds;
    impl IdGenerator for SeqIds {
        fn new_id(&self) -> Uuid {
            Uuid::new_v4()
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    /// In-memory fake repository (reproduces the `(tenant, code)` unique constraint).
    #[derive(Default)]
    struct FakePolicies {
        rows: Mutex<Vec<AuthenticationPolicy>>,
    }
    #[async_trait]
    impl AuthenticationPolicyRepository for FakePolicies {
        async fn create(&self, policy: &AuthenticationPolicy) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if rows
                .iter()
                .any(|p| p.tenant_id == policy.tenant_id && p.policy_code == policy.policy_code)
            {
                return Err(DomainError::Conflict("dup".to_string()));
            }
            rows.push(policy.clone());
            Ok(())
        }
        async fn list_for_tenant(
            &self,
            tenant_id: TenantId,
        ) -> DomainResult<Vec<AuthenticationPolicy>> {
            let mut rows: Vec<_> = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|p| p.tenant_id == tenant_id)
                .cloned()
                .collect();
            rows.sort_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then_with(|| a.policy_code.cmp(&b.policy_code))
            });
            Ok(rows)
        }
        async fn list_enabled_for_tenant(
            &self,
            tenant_id: TenantId,
        ) -> DomainResult<Vec<AuthenticationPolicy>> {
            Ok(self
                .list_for_tenant(tenant_id)
                .await?
                .into_iter()
                .filter(|p| p.enabled)
                .collect())
        }
        async fn find_by_id(
            &self,
            tenant_id: TenantId,
            id: Uuid,
        ) -> DomainResult<Option<AuthenticationPolicy>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|p| p.tenant_id == tenant_id && p.id == id)
                .cloned())
        }
        async fn update(&self, policy: &AuthenticationPolicy) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            if rows.iter().any(|p| {
                p.tenant_id == policy.tenant_id
                    && p.policy_code == policy.policy_code
                    && p.id != policy.id
            }) {
                return Err(DomainError::Conflict("dup".to_string()));
            }
            match rows
                .iter_mut()
                .find(|p| p.tenant_id == policy.tenant_id && p.id == policy.id)
            {
                Some(row) => {
                    *row = policy.clone();
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        async fn delete(&self, tenant_id: TenantId, id: Uuid) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|p| !(p.tenant_id == tenant_id && p.id == id));
            Ok(rows.len() < before)
        }
    }

    fn service(
        policies: Arc<FakePolicies>,
        sink: Arc<CapturingSink>,
    ) -> AuthenticationPolicyManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(fixed_now()))));
        AuthenticationPolicyManagementService::new(
            policies,
            audit,
            Arc::new(FixedClock(fixed_now())),
            Arc::new(SeqIds),
        )
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    fn tenant_ctx() -> TenantContext {
        TenantContext::new(test_tenant())
    }

    #[tokio::test]
    async fn create_persists_validates_and_audits() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies.clone(), sink.clone());

        let created = svc
            .create(
                tenant_ctx(),
                draft("deny-legacy"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("create ok");
        assert_eq!(created.tenant_id, test_tenant());
        assert_eq!(created.effect, PolicyEffect::Deny);
        assert_eq!(
            created.conditions.application_ids,
            vec![Uuid::from_u128(0x0199_0000_0000_7000_8000_0000_0000_0001)]
        );

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            AuditEventType::AuthenticationPolicyCreated
        );
        assert_eq!(events[0].reason.as_deref(), Some("policy=deny-legacy"));
    }

    #[tokio::test]
    async fn create_rejects_invalid_input_without_persisting() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies.clone(), sink.clone());

        for bad in [
            AuthenticationPolicyDraft {
                effect_params: None,
                ip_cidrs: Vec::new(),
                time_windows: Vec::new(),
                requested_acr: Vec::new(),
                policy_code: "bad code!".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                effect_params: None,
                ip_cidrs: Vec::new(),
                time_windows: Vec::new(),
                requested_acr: Vec::new(),
                policy_name: "  ".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                effect_params: None,
                ip_cidrs: Vec::new(),
                time_windows: Vec::new(),
                requested_acr: Vec::new(),
                effect: "block".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                effect_params: None,
                ip_cidrs: Vec::new(),
                time_windows: Vec::new(),
                requested_acr: Vec::new(),
                application_ids: vec![Uuid::nil(); MAX_CONDITION_ENTRIES + 1],
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                effect_params: None,
                ip_cidrs: Vec::new(),
                time_windows: Vec::new(),
                requested_acr: Vec::new(),
                user_ids: vec![Uuid::new_v4(); MAX_CONDITION_ENTRIES + 1],
                ..draft("x")
            },
        ] {
            assert!(matches!(
                svc.create(tenant_ctx(), bad, &AdminActor::User(Uuid::new_v4()), &ctx())
                    .await,
                Err(AuthenticationPolicyManagementError::Validation(_))
            ));
        }
        assert!(policies.rows.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_code_is_conflict() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies, sink);

        svc.create(
            tenant_ctx(),
            draft("dup"),
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("first create ok");
        assert!(matches!(
            svc.create(
                tenant_ctx(),
                draft("dup"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(AuthenticationPolicyManagementError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn update_replaces_fields_and_audits() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies, sink.clone());

        let created = svc
            .create(
                tenant_ctx(),
                draft("mfa-admins"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("create ok");
        let mut updated_draft = draft("mfa-admins");
        updated_draft.effect = "require_mfa".to_string();
        updated_draft.enabled = false;
        updated_draft.priority = 5;
        let updated = svc
            .update(
                tenant_ctx(),
                created.id,
                updated_draft,
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("update ok");
        assert_eq!(updated.effect, PolicyEffect::RequireMfa);
        assert!(!updated.enabled);
        assert_eq!(updated.priority, 5);
        assert_eq!(updated.created_at, created.created_at);

        let events = sink.events.lock().unwrap();
        assert_eq!(
            events.last().unwrap().event_type,
            AuditEventType::AuthenticationPolicyUpdated
        );
    }

    #[tokio::test]
    async fn update_and_delete_reject_other_tenants_policy() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies, sink);

        let created = svc
            .create(
                tenant_ctx(),
                draft("scoped"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("create ok");
        let other = TenantContext::new(TenantId::from(Uuid::now_v7()));
        assert!(matches!(
            svc.update(
                other,
                created.id,
                draft("scoped"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(AuthenticationPolicyManagementError::NotFound)
        ));
        assert!(matches!(
            svc.delete(other, created.id, &AdminActor::User(Uuid::new_v4()), &ctx())
                .await,
            Err(AuthenticationPolicyManagementError::NotFound)
        ));
    }

    #[tokio::test]
    async fn delete_removes_and_audits() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies.clone(), sink.clone());

        let created = svc
            .create(
                tenant_ctx(),
                draft("temp"),
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("create ok");
        svc.delete(
            tenant_ctx(),
            created.id,
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("delete ok");
        assert!(policies.rows.lock().unwrap().is_empty());
        assert_eq!(
            sink.events.lock().unwrap().last().unwrap().event_type,
            AuditEventType::AuthenticationPolicyDeleted
        );
    }

    #[tokio::test]
    async fn list_returns_priority_order() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies, sink);

        let mut low = draft("low");
        low.priority = 100;
        let mut high = draft("high");
        high.priority = 1;
        svc.create(tenant_ctx(), low, &AdminActor::User(Uuid::new_v4()), &ctx())
            .await
            .expect("ok");
        svc.create(
            tenant_ctx(),
            high,
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("ok");
        let listed = svc.list(tenant_ctx()).await.expect("list ok");
        assert_eq!(
            listed
                .iter()
                .map(|p| p.policy_code.as_str())
                .collect::<Vec<_>>(),
            vec!["high", "low"]
        );
    }
}
