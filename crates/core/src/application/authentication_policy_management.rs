//! 認証ポリシーの管理（CRUD）ユースケース（ユーザー認証・認証ポリシー仕様書 §7）。
//!
//! テナント管理者（`idp.tenant.admin`。判定は Presentation の `RequirePerms`）が、自テナントの
//! 認証ポリシーを作成・更新・削除する。検証は本 Application 層で完結し、Presentation には結果のみ
//! 返す。全ての変更は `audit_log` に記録する（`authentication_policy.created` / `.updated` /
//! `.deleted`。同仕様 §21）。
//!
//! ポリシーの**評価**はログインユースケース（`login.rs` / `passkey_authentication.rs`）が
//! ドメインの純粋関数（`evaluate_policies`）で行う。本サービスは規則の管理のみを担う（SRP）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::{AuthenticationPolicy, PolicyConditions, PolicyEffect};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::repositories::AuthenticationPolicyRepository;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// 条件リスト（client_ids / user_ids）の 1 ポリシーあたりの上限。評価はログインのホットパスで
/// 全件走査するため、無制限の肥大化を防ぐ。
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

/// 作成・更新の入力（Presentation の DTO から Application 層で変換して渡す）。
#[derive(Debug, Clone)]
pub struct AuthenticationPolicyDraft {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa`（不正値は Validation エラー）。
    pub effect: String,
    pub client_ids: Vec<String>,
    pub user_ids: Vec<Uuid>,
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

    /// テナントの全ポリシー（無効を含む）を priority 昇順で返す。
    pub async fn list(&self, tenant: TenantContext) -> PolicyResult<Vec<AuthenticationPolicy>> {
        self.policies
            .list_for_tenant(tenant.tenant_id())
            .await
            .map_err(internal)
    }

    /// ポリシーを作成する。`(tenant, policy_code)` 重複は `Conflict`。
    pub async fn create(
        &self,
        tenant: TenantContext,
        draft: AuthenticationPolicyDraft,
        actor: Uuid,
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

    /// ポリシーを全項目置換で更新する。対象不存在（他テナント含む）は `NotFound`。
    pub async fn update(
        &self,
        tenant: TenantContext,
        id: Uuid,
        draft: AuthenticationPolicyDraft,
        actor: Uuid,
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
            // find 後に別管理者が削除した競合。
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

    /// ポリシーを削除する。対象不存在（他テナント含む）は `NotFound`。
    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: Uuid,
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
        actor: Uuid,
        policy_code: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&format!("policy={policy_code}")),
                ctx,
            )
            .await;
    }
}

/// 入力を検証してエンティティの可変部分へ写す（`id` / `tenant_id` / `created_at` は呼び出し側が設定）。
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
    if draft.client_ids.len() > MAX_CONDITION_ENTRIES
        || draft.user_ids.len() > MAX_CONDITION_ENTRIES
        || draft
            .client_ids
            .iter()
            .any(|c| c.trim().is_empty() || c.len() > 255)
    {
        return Err(AuthenticationPolicyManagementError::Validation(
            MessageKey::new("api-auth-policy-conditions-invalid"),
        ));
    }
    Ok(AuthenticationPolicy {
        id: Uuid::nil(),
        tenant_id: Uuid::nil().into(),
        policy_code: draft.policy_code,
        policy_name: draft.policy_name.trim().to_string(),
        priority: draft.priority,
        enabled: draft.enabled,
        effect,
        conditions: PolicyConditions {
            client_ids: draft.client_ids,
            user_ids: draft.user_ids,
        },
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
            policy_code: code.to_string(),
            policy_name: format!("policy {code}"),
            priority: 10,
            enabled: true,
            effect: "deny".to_string(),
            client_ids: vec!["legacy-app".to_string()],
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

    /// インメモリのフェイクリポジトリ（`(tenant, code)` 一意制約を再現する）。
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
            .create(tenant_ctx(), draft("deny-legacy"), Uuid::new_v4(), &ctx())
            .await
            .expect("create ok");
        assert_eq!(created.tenant_id, test_tenant());
        assert_eq!(created.effect, PolicyEffect::Deny);
        assert_eq!(
            created.conditions.client_ids,
            vec!["legacy-app".to_string()]
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
                policy_code: "bad code!".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                policy_name: "  ".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                effect: "block".to_string(),
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                client_ids: vec!["".to_string()],
                ..draft("x")
            },
            AuthenticationPolicyDraft {
                user_ids: vec![Uuid::new_v4(); MAX_CONDITION_ENTRIES + 1],
                ..draft("x")
            },
        ] {
            assert!(matches!(
                svc.create(tenant_ctx(), bad, Uuid::new_v4(), &ctx()).await,
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

        svc.create(tenant_ctx(), draft("dup"), Uuid::new_v4(), &ctx())
            .await
            .expect("first create ok");
        assert!(matches!(
            svc.create(tenant_ctx(), draft("dup"), Uuid::new_v4(), &ctx())
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
            .create(tenant_ctx(), draft("mfa-admins"), Uuid::new_v4(), &ctx())
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
                Uuid::new_v4(),
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
            .create(tenant_ctx(), draft("scoped"), Uuid::new_v4(), &ctx())
            .await
            .expect("create ok");
        let other = TenantContext::new(TenantId::from(Uuid::now_v7()));
        assert!(matches!(
            svc.update(other, created.id, draft("scoped"), Uuid::new_v4(), &ctx())
                .await,
            Err(AuthenticationPolicyManagementError::NotFound)
        ));
        assert!(matches!(
            svc.delete(other, created.id, Uuid::new_v4(), &ctx()).await,
            Err(AuthenticationPolicyManagementError::NotFound)
        ));
    }

    #[tokio::test]
    async fn delete_removes_and_audits() {
        let policies = Arc::new(FakePolicies::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(policies.clone(), sink.clone());

        let created = svc
            .create(tenant_ctx(), draft("temp"), Uuid::new_v4(), &ctx())
            .await
            .expect("create ok");
        svc.delete(tenant_ctx(), created.id, Uuid::new_v4(), &ctx())
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
        svc.create(tenant_ctx(), low, Uuid::new_v4(), &ctx())
            .await
            .expect("ok");
        svc.create(tenant_ctx(), high, Uuid::new_v4(), &ctx())
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
