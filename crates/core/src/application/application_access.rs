//! 「この利用者はこのアプリを使ってよいか」の判定（ADR-0054）。
//!
//! # 判定は認証の**あと**
//!
//! 認証するまで誰なのか分からないので、割り当ての判定は認証の後になる。これは実装の都合ではなく
//! 順序の必然で、だからこそ拒否は RP へ戻さず assay の画面で伝える ——利用者から見れば
//! 「入れたのに弾かれた」ので、黙って弾くと障害と区別が付かない。
//!
//! # 段階導入（`APPLICATION_ASSIGNMENT_ENFORCEMENT`）
//!
//! いきなり断らない。まず `record_only` で本番へ出し、「割り当てが無いのに来た人」を監査ログへ
//! 溜める（移行の漏れはここで全部出る）。ログが静かになってから `enforce` へ切り替える。
//! ⚠ **切り替えはコードではなく設定で行う。** 入れ替えにすると、戻すのにデプロイが要る。
//!
//! 設定は**テナントが決める**（ADR-0058 §4）。名簿が整ったテナントから `enforce` へ倒せる。
//! ⚠ 値は参照のたびにテナントについて引く（[`EffectiveTenantSettings`]）。起動時の `Config` を
//! 読むと、全テナントが全体の値で動く。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::application::{Application, ApplicationAccess};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::ApplicationRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::AssignmentEnforcement;
use std::sync::Arc;
use uuid::Uuid;

/// 判定の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationGate {
    /// 通してよい。
    Allowed,
    /// 断る（`enforce` のときだけ返る）。画面に出すためのアプリ名を持つ。
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

    /// OIDC の `client_id` からアプリを解決する。
    ///
    /// 認証ポリシーの宛先（`conditions.application_ids`）と、下の [`Self::check`] の両方が使う。
    /// binding がまだ無い client は `None` ——移行前・移行漏れであって「割り当てが無い」ではない。
    pub async fn resolve_for_oidc_client(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>, DomainError> {
        self.applications
            .find_by_oidc_client_id(tenant_id, client_id)
            .await
    }

    /// 解決したアプリの id だけを返す（認証ポリシー評価用の薄い口）。
    ///
    /// アプリを持たない client は `None`。`conditions.application_ids` を持つポリシーは
    /// **一致しない**（評価材料が無い条件は「一致しない」に倒す、という既存の規則どおり）。
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

    /// 判定して、必要なら監査ログへ 1 行残す。
    ///
    /// **アプリが解決できないときは通す。** 移行前・移行漏れの client を「割り当てが無い」と同じに
    /// 扱うと、取りこぼしが「正しく断った」ように見えてしまう（ADR-0054 の帰結）。
    ///
    /// 問い合わせの失敗（DB 障害）も通す。門番が落ちたときに**全員を締め出す**のは、この門が
    /// 守っているものの重さに見合わない ——警告は構造化ログへ出す。
    pub async fn check(
        &self,
        tenant_id: TenantId,
        client_id: &str,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> ApplicationGate {
        let application = match self.resolve_for_oidc_client(tenant_id, client_id).await {
            Ok(Some(application)) => application,
            Ok(None) => {
                tracing::debug!(
                    client_id = %client_id,
                    "client is not bound to an application; assignment check skipped"
                );
                return ApplicationGate::Allowed;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    client_id = %client_id,
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

        // 設定は断る場面になってから引く（素通りする大半の要求で問い合わせを増やさない）。
        // 引けないときは「記録するだけ」に倒す ——上の問い合わせの失敗と同じく、門番が落ちたときに
        // 全員を締め出さない。
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

        // `record_only` は成功（＝通した）として残す。切り替えの前後を同じ問い合わせで数えたいので、
        // 種別は分けず `result` で分ける。
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
                Some(client_id),
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
            // 記録するだけの期間。ここを通った件数がそのまま「移行の漏れ」である。
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
    //! 判定の入り口を持たないテスト用の実装。
    //!
    //! `CodeIssuanceService` は判定器を必ず 1 つ持つが、code 発行の周りを試すテストの多くは
    //! アプリの割り当てに関心が無い。そこで「アプリが 1 件も無い」＝**判定が素通しになる**
    //! 実装をここに 1 つだけ置き、各テストが自前の空実装を書き写さないようにする。

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

    /// 1 件もアプリを持たないリポジトリ（すべての問い合わせが空を返す）。
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

    /// アプリを持たない（＝判定が素通しになる）判定器。
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

    /// 割り当てが 1 件も無い「個別」のアプリを 1 つだけ持つリポジトリ。
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

    /// 本物の解決（テナントの行 > 組み込み既定）を、指定したテナントの行だけで組み立てる。
    ///
    /// ⚠ テナントごとに違う値を試すときはこちらを使う。全体の値だけを入れた解決器では「全体の値を
    /// 読んでいても通ってしまう」試験になる。
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

    /// 移行前・移行漏れの client（binding が無い）は通す。ここで断ると、取りこぼしが
    /// 「正しく断った」ように見えてしまう。
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
        // 断っていないので監査行も出さない（移行の漏れを数える行に混ぜない）。
        assert!(sink.events.lock().unwrap().is_empty());
    }

    /// 「記録するだけ」の期間は、割り当てが無くても通す。ただし監査には残す
    /// ——ここに溜まった件数がそのまま移行の漏れである。
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
        // 通した側は success。切り替えの前後を同じ問い合わせで数えられるようにしている。
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

    /// 「全員」のアプリは割り当てを引かずに通す。
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

    /// 断るかどうかはテナントが決める（ADR-0058 §4）。2 テナントで違う値を入れ、同じ「割り当ての
    /// 無い人」がそれぞれのテナントの値で扱われること ——1 テナントだけだと、全体の値を読んでいても
    /// 通ってしまう。
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

    /// 行の無いテナントは既定の「記録するだけ」。⚠ 名簿の無いまま断る側へ倒れると全員が締め出される。
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

    /// 設定が引けない（保存値が壊れている）ときも締め出さない。記録だけ残して通す。
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

    /// 止めたアプリは、割り当てのモードに関わらず通さない。
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
