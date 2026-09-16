//! アプリの管理（登録・停止・binding・利用者の割り当て）——ADR-0054。
//!
//! クライアント管理（`client_management`）と別サービスにするのは、**扱っている段が違う**ため
//! である。あちらは「OIDC でどう繋ぐか」を持ち、こちらは「利用者から見て何というアプリで、
//! 誰が使ってよいか」を持つ。混ぜると、SAML を足した日にクライアント管理の中へ SAML の枝が
//! 生えることになる。
//!
//! 判定は本 Application 層で行い、Presentation には結果のみ渡す（CLAUDE.md「権限管理」）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::application::{
    validate_display_name, Application, ApplicationAssignment, ApplicationBinding, AssignedUser,
    BindingTarget,
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
use std::sync::Arc;
use uuid::Uuid;

/// 「いま入れている人」を出すときに読む上限。
///
/// ⚠ **ここで打ち切ると名簿が欠ける。** 「全員」から「個別」へ倒すときの写し元なので、
/// 超えた場合は黙って切らず [`CurrentUsers::truncated`] を立てて画面へ伝える。
pub const MAX_CURRENT_USERS: i64 = 500;

#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationManagementError {
    /// アプリ・binding・利用者が要求テナントに存在しない。
    NotFound,
    /// 入力が不正（表示名が空・長すぎる等）。
    Invalid(MessageKey),
    /// その相手は既に別のアプリの名乗りになっている（差し込み値は相手のアプリの表示名）。
    Conflict(MessageKey),
    Internal(String),
}

/// 一覧の 1 行（アプリ ＋ 画面が要る集計）。
///
/// 件数を数えるのをここでやるのは、**画面に人数を出すために名簿を全部読ませない**ためである。
pub struct ApplicationSummary {
    pub application: Application,
    /// 繋がっている認証方法（表示名つき）。
    pub bindings: Vec<BindingSummary>,
    /// 割り当て人数。`EVERYONE` のアプリでは行が無いので 0 になる（画面はモードで出し分ける）。
    pub assigned_count: i64,
}

/// 名乗り 1 本を画面に出す形。
pub struct BindingSummary {
    pub binding: ApplicationBinding,
    /// 人が見分ける値。ログイン用・サービスアカウントなら `clients.client_id`、SAML なら
    /// `entity_id`、宛名なら `resource_uri`。相手が消えていれば `None`。
    pub identifier: Option<String>,
    /// 相手の登録名（`clients.app_name` / SP・宛名の `display_name`）。
    pub display_name: Option<String>,
}

/// 足したい名乗り（管理 API の要求を解釈したもの。ADR-0059）。
///
/// 相手は**人が知っている値**で指す（`client_id`・宛名の URI）。SAML の SP だけは
/// `entity_id` が URL 形でパスに載せにくいので内部 ID で指す（ADR-0054 のまま）。
pub enum NewBinding {
    /// ログイン用の OIDC client（`authorization_code`）。
    Oidc { client_id: String },
    /// SAML の SP。
    Saml { service_provider_id: Uuid },
    /// サービスアカウント（`client_credentials` だけのクライアント）。
    ServiceAccount { client_id: String },
    /// アプリの API の宛名（`aud`）。
    Resource { resource_uri: String },
}

/// アプリの詳細（binding と名簿）。
pub struct ApplicationDetail {
    pub application: Application,
    pub bindings: Vec<BindingSummary>,
    pub assigned: Vec<AssignedUser>,
}

/// 「いま入れている人」——`EVERYONE` を `INDIVIDUAL` へ倒す前に写す元。
pub struct CurrentUsers {
    pub members: Vec<TenantMember>,
    /// 全体の人数（[`MAX_CURRENT_USERS`] で切る前の値）。
    pub total: i64,
    /// 上限で打ち切ったか。⚠ **立っていたら画面は「全員は出せていない」と言うこと。**
    pub truncated: bool,
}

/// 新しいアプリの入力。
pub struct NewApplication {
    pub display_name: String,
    /// ⚠ 既定は [`AssignmentMode::Individual`]（ADR-0054 の決定 3）。呼び出し側が明示する。
    pub assignment_mode: AssignmentMode,
    /// 作った本人を同時に割り当てるか。⚠ **画面では初めからチェックしておく**
    /// ——「個別」で作った直後は誰も入れないので、作った本人が締め出される形にしない。
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

    /// アプリを一覧する（表示名の昇順）。
    pub async fn list(
        &self,
        tenant: TenantContext,
    ) -> Result<Vec<ApplicationSummary>, ApplicationManagementError> {
        let applications = self
            .applications
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)?;
        // クライアントは**1 回だけ**読む。binding ごとに引き直すと、アプリ数 × クライアント数の
        // 走査になる（アプリが増えるほど二乗で効いてくる）。
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

    /// アプリ 1 件の詳細。
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
        Ok(ApplicationDetail {
            application,
            bindings,
            assigned,
        })
    }

    /// アプリを登録する。
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

        // 作った本人を割り当てる。⚠ ここを落とすと、「個別」で作った直後は**誰も入れない**アプリが
        // できる。人ではない実行主体（機械）には割り当てる相手が居ないので何もしない。
        if input.assign_creator {
            if let Some(user_id) = actor.user_id() {
                self.assign(tenant, application.id, user_id, actor, ctx)
                    .await?;
            }
        }
        Ok(application)
    }

    /// 表示名・状態・割り当てモードを変える。
    ///
    /// ⚠ **「個別」へ倒すときに名簿が空でないことは、ここでは見ない。** 空のまま保存してよいか
    /// （＝誰も入れなくしてよいか）は人が決めることなので、確認は画面が出す。ここで拒むと、
    /// 「まず全員を止めて、それから 1 人ずつ足す」という正当な手順が踏めなくなる。
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
        // 戻り値の bool は「不存在」の判定に使わない。MySQL の `rows_affected` は**値が変わった行**
        // を数えるため、何も変えない更新が 0 を返して存在する行を 404 にしてしまう。
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

    /// アプリを削除する（binding と割り当ては一緒に消える）。
    ///
    /// ⚠ **ぶら下がっている `clients` / `saml_service_providers` は消えない。** アプリは
    /// 「利用者から見た括り」であって、繋ぎ方の設定そのものではない。消えるのは括りと名簿だけで、
    /// RP はそのまま繋がったまま（＝判定の対象から外れる）になる。
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

    /// 名乗りを足す（ADR-0059）。
    ///
    /// ⚠ **種類と相手の性質を突き合わせる。** ログイン用に `client_credentials` の client を
    /// 結び付けると、ログインの判定がそのアプリを見ないまま素通しになる。逆にサービスアカウントとして
    /// ログイン用の client を結び付けると、利用者のアクセストークンで self の名簿が読める。
    pub async fn bind(
        &self,
        tenant: TenantContext,
        id: Uuid,
        request: NewBinding,
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
        self.add_binding(tenant, &application, target, &identifier, actor, ctx)
            .await
    }

    /// binding を外す。
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

    /// 利用者を割り当てる（冪等）。
    pub async fn assign(
        &self,
        tenant: TenantContext,
        id: Uuid,
        user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        // ⚠ **要求テナントのメンバーであることを確かめる。** アプリはテナントの中のものなので、
        // 他テナントの利用者 id を持ち込んで名簿へ入れられてはいけない。
        self.require_member(tenant, user_id).await?;

        self.applications
            .assign(&ApplicationAssignment {
                application_id: id,
                user_id,
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
                // `user_id` 列は**操作対象**の利用者。実行主体は理由欄へ回す。
                Some(user_id),
                None,
                Some(&audit_reason(&application, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// 割り当てを外す（未割り当てでもエラーにしない）。
    pub async fn unassign(
        &self,
        tenant: TenantContext,
        id: Uuid,
        user_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        self.applications
            .unassign(id, user_id)
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

    /// 「いま入れている人」を返す。
    ///
    /// 「全員」から「個別」へ倒すときの**写し元**である。これを出さずに切り替えさせると、
    /// 空の名簿で保存した瞬間に全員が入れなくなる。
    pub async fn current_users(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<CurrentUsers, ApplicationManagementError> {
        let application = self.load(tenant, id).await?;
        match application.assignment_mode {
            // 「全員」＝テナントのメンバー全員。⚠ 他テナントの利用者は含まない。
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
            // 既に「個別」なら、写す相手は名簿そのもの。画面は割り当て一覧を出せばよい。
            AssignmentMode::Individual => Ok(CurrentUsers {
                members: Vec::new(),
                total: 0,
                truncated: false,
            }),
        }
    }

    async fn add_binding(
        &self,
        tenant: TenantContext,
        application: &Application,
        target: BindingTarget,
        identifier: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ApplicationBinding, ApplicationManagementError> {
        // ⚠ 既に**別の**アプリの名乗りなら、そのアプリの名前で断る。「繋がっています」だけでは、
        // 人はどのアプリから外せばよいのか探しに行くことになる。同じアプリなら何もしない（冪等）。
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
            return Err(already_bound(&owner));
        }
        let binding = ApplicationBinding {
            id: self.ids.new_id(),
            application_id: application.id,
            target,
            created_at: self.clock.now(),
        };
        if let Err(e) = self.applications.add_binding(&binding).await {
            // 読んでから書くまでの間に、別の要求が同じ相手を結び付けた。
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

    /// 名乗りを画面に出す形へ広げる。`clients` は呼び出し側が 1 回だけ読んだ一覧
    /// （`clients.id` から名前を引くだけなので、binding ごとに読み直さない）。
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

    /// 要求テナント内のクライアントを `client_id` で解決する。
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
            // 論理削除済み（ADR-0035）は「無い」として扱う。消したはずの client を新しいアプリへ
            // 繋げると、復活したときに知らないアプリの名乗りが付いてくる。
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

/// 監査ログの `reason`（PII を含めない）。
///
/// 表示名ではなく **id** を載せる。名前は後から変わるので、変わった瞬間に過去の行と繋がらなくなる。
fn audit_reason(application: &Application, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("application={} {note}", application.id),
        None => format!("application={}", application.id),
    }
}

/// 「既に ○○ の名乗りです」。
fn already_bound(owner: &Application) -> ApplicationManagementError {
    ApplicationManagementError::Conflict(MessageKey::with_value(
        "api-application-binding-conflict",
        owner.display_name.clone(),
    ))
}

fn map_repo_error(e: DomainError) -> ApplicationManagementError {
    match e {
        // 相手のアプリ名を引けなかった衝突（名前付きの案内は `already_bound` が出す）。
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
