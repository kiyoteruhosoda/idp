//! 保護リソース（`aud` に入る宛名）の登録・停止・削除と、クライアントへの許可（ADR-0042）。
//!
//! 権限コードの付与（`client_permission_management`）と別サービスにするのは、**判定の材料が違う**
//! ためである。あちらは「クライアントへ付与してよいコードか」を静的に判断できるが、こちらは
//! 「その宛名が要求テナントに登録されているか」をリポジトリに問う必要がある。
//!
//! 判定は本 Application 層で行い、Presentation には結果のみ渡す（CLAUDE.md「権限管理」）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::client::Client;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::issuer::tenant_issuer;
use crate::domain::message::MessageKey;
use crate::domain::repositories::{
    ClientRepository, ClientResourceRepository, ProtectedResourceRepository,
};
use crate::domain::resource::{validate_display_name, validate_resource_uri, ProtectedResource};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::ResourceStatus;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceManagementError {
    /// 宛名・クライアントが要求テナントに存在しない（削除済みのクライアントを含む）。
    NotFound,
    /// 入力が不正（空・絶対 URI でない・fragment 付き・予約済みの宛名）。
    Invalid(MessageKey),
    /// 同じ宛名が既に登録されている。
    Conflict(MessageKey),
    Internal(String),
}

pub struct ResourceManagementService {
    resources: Arc<dyn ProtectedResourceRepository>,
    client_resources: Arc<dyn ClientResourceRepository>,
    clients: Arc<dyn ClientRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    /// テナント接頭辞を付ける前の issuer。予約済みの宛名（`/userinfo`・`/admin`）の判定に使う。
    base_issuer: String,
}

impl ResourceManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resources: Arc<dyn ProtectedResourceRepository>,
        client_resources: Arc<dyn ClientResourceRepository>,
        clients: Arc<dyn ClientRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        base_issuer: String,
    ) -> Self {
        Self {
            resources,
            client_resources,
            clients,
            audit,
            clock,
            ids,
            base_issuer,
        }
    }

    /// 宛名を一覧する（`resource_uri` 昇順）。
    pub async fn list(
        &self,
        tenant: TenantContext,
    ) -> Result<Vec<ProtectedResource>, ResourceManagementError> {
        self.resources
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)
    }

    /// 宛名を登録する。
    pub async fn register(
        &self,
        tenant: TenantContext,
        raw_uri: &str,
        raw_display_name: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        let resource_uri =
            validate_resource_uri(raw_uri).map_err(ResourceManagementError::Invalid)?;
        let display_name =
            validate_display_name(raw_display_name).map_err(ResourceManagementError::Invalid)?;
        self.ensure_not_reserved(tenant, &resource_uri)?;

        let now = self.clock.now();
        let resource = ProtectedResource {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            resource_uri,
            display_name,
            status: ResourceStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.resources
            .create(&resource)
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ResourceRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        Ok(resource)
    }

    /// 宛名の状態を変える（`DISABLED` にすると新しいトークンの宛先に使えなくなる）。
    pub async fn set_status(
        &self,
        tenant: TenantContext,
        id: Uuid,
        status: ResourceStatus,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        let resource = self.load(tenant, id).await?;
        let changed = self
            .resources
            .set_status(tenant.tenant_id(), id, status, self.clock.now())
            .await
            .map_err(map_repo_error)?;
        if !changed {
            return Err(ResourceManagementError::NotFound);
        }

        self.audit
            .record(
                AuditEventType::ResourceUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&format!(
                    "{} status={}",
                    audit_reason(&resource.resource_uri, actor),
                    status.as_str()
                )),
                ctx,
            )
            .await;
        self.load(tenant, id).await
    }

    /// 宛名を削除する。許可行（`client_resources`）も一緒に消える。
    ///
    /// **発行済みのトークンは失効しない。** `aud` は署名済みのクレームで、寿命が尽きるまで
    /// リソースサーバから見て有効なままである。急いで止めたいときは、受け側でその `client_id` を
    /// 落とすほうが速い。
    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ResourceManagementError> {
        let resource = self.load(tenant, id).await?;
        let deleted = self
            .resources
            .delete(tenant.tenant_id(), id)
            .await
            .map_err(map_repo_error)?;
        if !deleted {
            return Err(ResourceManagementError::NotFound);
        }

        self.audit
            .record(
                AuditEventType::ResourceDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// クライアントへ許した宛名を一覧する。
    pub async fn list_for_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Vec<ProtectedResource>, ResourceManagementError> {
        let client = self.load_client(tenant, client_id).await?;
        self.client_resources
            .list_for_client(client.id)
            .await
            .map_err(map_repo_error)
    }

    /// クライアントへ宛名を許可する（冪等）。許可後の一覧を返す。
    pub async fn grant(
        &self,
        tenant: TenantContext,
        client_id: &str,
        raw_uri: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<ProtectedResource>, ResourceManagementError> {
        let client = self.load_client(tenant, client_id).await?;
        let resource = self.load_by_uri(tenant, raw_uri).await?;

        self.client_resources
            .grant(client.id, resource.id, self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientResourceGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                // `client_id` 列は操作対象のクライアント。実行主体が機械のときは理由欄へ回す。
                Some(&client.client_id),
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        self.list_for_client(tenant, client_id).await
    }

    /// クライアントの許可を取り消す（未許可でもエラーにしない）。取り消し後の一覧を返す。
    ///
    /// 貸すときは**名前**（`resource_uri`）で、取り消すときは**行の id** で指すのは、
    /// 宛名の登録（名前で作り、id で消す）と同じ形に揃えるため。名前を URL のパスに載せると
    /// スラッシュの percent-encode が要り、取り消しという後戻りできない操作で綴りを誤りやすい。
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        client_id: &str,
        resource_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<ProtectedResource>, ResourceManagementError> {
        let client = self.load_client(tenant, client_id).await?;
        let resource = self.load(tenant, resource_id).await?;

        self.client_resources
            .revoke(client.id, resource.id)
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientResourceRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        self.list_for_client(tenant, client_id).await
    }

    /// この認可サーバ自身の `aud`（`{issuer}/userinfo`・`{issuer}/admin`）を宛名として登録させない。
    ///
    /// 登録できると、管理 API 向けのトークンを「普通の宛名」として誰にでも発行できてしまう
    /// （`perms` は付かないが、`aud` だけを見るリソースサーバは通してしまう）。
    fn ensure_not_reserved(
        &self,
        tenant: TenantContext,
        resource_uri: &str,
    ) -> Result<(), ResourceManagementError> {
        let issuer = tenant_issuer(&self.base_issuer, tenant.tenant_id());
        let reserved = [
            format!("{issuer}/userinfo"),
            format!("{issuer}/admin"),
            issuer,
        ];
        if reserved.iter().any(|value| value == resource_uri) {
            return Err(ResourceManagementError::Invalid(MessageKey::new(
                "api-resource-uri-reserved",
            )));
        }
        Ok(())
    }

    async fn load(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        match self.resources.find_by_id(tenant.tenant_id(), id).await {
            Ok(Some(resource)) => Ok(resource),
            Ok(None) => Err(ResourceManagementError::NotFound),
            Err(e) => Err(ResourceManagementError::Internal(e.to_string())),
        }
    }

    async fn load_by_uri(
        &self,
        tenant: TenantContext,
        raw_uri: &str,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        let uri = raw_uri.trim();
        match self.resources.find_by_uri(tenant.tenant_id(), uri).await {
            Ok(Some(resource)) => Ok(resource),
            Ok(None) => Err(ResourceManagementError::NotFound),
            Err(e) => Err(ResourceManagementError::Internal(e.to_string())),
        }
    }

    /// 要求テナント内で有効なクライアントを解決する。他テナントの `client_id` は解決しない。
    async fn load_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Client, ResourceManagementError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            // 論理削除済み（ADR-0035）は「無い」として扱う。消したはずのクライアントに
            // 宛先を貸せると、復活したときに知らない宛名を持っている。
            Ok(Some(client)) if !client.is_deleted() => Ok(client),
            Ok(_) => Err(ResourceManagementError::NotFound),
            Err(e) => Err(ResourceManagementError::Internal(e.to_string())),
        }
    }
}

/// 監査ログの `reason`（PII を含めない。宛名と、機械が実行した場合はその `client_id`）。
fn audit_reason(resource_uri: &str, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("resource={resource_uri} {note}"),
        None => format!("resource={resource_uri}"),
    }
}

fn map_repo_error(e: DomainError) -> ResourceManagementError {
    match e {
        DomainError::Conflict(_) => {
            ResourceManagementError::Conflict(MessageKey::new("api-resource-uri-conflict"))
        }
        DomainError::InvalidValue(_) => {
            ResourceManagementError::Invalid(MessageKey::new("api-resource-uri-invalid"))
        }
        DomainError::NotFound => ResourceManagementError::NotFound,
        other => ResourceManagementError::Internal(other.to_string()),
    }
}
