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
        // 戻り値の bool は「不存在」の判定に使わない。MySQL の `rows_affected` は**値が変わった行**
        // を数えるため、既に同じ状態の行を同じ `updated_at` で更新すると 0 になり、存在する行を
        // 404 にしてしまう。存在は直前の `load` で、消えた場合は末尾の `load` で拾う。
        self.resources
            .set_status(tenant.tenant_id(), id, status, self.clock.now())
            .await
            .map_err(map_repo_error)?;

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

    /// **この認可サーバ自身の名前空間（issuer 配下）は貸さない。**
    ///
    /// いま assay 自身が使っている `aud` は `{issuer}/userinfo` と `{issuer}/admin` の 2 つだが、
    /// 完全一致だけを拒むと `{issuer}/admin/`（末尾スラッシュ）のような**紛らわしい名前が登録できる**。
    /// エンドポイントが増えるたびに「その名前は貸してよかったか」を考え直すことになるので、
    /// 接頭辞で丸ごと予約する。
    ///
    /// ⚠ **これは多層防御であって、これが無いと権限が漏れるという話ではない。**
    /// `{issuer}/admin` を登録できたとしても (1) トークン発行は管理 API の腕が先に当たるので
    /// この表は読まれず、(2) 仮に読まれても `perms` が付かないトークンでは管理 API の
    /// `RequirePerms` が 1 つも通らない（保有コードは `perms` クレームから読む）。
    /// 守っているのは**発行側の分岐の順序という暗黙の前提**であり、並べ替えられた瞬間に
    /// 崩れる種類のものなので、登録の側でも塞いでおく。
    fn ensure_not_reserved(
        &self,
        _tenant: TenantContext,
        resource_uri: &str,
    ) -> Result<(), ResourceManagementError> {
        // テナント接頭辞を含めない基底 issuer で見る。`{base}/{他テナント}/admin` のような、
        // 別テナントの名前を騙る登録も同時に塞げる。
        //
        // 比較は**大小を無視する**。URI のスキームとホストは RFC 3986 §3.1・§3.2.2 が
        // 大小同一と定めるため、大小だけを変えた `HTTPS://…/admin` が素通りしてしまう。
        // 予約領域を広めに取る方向の誤差なので、過剰に弾いても害はない。
        let base = self.base_issuer.trim_end_matches('/').to_ascii_lowercase();
        let candidate = resource_uri.to_ascii_lowercase();
        let inside_our_namespace = candidate == base || candidate.starts_with(&format!("{base}/"));
        if inside_our_namespace {
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
