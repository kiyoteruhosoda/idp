//! システム用クライアントへの管理権限の付与・剥奪・参照（ADR-0037）。
//!
//! 利用者への付与（`permission_management`）と別サービスにするのは、**付与できるコードの集合が
//! 違う**ためである。クライアントには包括的な管理権限（`idp.system.admin` / `idp.tenant.admin`）を
//! 付与させない。1 つのサービスに両方を通すと、この違いが `if` の分岐として埋もれる。
//!
//! 判定は本 Application 層で行い、Presentation には結果のみ渡す（CLAUDE.md「権限管理」）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;
use crate::domain::permission::{self, PermissionCode};
use crate::domain::repositories::{ClientPermissionRepository, ClientRepository};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientPermissionError {
    /// 対象クライアントが要求テナントに存在しない（削除済みを含む）。
    NotFound,
    /// 権限コードが不正（空・未知・クライアントへ付与できないコード）。
    Invalid(MessageKey),
    Internal(String),
}

pub struct ClientPermissionManagementService {
    clients: Arc<dyn ClientRepository>,
    client_permissions: Arc<dyn ClientPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl ClientPermissionManagementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            client_permissions,
            audit,
            clock,
        }
    }

    /// 対象クライアントが保有する権限コードを一覧する（昇順）。
    pub async fn list(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let client = self.load_client(tenant, client_id).await?;
        let mut codes = self
            .client_permissions
            .list_codes_for_client(client.id)
            .await
            .map_err(map_repo_error)?;
        codes.sort();
        Ok(codes)
    }

    /// 権限コードを付与する（冪等）。付与後の保有コード一覧を返す。
    pub async fn grant(
        &self,
        tenant: TenantContext,
        client_id: &str,
        raw_code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let code = parse_code(raw_code)?;
        let client = self.load_client(tenant, client_id).await?;

        // 包括的な管理権限はクライアントへ付与しない（DB の CHECK 制約と二重防御）。
        // ここで落とすのは、DB 制約違反を利用者向けの文言に翻訳するためでもある。
        if !permission::is_grantable_to_client(code.as_str()) {
            return Err(ClientPermissionError::Invalid(MessageKey::new(
                "api-client-permission-not-grantable",
            )));
        }

        self.client_permissions
            .grant(client.id, code.as_str(), self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientPermissionGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                // `client_id` 列は操作対象のクライアント。実行主体が機械のときは理由欄へ回す。
                Some(&client.client_id),
                Some(&audit_reason(code.as_str(), actor)),
                ctx,
            )
            .await;
        self.list(tenant, client_id).await
    }

    /// 権限コードを剥奪する（未保有でもエラーにしない）。剥奪後の保有コード一覧を返す。
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        client_id: &str,
        raw_code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let code = parse_code(raw_code)?;
        let client = self.load_client(tenant, client_id).await?;

        self.client_permissions
            .revoke(client.id, code.as_str())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientPermissionRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                Some(&audit_reason(code.as_str(), actor)),
                ctx,
            )
            .await;
        self.list(tenant, client_id).await
    }

    /// 要求テナント内で有効なクライアントを解決する。他テナントの `client_id` は解決しない。
    async fn load_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<crate::domain::client::Client, ClientPermissionError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            // 論理削除済み（ADR-0035）は「無い」として扱う。権限だけ付け替えられると、
            // 削除したはずのクライアントが復活したときに知らない権限を持っている。
            Ok(Some(client)) if !client.is_deleted() => Ok(client),
            Ok(_) => Err(ClientPermissionError::NotFound),
            Err(e) => Err(ClientPermissionError::Internal(e.to_string())),
        }
    }
}

fn parse_code(raw: &str) -> Result<PermissionCode, ClientPermissionError> {
    PermissionCode::parse(raw.trim()).map_err(|_| {
        ClientPermissionError::Invalid(MessageKey::new("api-permission-code-required"))
    })
}

/// 監査ログの `reason`（PII を含めない。権限コードと、機械が実行した場合はその `client_id`）。
fn audit_reason(code: &str, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("permission={code} {note}"),
        None => format!("permission={code}"),
    }
}

fn map_repo_error(e: DomainError) -> ClientPermissionError {
    match e {
        // 未知の権限コード（FK 違反）・CHECK 違反はいずれも入力の誤り。
        DomainError::InvalidValue(_) => {
            ClientPermissionError::Invalid(MessageKey::new("api-client-permission-not-grantable"))
        }
        other => ClientPermissionError::Internal(other.to_string()),
    }
}
