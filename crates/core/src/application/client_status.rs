//! Client status list use case (status screen A3).
//!
//! Joins registered clients (`ClientRepository`) with the **last used time** from the audit log (`AuditLogQuery`)
//! to build a status view for operators (state, scope, last used time). It is read-only and kept
//! separate from `ClientManagementService` (changes), which registers and updates clients (SRP).

use crate::domain::client::Client;
use crate::domain::error::DomainError;
use crate::domain::repositories::{AuditLogQuery, ClientRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::ClientStatus;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;

/// Status of one client (read model).
#[derive(Debug, Clone)]
pub struct ClientStatusView {
    pub client_id: String,
    pub app_name: String,
    pub status: ClientStatus,
    pub scopes: Vec<String>,
    /// Last used time (latest successful token issuance or authorization code issuance). `None` if never used.
    pub last_used_at: Option<DateTime<Utc>>,
}

pub struct ClientStatusService {
    clients: Arc<dyn ClientRepository>,
    audit_logs: Arc<dyn AuditLogQuery>,
}

impl ClientStatusService {
    pub fn new(clients: Arc<dyn ClientRepository>, audit_logs: Arc<dyn AuditLogQuery>) -> Self {
        Self {
            clients,
            audit_logs,
        }
    }

    /// Returns the status of every client in the given tenant, newest registration first (the order of `ClientRepository::list`).
    pub async fn list(&self, tenant: TenantContext) -> Result<Vec<ClientStatusView>, DomainError> {
        let clients = self.clients.list(tenant.tenant_id()).await?;
        let last_used: HashMap<String, DateTime<Utc>> = self
            .audit_logs
            .last_used_per_client(tenant.tenant_id())
            .await?
            .into_iter()
            .collect();
        Ok(clients
            .into_iter()
            .map(|c| to_view(c, &last_used))
            .collect())
    }
}

fn to_view(client: Client, last_used: &HashMap<String, DateTime<Utc>>) -> ClientStatusView {
    ClientStatusView {
        last_used_at: last_used.get(&client.client_id).copied(),
        client_id: client.client_id,
        app_name: client.app_name,
        status: client.client_status,
        scopes: client.scopes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::{AuditLogEntry, AuditLogFilter};
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{ClientType, TokenEndpointAuthMethod};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn client(client_id: &str, app_name: &str) -> Client {
        Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::now_v7().into(),
            client_id: client_id.to_string(),
            client_secret_hash: None,
            client_type: ClientType::Public,
            client_status: ClientStatus::Active,
            app_name: app_name.to_string(),
            redirect_uris: vec!["https://a.example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string()],
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    struct FakeClients(Vec<Client>);
    #[async_trait]
    impl ClientRepository for FakeClients {
        async fn find_by_client_id(&self, _t: TenantId, _id: &str) -> DomainResult<Option<Client>> {
            unreachable!()
        }
        async fn create(&self, _c: &Client) -> DomainResult<()> {
            unreachable!()
        }
        async fn list(&self, _t: TenantId) -> DomainResult<Vec<Client>> {
            Ok(self.0.clone())
        }
        async fn update(&self, _c: &Client) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeAuditLogs(Vec<(String, DateTime<Utc>)>);
    #[async_trait]
    impl AuditLogQuery for FakeAuditLogs {
        async fn search(&self, _f: &AuditLogFilter) -> DomainResult<Vec<AuditLogEntry>> {
            unreachable!()
        }
        async fn last_used_per_client(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<(String, DateTime<Utc>)>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn joins_clients_with_last_used_and_leaves_unused_as_none() {
        let used_at = Utc.with_ymd_and_hms(2026, 7, 6, 10, 0, 0).unwrap();
        let svc = ClientStatusService::new(
            Arc::new(FakeClients(vec![
                client("used", "Used App"),
                client("fresh", "Fresh App"),
            ])),
            Arc::new(FakeAuditLogs(vec![("used".to_string(), used_at)])),
        );
        let views = svc
            .list(TenantContext::new(Uuid::now_v7().into()))
            .await
            .expect("list ok");
        assert_eq!(views.len(), 2);
        // Keep the order of clients.list.
        assert_eq!(views[0].client_id, "used");
        assert_eq!(views[0].last_used_at, Some(used_at));
        assert_eq!(views[1].client_id, "fresh");
        assert_eq!(views[1].last_used_at, None, "never used is None");
    }
}
