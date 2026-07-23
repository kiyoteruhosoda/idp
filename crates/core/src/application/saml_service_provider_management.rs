//! SAML SP（クライアント）登録の管理ユースケース。

use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::SamlServiceProviderRepository;
use crate::domain::saml_service_provider::{
    NewSamlServiceProvider, SamlServiceProvider, SamlServiceProviderChanges,
};
use crate::domain::tenant::TenantId;
use std::sync::Arc;
use uuid::Uuid;

pub struct RegisterSamlServiceProviderCommand {
    pub tenant_id: TenantId,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// 既存 SP の更新コマンド。対象はテナント境界内の `id` で特定する。
pub struct UpdateSamlServiceProviderCommand {
    pub tenant_id: TenantId,
    pub id: Uuid,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

#[derive(Debug)]
pub enum SamlServiceProviderManagementError {
    Validation(String),
    Conflict(String),
    NotFound,
    Internal(String),
}

pub struct SamlServiceProviderManagementService {
    providers: Arc<dyn SamlServiceProviderRepository>,
    ids: Arc<dyn IdGenerator>,
    clock: Arc<dyn Clock>,
}

impl SamlServiceProviderManagementService {
    pub fn new(
        providers: Arc<dyn SamlServiceProviderRepository>,
        ids: Arc<dyn IdGenerator>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            providers,
            ids,
            clock,
        }
    }

    pub async fn register(
        &self,
        cmd: RegisterSamlServiceProviderCommand,
    ) -> Result<SamlServiceProvider, SamlServiceProviderManagementError> {
        let provider = SamlServiceProvider::register(
            self.ids.new_id(),
            NewSamlServiceProvider {
                tenant_id: cmd.tenant_id,
                display_name: cmd.display_name,
                entity_id: cmd.entity_id,
                acs_url: cmd.acs_url,
                name_id_format: cmd.name_id_format,
                x509_certificate: cmd.x509_certificate,
                enabled: cmd.enabled,
            },
            self.clock.now(),
        )
        .map_err(|e| SamlServiceProviderManagementError::Validation(e.to_string()))?;

        self.providers
            .create(&provider)
            .await
            .map_err(|e| match e {
                crate::domain::error::DomainError::Conflict(m) => {
                    SamlServiceProviderManagementError::Conflict(m)
                }
                crate::domain::error::DomainError::InvalidValue(m) => {
                    SamlServiceProviderManagementError::Validation(m)
                }
                other => SamlServiceProviderManagementError::Internal(other.to_string()),
            })?;
        Ok(provider)
    }

    pub async fn list(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<SamlServiceProvider>, SamlServiceProviderManagementError> {
        self.providers
            .list_for_tenant(tenant_id)
            .await
            .map_err(|e| SamlServiceProviderManagementError::Internal(e.to_string()))
    }

    pub async fn update(
        &self,
        cmd: UpdateSamlServiceProviderCommand,
    ) -> Result<SamlServiceProvider, SamlServiceProviderManagementError> {
        let mut provider = self
            .providers
            .find_by_id(cmd.tenant_id, cmd.id)
            .await
            .map_err(|e| SamlServiceProviderManagementError::Internal(e.to_string()))?
            .ok_or(SamlServiceProviderManagementError::NotFound)?;

        provider
            .apply(
                SamlServiceProviderChanges {
                    display_name: cmd.display_name,
                    entity_id: cmd.entity_id,
                    acs_url: cmd.acs_url,
                    name_id_format: cmd.name_id_format,
                    x509_certificate: cmd.x509_certificate,
                    enabled: cmd.enabled,
                },
                self.clock.now(),
            )
            .map_err(|e| SamlServiceProviderManagementError::Validation(e.to_string()))?;

        self.providers
            .update(&provider)
            .await
            .map_err(|e| match e {
                crate::domain::error::DomainError::Conflict(m) => {
                    SamlServiceProviderManagementError::Conflict(m)
                }
                crate::domain::error::DomainError::InvalidValue(m) => {
                    SamlServiceProviderManagementError::Validation(m)
                }
                other => SamlServiceProviderManagementError::Internal(other.to_string()),
            })?;
        Ok(provider)
    }

    pub async fn delete(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<(), SamlServiceProviderManagementError> {
        let deleted = self
            .providers
            .delete(tenant_id, id)
            .await
            .map_err(|e| SamlServiceProviderManagementError::Internal(e.to_string()))?;
        if deleted {
            Ok(())
        } else {
            Err(SamlServiceProviderManagementError::NotFound)
        }
    }
}
