//! Use cases for managing SAML SP (client) registrations.

use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
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

/// Command to update an existing SP. The target is identified by `id` within the tenant boundary.
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
    Validation(MessageKey),
    Conflict(MessageKey),
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
        .map_err(SamlServiceProviderManagementError::Validation)?;

        self.providers
            .create(&provider)
            .await
            .map_err(|e| match e {
                // The unique key is only (tenant_id, entity_id).
                crate::domain::error::DomainError::Conflict(_) => {
                    SamlServiceProviderManagementError::Conflict(MessageKey::new(
                        "api-saml-sp-entity-id-conflict",
                    ))
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
            .map_err(SamlServiceProviderManagementError::Validation)?;

        let updated = self
            .providers
            .update(&provider)
            .await
            .map_err(|e| match e {
                crate::domain::error::DomainError::Conflict(_) => {
                    SamlServiceProviderManagementError::Conflict(MessageKey::new(
                        "api-saml-sp-entity-id-conflict",
                    ))
                }
                other => SamlServiceProviderManagementError::Internal(other.to_string()),
            })?;
        // A race where another admin deleted it after find_by_id succeeded (0 rows updated) is treated as not-found.
        if !updated {
            return Err(SamlServiceProviderManagementError::NotFound);
        }
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
