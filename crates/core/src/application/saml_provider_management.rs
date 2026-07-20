//! SAML IdP 連携設定の管理ユースケース。

use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::SamlIdentityProviderRepository;
use crate::domain::saml_provider::{NewSamlIdentityProvider, SamlIdentityProvider};
use crate::domain::tenant::TenantId;
use std::sync::Arc;

pub struct RegisterSamlProviderCommand {
    pub tenant_id: TenantId,
    pub display_name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub x509_certificate: String,
    pub enabled: bool,
}

#[derive(Debug)]
pub enum SamlProviderManagementError {
    Validation(String),
    Conflict(String),
    Internal(String),
}

pub struct SamlProviderManagementService {
    providers: Arc<dyn SamlIdentityProviderRepository>,
    ids: Arc<dyn IdGenerator>,
    clock: Arc<dyn Clock>,
}

impl SamlProviderManagementService {
    pub fn new(
        providers: Arc<dyn SamlIdentityProviderRepository>,
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
        cmd: RegisterSamlProviderCommand,
    ) -> Result<SamlIdentityProvider, SamlProviderManagementError> {
        let provider = SamlIdentityProvider::register(
            self.ids.new_id(),
            NewSamlIdentityProvider {
                tenant_id: cmd.tenant_id,
                display_name: cmd.display_name,
                entity_id: cmd.entity_id,
                sso_url: cmd.sso_url,
                x509_certificate: cmd.x509_certificate,
                enabled: cmd.enabled,
            },
            self.clock.now(),
        )
        .map_err(|e| SamlProviderManagementError::Validation(e.to_string()))?;

        self.providers
            .create(&provider)
            .await
            .map_err(|e| match e {
                crate::domain::error::DomainError::Conflict(m) => {
                    SamlProviderManagementError::Conflict(m)
                }
                crate::domain::error::DomainError::InvalidValue(m) => {
                    SamlProviderManagementError::Validation(m)
                }
                other => SamlProviderManagementError::Internal(other.to_string()),
            })?;
        Ok(provider)
    }

    pub async fn list(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<SamlIdentityProvider>, SamlProviderManagementError> {
        self.providers
            .list_for_tenant(tenant_id)
            .await
            .map_err(|e| SamlProviderManagementError::Internal(e.to_string()))
    }
}
