//! External IdP configuration management use case (AP10. spec §13).
//!
//! A tenant admin (`idp.tenant.admin`; `idp.system.admin` is accepted as an alternative) registers, updates and
//! deletes the external OpenID Providers usable in the tenant.
//!
//! The client secret is stored encrypted with `KEY_ENCRYPTION_KEY`, and **there is no API to read it back**
//! (it is decrypted only at the moment a token request is sent to the external IdP). If the secret is omitted on update,
//! the existing value is kept (making admins paste it every time would break the integration when they forget).
//!
//! Endpoint URLs are validated as https only with internal destinations forbidden. Loosening this would make assay's
//! server a stepping stone that hits arbitrary URLs (SSRF).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::external_idp::{
    ExternalIdentityProvider, ExternalIdpConfig, ExternalIdpProtocol, OidcProviderConfig,
    SamlProviderConfig,
};
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::ExternalIdentityProviderRepository;
use crate::domain::saml_external_idp::NAME_ID_FORMAT_UNSPECIFIED;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// Protocol-specific input for register/update. **Which combinations are valid** is narrowed to one at the entrance
/// (ADR-0027). Putting the OIDC and SAML fields side by side as optional fields would allow a config with only one
/// side filled, and the mistake wouldn't show until login.
#[derive(Debug, Clone)]
pub enum ExternalIdpConfigCommand {
    Oidc {
        authorization_endpoint: String,
        token_endpoint: String,
        jwks_uri: String,
        client_id: String,
        /// Plaintext client secret (`None` when registering as a public client).
        client_secret: Option<String>,
        /// Defaults to `openid profile email` when omitted.
        scopes: Vec<String>,
    },
    Saml {
        sso_url: String,
        /// X.509 certificates for signature verification (base64 DER). During a renewal period, old and new are listed side by side.
        certificates: Vec<String>,
        /// `unspecified` when omitted.
        name_id_format: Option<String>,
    },
}

impl ExternalIdpConfigCommand {
    pub fn protocol(&self) -> ExternalIdpProtocol {
        match self {
            Self::Oidc { .. } => ExternalIdpProtocol::Oidc,
            Self::Saml { .. } => ExternalIdpProtocol::Saml,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegisterExternalIdpCommand {
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    pub config: ExternalIdpConfigCommand,
    pub enabled: bool,
    pub allow_auto_link: bool,
}

/// Partial update. Fields that are `None` are not changed.
///
/// Protocol-specific settings are **replaced as a whole** (`config`). Per-field partial updates would allow
/// half-baked states like "adding only a SAML SSO URL to an OIDC config".
/// Changing the protocol itself is not accepted (register it again as a separate provider) ——switching while keeping
/// the same `provider_code` would leave existing links (`user_external_identities`) pointing at
/// identifiers of the other protocol.
#[derive(Debug, Clone, Default)]
pub struct UpdateExternalIdpCommand {
    pub display_name: Option<String>,
    pub issuer: Option<String>,
    pub config: Option<ExternalIdpConfigCommand>,
    /// OIDC only: `Some(Some(_))` replaces, `Some(None)` deletes (makes it a public client),
    /// `None` keeps. When `config` is replaced, the value on the `config` side takes precedence.
    pub client_secret: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub allow_auto_link: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalIdpManagementError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DomainError> for ExternalIdpManagementError {
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::InvalidValue(m) => Self::Validation(m),
            DomainError::Conflict(m) => Self::Conflict(m),
            other => Self::Internal(other.to_string()),
        }
    }
}

pub struct ExternalIdpManagementService {
    providers: Arc<dyn ExternalIdentityProviderRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    key_encryption_key: [u8; 32],
}

impl ExternalIdpManagementService {
    pub fn new(
        providers: Arc<dyn ExternalIdentityProviderRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        key_encryption_key: [u8; 32],
    ) -> Self {
        Self {
            providers,
            audit,
            clock,
            ids,
            key_encryption_key,
        }
    }

    pub async fn list(
        &self,
        tenant: TenantContext,
    ) -> Result<Vec<ExternalIdentityProvider>, ExternalIdpManagementError> {
        Ok(self.providers.list_for_tenant(tenant.tenant_id()).await?)
    }

    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterExternalIdpCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ExternalIdentityProvider, ExternalIdpManagementError> {
        ExternalIdentityProvider::validate_code(&cmd.provider_code)?;
        validate_display_name(&cmd.display_name)?;
        validate_issuer(&cmd.issuer, cmd.config.protocol())?;

        let now = self.clock.now();
        let provider = ExternalIdentityProvider {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            provider_code: cmd.provider_code,
            display_name: cmd.display_name.trim().to_string(),
            issuer: cmd.issuer.trim().to_string(),
            config: self.build_config(cmd.config, None)?,
            enabled: cmd.enabled,
            allow_auto_link: cmd.allow_auto_link,
            created_at: now,
            updated_at: now,
        };
        self.providers.create(&provider).await?;

        self.audit
            .record(
                AuditEventType::ExternalIdpCreated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("provider={}", provider.provider_code)),
                ctx,
            )
            .await;
        Ok(provider)
    }

    pub async fn update(
        &self,
        tenant: TenantContext,
        id: Uuid,
        cmd: UpdateExternalIdpCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ExternalIdentityProvider, ExternalIdpManagementError> {
        let mut provider = self
            .providers
            .find_by_id(tenant.tenant_id(), id)
            .await?
            .ok_or(ExternalIdpManagementError::NotFound)?;

        if let Some(display_name) = cmd.display_name {
            validate_display_name(&display_name)?;
            provider.display_name = display_name.trim().to_string();
        }
        // URLs go through the same checks on update as on registration (passing registration is pointless if an update can replace them).
        if let Some(issuer) = cmd.issuer {
            validate_issuer(&issuer, provider.protocol())?;
            provider.issuer = issuer.trim().to_string();
        }
        if let Some(config) = cmd.config {
            if config.protocol() != provider.protocol() {
                return Err(ExternalIdpManagementError::Validation(
                    "the protocol of a registered provider cannot be changed".to_string(),
                ));
            }
            provider.config = self.build_config(config, Some(&provider.config))?;
        }
        if let Some(secret) = cmd.client_secret {
            if let ExternalIdpConfig::Oidc(oidc) = &mut provider.config {
                oidc.client_secret_encrypted = self.encrypt_secret(secret.as_deref())?;
            }
        }
        if let Some(enabled) = cmd.enabled {
            provider.enabled = enabled;
        }
        if let Some(allow_auto_link) = cmd.allow_auto_link {
            provider.allow_auto_link = allow_auto_link;
        }

        if !self.providers.update(&provider).await? {
            return Err(ExternalIdpManagementError::NotFound);
        }
        self.audit
            .record(
                AuditEventType::ExternalIdpUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("provider={}", provider.provider_code)),
                ctx,
            )
            .await;
        Ok(provider)
    }

    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ExternalIdpManagementError> {
        let provider = self
            .providers
            .find_by_id(tenant.tenant_id(), id)
            .await?
            .ok_or(ExternalIdpManagementError::NotFound)?;
        if !self.providers.delete(tenant.tenant_id(), id).await? {
            return Err(ExternalIdpManagementError::NotFound);
        }
        self.audit
            .record(
                AuditEventType::ExternalIdpDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("provider={}", provider.provider_code)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Encrypts the plaintext secret (an empty string is normalized to "none").
    fn encrypt_secret(
        &self,
        secret: Option<&str>,
    ) -> Result<Option<String>, ExternalIdpManagementError> {
        match secret.map(str::trim).filter(|s| !s.is_empty()) {
            Some(plain) => crypto::encrypt(plain.as_bytes(), &self.key_encryption_key)
                .map(Some)
                .map_err(|e| ExternalIdpManagementError::Internal(e.to_string())),
            None => Ok(None),
        }
    }

    /// Builds the protocol-specific settings from the input. On update, passing `previous` lets an omitted
    /// secret keep the existing value (making admins paste it every time would break the integration when they forget).
    fn build_config(
        &self,
        cmd: ExternalIdpConfigCommand,
        previous: Option<&ExternalIdpConfig>,
    ) -> Result<ExternalIdpConfig, ExternalIdpManagementError> {
        match cmd {
            ExternalIdpConfigCommand::Oidc {
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                client_id,
                client_secret,
                scopes,
            } => {
                for (url, field) in [
                    (&authorization_endpoint, "authorization_endpoint"),
                    (&token_endpoint, "token_endpoint"),
                    (&jwks_uri, "jwks_uri"),
                ] {
                    ExternalIdentityProvider::validate_endpoint(url, field)?;
                }
                let client_secret_encrypted = match client_secret {
                    Some(plain) => self.encrypt_secret(Some(&plain))?,
                    None => previous
                        .and_then(ExternalIdpConfig::as_oidc)
                        .and_then(|o| o.client_secret_encrypted.clone()),
                };
                Ok(ExternalIdpConfig::Oidc(OidcProviderConfig {
                    authorization_endpoint: authorization_endpoint.trim().to_string(),
                    token_endpoint: token_endpoint.trim().to_string(),
                    jwks_uri: jwks_uri.trim().to_string(),
                    client_id: client_id.trim().to_string(),
                    client_secret_encrypted,
                    scopes,
                }))
            }
            ExternalIdpConfigCommand::Saml {
                sso_url,
                certificates,
                name_id_format,
            } => {
                ExternalIdentityProvider::validate_endpoint(&sso_url, "sso_url")?;
                // Confirm the certificates can be read at registration. If a broken certificate could be saved,
                // the error would first appear **at a user's login** (the admin wouldn't notice).
                let certificates: Vec<String> = certificates
                    .into_iter()
                    .map(|c| c.split_whitespace().collect::<String>())
                    .filter(|c| !c.is_empty())
                    .collect();
                if certificates.is_empty() {
                    return Err(ExternalIdpManagementError::Validation(
                        "a SAML provider needs at least one signing certificate".to_string(),
                    ));
                }
                for certificate in &certificates {
                    crate::domain::xml_signature::SigningCertificateKey::from_base64_certificate(
                        certificate,
                    )?;
                }
                Ok(ExternalIdpConfig::Saml(SamlProviderConfig {
                    sso_url: sso_url.trim().to_string(),
                    certificates,
                    name_id_format: name_id_format
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| NAME_ID_FORMAT_UNSPECIFIED.to_string()),
                }))
            }
        }
    }
}

/// Validation of `issuer` differs by protocol.
///
/// The OIDC `iss` is always an https URL (OIDC Discovery), but **a SAML entityID is not necessarily
/// a URL** (`urn:` forms are valid entityIDs too). Applying the OIDC checks would make correctly configured
/// IdPs impossible to register.
fn validate_issuer(
    issuer: &str,
    protocol: ExternalIdpProtocol,
) -> Result<(), ExternalIdpManagementError> {
    match protocol {
        ExternalIdpProtocol::Oidc => {
            ExternalIdentityProvider::validate_endpoint(issuer, "issuer")?;
        }
        ExternalIdpProtocol::Saml => {
            let trimmed = issuer.trim();
            if trimmed.is_empty() || trimmed.len() > 512 {
                return Err(ExternalIdpManagementError::Validation(
                    "issuer (entityID) must be 1-512 characters".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), ExternalIdpManagementError> {
    if value.trim().is_empty() || value.chars().count() > 255 {
        return Err(ExternalIdpManagementError::Validation(
            "display name must be 1-255 characters".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_must_not_be_blank_or_too_long() {
        assert!(validate_display_name("Corp SSO").is_ok());
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name(&"あ".repeat(256)).is_err());
        assert!(validate_display_name(&"あ".repeat(255)).is_ok());
    }
}
