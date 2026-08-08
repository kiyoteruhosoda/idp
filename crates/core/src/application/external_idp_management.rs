//! 外部 IdP 設定の管理ユースケース（AP10。仕様 §13）。
//!
//! テナント管理者（`idp.tenant.admin`。`idp.system.admin` は代替として許可）が、テナントで使える
//! 外部 OpenID Provider を登録・更新・削除する。
//!
//! クライアントシークレットは `KEY_ENCRYPTION_KEY` で暗号化して保存し、**読み出す API を持たない**
//! （復号するのは外部 IdP へトークン要求を出す瞬間だけ）。更新時にシークレットを省略したら
//! 既存値を維持する（毎回貼り直させると、貼り忘れで連携が壊れる）。
//!
//! エンドポイント URL は https のみ・内部宛先禁止で検証する。ここを緩めると、本 IdP のサーバに
//! 任意の URL を叩かせる（SSRF の）踏み台になる。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::external_idp::ExternalIdentityProvider;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::ExternalIdentityProviderRepository;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RegisterExternalIdpCommand {
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// 平文のクライアントシークレット（public クライアントとして登録するなら `None`）。
    pub client_secret: Option<String>,
    /// 省略時は既定（`openid profile email`）。
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub allow_auto_link: bool,
}

/// 部分更新。`None` のフィールドは変更しない。
#[derive(Debug, Clone, Default)]
pub struct UpdateExternalIdpCommand {
    pub display_name: Option<String>,
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: Option<String>,
    /// `Some(Some(_))` で差し替え、`Some(None)` で削除（public クライアント化）、`None` で維持。
    pub client_secret: Option<Option<String>>,
    pub scopes: Option<Vec<String>>,
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
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<ExternalIdentityProvider, ExternalIdpManagementError> {
        ExternalIdentityProvider::validate_code(&cmd.provider_code)?;
        validate_display_name(&cmd.display_name)?;
        ExternalIdentityProvider::validate_endpoint(&cmd.issuer, "issuer")?;
        ExternalIdentityProvider::validate_endpoint(
            &cmd.authorization_endpoint,
            "authorization_endpoint",
        )?;
        ExternalIdentityProvider::validate_endpoint(&cmd.token_endpoint, "token_endpoint")?;
        ExternalIdentityProvider::validate_endpoint(&cmd.jwks_uri, "jwks_uri")?;

        let now = self.clock.now();
        let provider = ExternalIdentityProvider {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            provider_code: cmd.provider_code,
            display_name: cmd.display_name.trim().to_string(),
            issuer: cmd.issuer.trim().to_string(),
            authorization_endpoint: cmd.authorization_endpoint.trim().to_string(),
            token_endpoint: cmd.token_endpoint.trim().to_string(),
            jwks_uri: cmd.jwks_uri.trim().to_string(),
            client_id: cmd.client_id.trim().to_string(),
            client_secret_encrypted: self.encrypt_secret(cmd.client_secret.as_deref())?,
            scopes: cmd.scopes,
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
                Some(actor),
                None,
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
        actor: Uuid,
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
        // URL 系は更新時も登録時と同じ検査を通す（登録を通しても更新で差し替えられては意味がない）。
        for (value, field, target) in [
            (cmd.issuer, "issuer", &mut provider.issuer),
            (
                cmd.authorization_endpoint,
                "authorization_endpoint",
                &mut provider.authorization_endpoint,
            ),
            (cmd.token_endpoint, "token_endpoint", &mut provider.token_endpoint),
            (cmd.jwks_uri, "jwks_uri", &mut provider.jwks_uri),
        ] {
            if let Some(url) = value {
                ExternalIdentityProvider::validate_endpoint(&url, field)?;
                *target = url.trim().to_string();
            }
        }
        if let Some(client_id) = cmd.client_id {
            provider.client_id = client_id.trim().to_string();
        }
        if let Some(secret) = cmd.client_secret {
            provider.client_secret_encrypted = self.encrypt_secret(secret.as_deref())?;
        }
        if let Some(scopes) = cmd.scopes {
            provider.scopes = scopes;
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
                Some(actor),
                None,
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
        actor: Uuid,
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
                Some(actor),
                None,
                Some(&format!("provider={}", provider.provider_code)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// 平文のシークレットを暗号化する（空文字は「無し」に正規化する）。
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
