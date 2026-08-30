//! 外部 IdP 設定の管理ユースケース（AP10。仕様 §13）。
//!
//! テナント管理者（`idp.tenant.admin`。`idp.system.admin` は代替として許可）が、テナントで使える
//! 外部 OpenID Provider を登録・更新・削除する。
//!
//! クライアントシークレットは `KEY_ENCRYPTION_KEY` で暗号化して保存し、**読み出す API を持たない**
//! （復号するのは外部 IdP へトークン要求を出す瞬間だけ）。更新時にシークレットを省略したら
//! 既存値を維持する（毎回貼り直させると、貼り忘れで連携が壊れる）。
//!
//! エンドポイント URL は https のみ・内部宛先禁止で検証する。ここを緩めると、assay のサーバに
//! 任意の URL を叩かせる（SSRF の）踏み台になる。

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

/// 登録・更新で受け取るプロトコル固有の入力。**どの組み合わせが妥当か**を入口で 1 つに絞る
/// （ADR-0027）。OIDC の欄と SAML の欄を並べて任意項目にすると、片方だけ埋めた設定を作れて
/// しまい、誤りがログイン時まで見えない。
#[derive(Debug, Clone)]
pub enum ExternalIdpConfigCommand {
    Oidc {
        authorization_endpoint: String,
        token_endpoint: String,
        jwks_uri: String,
        client_id: String,
        /// 平文のクライアントシークレット（public クライアントとして登録するなら `None`）。
        client_secret: Option<String>,
        /// 省略時は既定（`openid profile email`）。
        scopes: Vec<String>,
    },
    Saml {
        sso_url: String,
        /// 署名検証に使う X.509 証明書（base64 DER）。更新期間には新旧 2 枚を並べる。
        certificates: Vec<String>,
        /// 省略時は `unspecified`。
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

/// 部分更新。`None` のフィールドは変更しない。
///
/// プロトコル固有の設定は**まとめて差し替える**（`config`）。項目ごとの部分更新にすると
/// 「OIDC の設定に SAML の SSO URL だけを足す」ような中途半端な状態を作れてしまう。
/// プロトコルそのものの変更は受け付けない（別プロバイダとして登録し直す）——同じ
/// `provider_code` のまま切り替えると、既存の連携（`user_external_identities`）が
/// 別プロトコルの識別子を指したまま残る。
#[derive(Debug, Clone, Default)]
pub struct UpdateExternalIdpCommand {
    pub display_name: Option<String>,
    pub issuer: Option<String>,
    pub config: Option<ExternalIdpConfigCommand>,
    /// OIDC のみ: `Some(Some(_))` で差し替え、`Some(None)` で削除（public クライアント化）、
    /// `None` で維持。`config` を差し替えるときは `config` 側の値が優先される。
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
        // URL 系は更新時も登録時と同じ検査を通す（登録を通しても更新で差し替えられては意味がない）。
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

    /// 入力をプロトコル固有の設定へ組み立てる。更新時は `previous` を渡すと、シークレットの
    /// 省略で既存値を維持できる（毎回貼り直させると、貼り忘れで連携が壊れる）。
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
                // 証明書は登録時に読めることを確かめる。壊れた証明書を保存できてしまうと、
                // 誤りが**利用者のログイン時**に初めて出る（管理者は気づけない）。
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

/// `issuer` の検証はプロトコルで違う。
///
/// OIDC の `iss` は必ず https の URL（OIDC Discovery）だが、**SAML の entityID は URL とは
/// 限らない**（`urn:` 形式も正当な entityID である）。OIDC と同じ検査を掛けると、正しく設定
/// された IdP を登録できなくなる。
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
