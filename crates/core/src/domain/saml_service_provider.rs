//! SAML SP（サービスプロバイダ＝クライアント）登録のドメインモデル。
//!
//! 本プロダクトは IdP であり、SP を登録して SAML アサーションの送信先（ACS URL）を管理する。
//! SP 登録はテナント境界に属し、Entity ID はテナント内で一意に扱う。ACS URL は HTTPS を原則とし、
//! ローカル開発用途のみ `http://localhost` / loopback を許可する。

use crate::domain::error::{DomainError, Result};
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;

/// NameID フォーマットの既定値（未指定時）。
pub const DEFAULT_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

#[derive(Debug, Clone)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// 署名/暗号用証明書（任意）。SP が AuthnRequest 署名等を要求する場合のみ。
    pub x509_certificate: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct NewSamlServiceProvider {
    pub tenant_id: TenantId,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// 既存 SP の変更内容。テナントは変更しない（別テナントへの付け替えは不可）。
pub struct SamlServiceProviderChanges {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

impl SamlServiceProvider {
    pub fn register(id: Uuid, input: NewSamlServiceProvider, now: DateTime<Utc>) -> Result<Self> {
        let fields = ValidatedFields::new(
            input.display_name,
            input.entity_id,
            input.acs_url,
            input.name_id_format,
            input.x509_certificate,
        )?;
        Ok(Self {
            id,
            tenant_id: input.tenant_id,
            display_name: fields.display_name,
            entity_id: fields.entity_id,
            acs_url: fields.acs_url,
            name_id_format: fields.name_id_format,
            x509_certificate: fields.x509_certificate,
            enabled: input.enabled,
            created_at: now,
            updated_at: now,
        })
    }

    /// 変更内容を検証して適用する（テナント・id・created_at は不変。updated_at を更新する）。
    pub fn apply(&mut self, changes: SamlServiceProviderChanges, now: DateTime<Utc>) -> Result<()> {
        let fields = ValidatedFields::new(
            changes.display_name,
            changes.entity_id,
            changes.acs_url,
            changes.name_id_format,
            changes.x509_certificate,
        )?;
        self.display_name = fields.display_name;
        self.entity_id = fields.entity_id;
        self.acs_url = fields.acs_url;
        self.name_id_format = fields.name_id_format;
        self.x509_certificate = fields.x509_certificate;
        self.enabled = changes.enabled;
        self.updated_at = now;
        Ok(())
    }
}

/// 登録・変更で共通の入力検証・正規化結果。
struct ValidatedFields {
    display_name: String,
    entity_id: String,
    acs_url: String,
    name_id_format: String,
    x509_certificate: Option<String>,
}

impl ValidatedFields {
    fn new(
        display_name: String,
        entity_id: String,
        acs_url: String,
        name_id_format: String,
        x509_certificate: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            display_name: required(display_name, "display_name")?,
            entity_id: required(entity_id, "entity_id")?,
            acs_url: validate_acs_url(&acs_url)?,
            name_id_format: match name_id_format.trim() {
                "" => DEFAULT_NAME_ID_FORMAT.to_string(),
                other => other.to_string(),
            },
            x509_certificate: x509_certificate
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty()),
        })
    }
}

/// ACS URL の検証。HTTPS を原則とし、ローカル開発のみ `http://localhost` / loopback を許可する。
pub fn validate_acs_url(raw: &str) -> Result<String> {
    let trimmed = required(raw.to_string(), "acs_url")?;
    let parsed = Url::parse(&trimmed)
        .map_err(|_| DomainError::InvalidValue("acs_url must be a valid URL".to_string()))?;
    match parsed.scheme() {
        "https" => Ok(trimmed),
        "http" if is_localhost(&parsed) => Ok(trimmed),
        _ => Err(DomainError::InvalidValue(
            "acs_url must use https or localhost http".to_string(),
        )),
    }
}

fn required(value: String, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DomainError::InvalidValue(format!("{field} is required")));
    }
    Ok(trimmed.to_string())
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_acs_url() {
        assert!(validate_acs_url("http://sp.evil.test/acs").is_err());
        assert!(validate_acs_url("ftp://sp.example.test/acs").is_err());
    }

    #[test]
    fn accepts_https_and_loopback_acs_url() {
        assert!(validate_acs_url("https://sp.example.test/acs").is_ok());
        assert!(validate_acs_url("http://localhost:8080/acs").is_ok());
    }

    #[test]
    fn defaults_name_id_format_when_blank() {
        let sp = SamlServiceProvider::register(
            Uuid::nil(),
            NewSamlServiceProvider {
                tenant_id: Uuid::nil().into(),
                display_name: "App".to_string(),
                entity_id: "urn:sp".to_string(),
                acs_url: "https://sp.example.test/acs".to_string(),
                name_id_format: "   ".to_string(),
                x509_certificate: Some("  ".to_string()),
                enabled: true,
            },
            Utc::now(),
        )
        .expect("register");
        assert_eq!(sp.name_id_format, DEFAULT_NAME_ID_FORMAT);
        // 空白のみの証明書は None に正規化する。
        assert_eq!(sp.x509_certificate, None);
    }

    #[test]
    fn apply_updates_fields_and_validates() {
        let created = Utc::now();
        let mut sp = SamlServiceProvider::register(
            Uuid::nil(),
            NewSamlServiceProvider {
                tenant_id: Uuid::nil().into(),
                display_name: "App".to_string(),
                entity_id: "urn:sp".to_string(),
                acs_url: "https://sp.example.test/acs".to_string(),
                name_id_format: String::new(),
                x509_certificate: None,
                enabled: true,
            },
            created,
        )
        .expect("register");

        let later = created + chrono::Duration::seconds(5);
        sp.apply(
            SamlServiceProviderChanges {
                display_name: "Renamed".to_string(),
                entity_id: "urn:sp:renamed".to_string(),
                acs_url: "https://sp.example.test/acs2".to_string(),
                name_id_format: String::new(),
                x509_certificate: Some("cert".to_string()),
                enabled: false,
            },
            later,
        )
        .expect("apply");

        assert_eq!(sp.display_name, "Renamed");
        assert_eq!(sp.entity_id, "urn:sp:renamed");
        assert_eq!(sp.acs_url, "https://sp.example.test/acs2");
        assert_eq!(sp.name_id_format, DEFAULT_NAME_ID_FORMAT);
        assert_eq!(sp.x509_certificate.as_deref(), Some("cert"));
        assert!(!sp.enabled);
        // id・created_at は不変、updated_at のみ進む。
        assert_eq!(sp.id, Uuid::nil());
        assert_eq!(sp.created_at, created);
        assert_eq!(sp.updated_at, later);

        // 非 HTTPS ACS は拒否し、状態は変更しない。
        assert!(sp
            .apply(
                SamlServiceProviderChanges {
                    display_name: "X".to_string(),
                    entity_id: "urn:sp:x".to_string(),
                    acs_url: "http://sp.evil.test/acs".to_string(),
                    name_id_format: String::new(),
                    x509_certificate: None,
                    enabled: true,
                },
                later,
            )
            .is_err());
        assert_eq!(sp.display_name, "Renamed");
    }
}
