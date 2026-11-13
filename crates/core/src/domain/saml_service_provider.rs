//! Domain model for SAML SP (service provider = client) registration.
//!
//! This product is an IdP; it registers SPs and manages where SAML assertions are sent (ACS URL).
//! SP registrations belong to a tenant boundary, and the Entity ID is unique within a tenant. ACS
//! URLs must be HTTPS in principle; only `http://localhost` / loopback is allowed for local
//! development.

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use url::Url;
use uuid::Uuid;

/// Default NameID format (when unspecified).
pub const DEFAULT_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

#[derive(Debug, Clone)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// Signing/encryption certificate (optional). Only when the SP requires e.g. AuthnRequest
    /// signing.
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

/// Changes to an existing SP. The tenant is not changed (moving to another tenant is not allowed).
pub struct SamlServiceProviderChanges {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

impl SamlServiceProvider {
    pub fn register(
        id: Uuid,
        input: NewSamlServiceProvider,
        now: DateTime<Utc>,
    ) -> std::result::Result<Self, MessageKey> {
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

    /// Validates and applies the changes (tenant, id, created_at are immutable; updated_at is
    /// updated).
    pub fn apply(
        &mut self,
        changes: SamlServiceProviderChanges,
        now: DateTime<Utc>,
    ) -> std::result::Result<(), MessageKey> {
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

/// Input validation / normalization result shared by registration and update.
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
    ) -> std::result::Result<Self, MessageKey> {
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

/// ACS URL validation. HTTPS in principle; only `http://localhost` / loopback is allowed for local
/// development.
pub fn validate_acs_url(raw: &str) -> std::result::Result<String, MessageKey> {
    let trimmed = required(raw.to_string(), "acs_url")?;
    let parsed =
        Url::parse(&trimmed).map_err(|_| MessageKey::new("api-saml-sp-acs-url-invalid"))?;
    match parsed.scheme() {
        "https" => Ok(trimmed),
        "http" if is_localhost(&parsed) => Ok(trimmed),
        _ => Err(MessageKey::new("api-saml-sp-acs-url-scheme")),
    }
}

/// Emptiness check of required fields. Returns a translation key, not text, and names the field via
/// the value (MT19).
fn required(value: String, field: &'static str) -> std::result::Result<String, MessageKey> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(MessageKey::with_value("api-field-required", field));
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
        // A whitespace-only certificate is normalized to None.
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
        // id and created_at are immutable; only updated_at advances.
        assert_eq!(sp.id, Uuid::nil());
        assert_eq!(sp.created_at, created);
        assert_eq!(sp.updated_at, later);

        // A non-HTTPS ACS is rejected and the state is unchanged.
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
