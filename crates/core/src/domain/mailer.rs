//! Port for mail delivery (DIP boundary; used by MT17 invitation mail and MT18 password reset).
//!
//! SMTP connection info is changed at runtime via system settings (`system_settings`; MT14), so it
//! is received **per send** rather than at construction. The implementation (lettre) is in
//! `infrastructure::mailer`. `SmtpServerConfig::password` is a plaintext secret; never put it in
//! logs, audit records, or error messages.

use crate::domain::error::Result;
use async_trait::async_trait;

/// Which route this connection info belongs to (ADR-0058 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpRoute {
    /// The global route. Only root decides it.
    WholeIdp,
    /// A tenant's route. Tenant admins decide it, so the recipient is checked before sending (task
    /// #740).
    Tenant,
}

/// SMTP connection info (the values used at delivery; the password is decrypted plaintext).
///
/// Deliberately does not implement `Debug` (the type prevents the password leaking into logs via
/// `{:?}`).
#[derive(Clone)]
pub struct SmtpServerConfig {
    pub host: String,
    /// When unset, the protocol default is used (465/587 with TLS, 25 without).
    pub port: Option<u16>,
    /// Empty string = no SMTP authentication.
    pub username: String,
    pub password: String,
    /// Sender address (`From`).
    pub from_address: String,
    pub use_tls: bool,
    pub route: SmtpRoute,
}

/// One mail to send (plain text only; HTML mail is not handled).
#[derive(Debug, Clone)]
pub struct OutgoingEmail {
    pub to: String,
    pub subject: String,
    pub body_text: String,
}

/// Port for mail delivery. Implementations send without blocking and return permanent failures as
/// errors.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> Result<()>;
}
