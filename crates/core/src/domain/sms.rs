//! Port for sending SMS (DIP boundary; AP13; used by SMS OTP).
//!
//! Shaped like mail delivery ([`crate::domain::mailer`]): connection info changes at runtime via
//! system settings (`system_settings`), so it is received **per send** rather than at construction.
//!
//! # Not choosing a carrier
//!
//! SMS gateway APIs differ per provider, and which to use is a per-deployment decision (country,
//! price, deliverability, contract). Leaning on one provider here would change the code every time
//! we re-choose. So assay's interface is a generic gateway that **just POSTs one JSON**, and
//! provider-specific differences are pushed out to a small relay (function / webhook) on the
//! operations side. The relay receives the shape of [`OutgoingSms`]; provider SDKs are not brought
//! into this repository.
//!
//! # PII
//!
//! Phone numbers are PII. Never put them in logs, audit records, or error messages (`Debug` is not
//! implemented to prevent leaks via `{:?}` by type). They are stored in the `target` column of the
//! authenticator registry, treated like the destination address of email OTP.

use crate::domain::error::Result;
use async_trait::async_trait;

/// SMS gateway connection info (the values used at send time; the token is decrypted plaintext).
///
/// Deliberately does not implement `Debug` (the type prevents the token leaking into logs via
/// `{:?}`).
#[derive(Clone)]
pub struct SmsGatewayConfig {
    /// URL to POST send requests to.
    pub endpoint_url: String,
    /// Auth header name (e.g. `Authorization`). Empty string = no auth header.
    pub auth_header: String,
    /// Auth header value (e.g. `Bearer xxx`). Empty string = no auth header.
    pub auth_token: String,
    /// Sender display (the value a provider treats as `sender id` / `from`). Empty string =
    /// unspecified.
    pub sender_id: String,
}

impl SmsGatewayConfig {
    /// Whether sending is configured (SMS sending is disabled when the URL is empty).
    pub fn is_usable(&self) -> bool {
        !self.endpoint_url.trim().is_empty()
    }
}

/// One SMS to send.
///
/// Does not implement `Debug` (the recipient is PII and the body carries a one-time code).
#[derive(Clone)]
pub struct OutgoingSms {
    /// Recipient phone number (E.164-normalized).
    pub to: String,
    pub body_text: String,
}

/// Port for sending SMS. Implementations send without blocking and return permanent failures as
/// errors.
#[async_trait]
pub trait SmsSender: Send + Sync {
    async fn send(&self, gateway: &SmsGatewayConfig, sms: &OutgoingSms) -> Result<()>;
}
