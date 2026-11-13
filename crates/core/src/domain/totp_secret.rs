//! TOTP (Time-based One-Time Password) secret entity.
//!
//! MFA is optional. Users register, confirm, and delete it themselves.
//! `confirmed_at IS NULL` means provisionally registered (QR confirmation not completed).
//! `confirmed_at IS NOT NULL` means an active MFA setting.

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TotpSecret {
    pub user_id: Uuid,
    /// Secret bytes encrypted with AES-256-GCM (the `crypto::encrypt` scheme).
    pub secret_encrypted: String,
    /// NULL = provisionally registered, non-NULL = activated.
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TotpSecret {
    /// Whether TOTP is active (the user has completed setup).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}
