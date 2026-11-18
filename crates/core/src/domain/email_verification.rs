//! Email verification tokens (proof of email ownership for self-registered accounts; SEC6b).
//!
//! The plaintext token reaches the user only via the email link; only its SHA-256 hex
//! (`token_hash`) is stored. Setting `used_at` makes it single-use (the same one-time pattern as
//! password_reset_tokens).

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EmailVerificationToken {
    /// SHA-256 hex of the verification token (the plaintext is not stored).
    pub token_hash: String,
    pub user_id: Uuid,
    pub expires_at: OffsetDateTime,
    /// Consumption time. `None` = unused.
    pub used_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}
