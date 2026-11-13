//! WebAuthn (FIDO2 passkey) credential entity.
//!
//! One record holds one passkey device registered by a user.
//! `passkey_json` holds the whole JSON-serialized `Passkey` struct of `webauthn-rs` (public key,
//! sign_count, transports, etc.).
//! `credential_id` is an index field (base64url string) to quickly find which `passkey_json`
//! to use when an authentication response arrives.

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    /// WebAuthn credential ID (base64url). Used for reverse lookup when resolving `passkey_challenges`.
    pub credential_id: String,
    /// `webauthn_rs::prelude::Passkey` serialized as a JSON string.
    pub passkey_json: String,
    /// Optional label set by the user (e.g. "MacBook Touch ID").
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Time of the latest successful authentication (updated together with sign_count).
    pub last_used_at: Option<DateTime<Utc>>,
}
