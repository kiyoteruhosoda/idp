//! RevokedAccessTokens entity (F5: token management §9.4). Records revoked jti values of JWT access
//! tokens so /userinfo and /introspect revoke them immediately.
#![allow(dead_code)]

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct RevokedAccessToken {
    pub jti: String,
    pub revoked_at: DateTime<Utc>,
    /// The exp of the original access token. Entries past expires_at can be cleaned up.
    pub expires_at: DateTime<Utc>,
}
