//! Temporary passkey challenge entity.
//!
//! Between the begin → complete steps of the WebAuthn handshake, keeps in the DB the intermediate
//! challenge state returned by `webauthn-rs` (`PasskeyRegistration` /
//! `DiscoverableAuthentication`). The application layer deletes records past `expires_at`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Purpose of the challenge. **The completing side does not accept a challenge for a different
/// purpose.**
///
/// Creating a session ([`Self::Authenticate`]) and elevating an existing one ([`Self::StepUp`];
/// AP5) are different operations. Without separating them, a challenge issued for re-verification
/// would complete a login, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyChallengeType {
    /// Passkey registration (`navigator.credentials.create`).
    Register,
    /// Login (`navigator.credentials.get`). Whether it is an OIDC authorization flow or a direct
    /// login depends on whether `auth_session_id_hash` is present (ADR-0040 decision 4).
    Authenticate,
    /// Re-verification right before a sensitive operation (AP5). Unlike login, no new session is
    /// created.
    StepUp,
}

impl PasskeyChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyChallengeType::Register => "register",
            PasskeyChallengeType::Authenticate => "authenticate",
            PasskeyChallengeType::StepUp => "step_up",
        }
    }
}

impl std::fmt::Display for PasskeyChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PasskeyChallengeType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "register" => Ok(PasskeyChallengeType::Register),
            "authenticate" => Ok(PasskeyChallengeType::Authenticate),
            "step_up" => Ok(PasskeyChallengeType::StepUp),
            other => Err(format!("unknown challenge_type: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyChallenge {
    pub id: Uuid,
    /// Registration challenge: UUID of the SSO'd user. Authentication challenge: `None`
    /// (discoverable).
    pub user_id: Option<Uuid>,
    pub challenge_type: PasskeyChallengeType,
    /// JSON of `webauthn_rs::prelude::PasskeyRegistration` or `DiscoverableAuthentication`.
    pub state_json: String,
    /// Authentication challenge: the OIDC flow's `auth_sessions.id_hash` (`None` for registration /
    /// re-verification). auth_session_id is a bearer credential, so the copy is also kept as a hash
    /// (SEC6).
    pub auth_session_id_hash: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
