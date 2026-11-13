//! Use case: the user's self-service profile (display name).
//!
//! A logged-in user reads and updates their own `users.name` (display name) via the SSO session.
//! The display name is free input with no uniqueness or format constraint; empty or whitespace-only clears it (`NULL`).

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use crate::domain::user::User;
use crate::domain::values::validate_display_name;
use std::sync::Arc;

/// Profile read result (for prefilling the settings screen).
pub enum ProfileOutcome {
    Ok {
        name: Option<String>,
        preferred_username: Option<String>,
        email: String,
        /// Saved display language (`users.language`; `None` if unset). MT20.
        language: Option<String>,
        /// Saved color scheme (`users.theme`; `None` if unset). web applies it to the screen.
        theme: Option<String>,
    },
    /// No SSO session, or it has expired.
    SessionExpired,
    Internal(String),
}

pub struct UpdateNameCommand {
    /// Raw value of the SSO session cookie (looked up in the DB by its SHA-256 hash).
    pub sso_session_id: String,
    /// New display name. Empty, whitespace-only or `None` clears it (DB `NULL`).
    pub name: Option<String>,
}

pub enum UpdateNameOutcome {
    Ok,
    /// No SSO session, or it has expired.
    SessionExpired,
    /// The value is invalid, e.g. the display name is too long.
    Invalid,
    Internal(String),
}

pub struct AccountProfileService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn Clock>,
}

impl AccountProfileService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clock,
        }
    }

    /// Reads the current profile (display name, login identifier, email).
    pub async fn get(&self, sso_session_id: &str) -> ProfileOutcome {
        match self.resolve_active_user(sso_session_id).await {
            Ok(Some(user)) => ProfileOutcome::Ok {
                name: user.name,
                preferred_username: user.preferred_username,
                email: user.email,
                language: user.language,
                theme: user.theme,
            },
            Ok(None) => ProfileOutcome::SessionExpired,
            Err(e) => ProfileOutcome::Internal(e),
        }
    }

    /// Updates the display name (empty or whitespace-only clears it).
    pub async fn update_name(&self, cmd: UpdateNameCommand) -> UpdateNameOutcome {
        // Normalize empty or whitespace-only to cleared (`NULL`). Leading/trailing whitespace is trimmed before saving.
        let normalized = cmd
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        if let Some(ref name) = normalized {
            if validate_display_name(name).is_err() {
                return UpdateNameOutcome::Invalid;
            }
        }

        let user = match self.resolve_active_user(&cmd.sso_session_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return UpdateNameOutcome::SessionExpired,
            Err(e) => return UpdateNameOutcome::Internal(e),
        };

        if let Err(e) = self.users.update_name(user.id, normalized.as_deref()).await {
            return UpdateNameOutcome::Internal(e.to_string());
        }
        UpdateNameOutcome::Ok
    }

    /// Resolves the user from the SSO session and returns an **active user row**. An invalid session,
    /// a missing user, or a disabled one (LOCKED/DISABLED) all yield `Ok(None)` (treated as logged out).
    /// Like the other authenticated paths (`AdminAccessService` / `AccountPasswordService`), `is_active()`
    /// is required, preventing actions by a disabled account whose session is still alive.
    async fn resolve_active_user(&self, sso_session_id: &str) -> Result<Option<User>, String> {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s.user_id,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(user)),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}
