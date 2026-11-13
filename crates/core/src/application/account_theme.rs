//! Use case: update the user's color scheme setting.
//!
//! A logged-in user updates their own `theme` column (`light` / `dark` / `system`) via the SSO
//! session. It only writes to the DB; web applies the actual colors (`data-bs-theme`).
//!
//! `system` (follow the OS) is kept as a value distinct from `NULL` (unset) because the former is
//! **the user's choice**. When unset, a cookie left on the device may be honored, but a user who chose
//! `system` should get OS-following colors across devices; one shared value could not tell them apart.

use crate::domain::crypto;
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use std::sync::Arc;

/// Allowed color scheme values (keep in sync with the DB CHECK constraint).
const ALLOWED_THEMES: [&str; 3] = ["light", "dark", "system"];

pub struct UpdateThemeCommand {
    /// Raw value of the SSO session cookie (looked up in the DB by its SHA-256 hash).
    pub sso_session_id: String,
    /// Color scheme to set (`light` / `dark` / `system`). Invalid values are a Validation error.
    pub theme: String,
}

pub enum UpdateThemeOutcome {
    Ok,
    /// No SSO session, or it has expired.
    SessionExpired,
    /// Unsupported color scheme value.
    InvalidTheme,
    Internal(String),
}

pub struct AccountThemeService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn crate::domain::clock::Clock>,
}

impl AccountThemeService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        clock: Arc<dyn crate::domain::clock::Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            clock,
        }
    }

    pub async fn update(&self, cmd: UpdateThemeCommand) -> UpdateThemeOutcome {
        let theme = cmd.theme.trim();
        if !ALLOWED_THEMES.contains(&theme) {
            return UpdateThemeOutcome::InvalidTheme;
        }
        let theme = theme.to_string();

        let now = self.clock.now();

        // Resolve the user from the SSO session.
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return UpdateThemeOutcome::SessionExpired,
            Err(e) => return UpdateThemeOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self.users.update_theme(session.user_id, Some(&theme)).await {
            return UpdateThemeOutcome::Internal(e.to_string());
        }

        UpdateThemeOutcome::Ok
    }
}
