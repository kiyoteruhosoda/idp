//! Use case: update the user's display language setting (MT20).
//!
//! A logged-in user updates their own `language` column (`ja` / `en` / `NULL`) via the SSO session.
//! It only writes to the DB; i18n is applied per request from `Accept-Language`.

use crate::domain::crypto;
use crate::domain::repositories::{SsoSessionRepository, UserRepository};
use std::sync::Arc;

pub struct UpdateLanguageCommand {
    /// Raw value of the SSO session cookie (looked up in the DB by its SHA-256 hash).
    pub sso_session_id: String,
    /// Language code to set (`ja` / `en`). Invalid values are a Validation error.
    pub language: String,
}

pub enum UpdateLanguageOutcome {
    Ok,
    /// No SSO session, or it has expired.
    SessionExpired,
    /// Unsupported language code (anything other than `ja` and `en`).
    InvalidLanguage,
    Internal(String),
}

pub struct AccountLanguageService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    clock: Arc<dyn crate::domain::clock::Clock>,
}

impl AccountLanguageService {
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

    pub async fn update(&self, cmd: UpdateLanguageCommand) -> UpdateLanguageOutcome {
        // Validate the supported languages (ja / en only).
        let lang = match cmd.language.trim() {
            "ja" | "en" => cmd.language.trim().to_string(),
            _ => return UpdateLanguageOutcome::InvalidLanguage,
        };

        let now = self.clock.now();

        // Resolve the user from the SSO session.
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return UpdateLanguageOutcome::SessionExpired,
            Err(e) => return UpdateLanguageOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self
            .users
            .update_language(session.user_id, Some(&lang))
            .await
        {
            return UpdateLanguageOutcome::Internal(e.to_string());
        }

        UpdateLanguageOutcome::Ok
    }
}
