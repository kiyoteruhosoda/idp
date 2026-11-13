//! Admin notes on accounts (ADR-0063 / ADR-0065).
//!
//! Free text where admins record "how this account came about". **It is meant for people and is never
//! used for decisions** (it is not copied into sign-in, tokens or the directory anywhere).
//!
//! Attaches to both people and service accounts ([`crate::domain::account::AccountRef`]). There is one set
//! of rules (limit, normalization) regardless of kind.
//!
//! - A person's note is a fact held by the tenant's admins, so it attaches to the **membership** (tenant x
//!   user), not the user. The same person can have different notes in the HOME tenant and a guest tenant
//! - A service account belongs to only one tenant, so it attaches directly to `clients.id`

use crate::domain::message::MessageKey;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Note limit (characters). Enough for a few lines of history; not long enough to become a place to paste minutes.
///
/// The column is `TEXT` (64KB), so ⚠ **count characters, not bytes** (Japanese is 3 bytes per character).
/// The value is shared with the web input field (the contract crate is the single source).
pub use assay_contracts::admin::ACCOUNT_NOTE_MAX_LEN;

/// A stored note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountNote {
    pub text: String,
    pub updated_at: DateTime<Utc>,
    /// The admin who last wrote it. `None` when written via a machine or the writer has been deleted.
    pub updated_by: Option<Uuid>,
}

/// Validates input and returns the value to store. **Empty (whitespace only) means `None` = delete the note.**
///
/// Line breaks are normalized to `\n` and leading/trailing whitespace is trimmed. Whitespace within lines is kept as written
/// (some people make bullet lists with indentation).
pub fn normalize_account_note(raw: &str) -> Result<Option<String>, MessageKey> {
    let unified = raw.replace("\r\n", "\n").replace('\r', "\n");
    let value = unified.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > ACCOUNT_NOTE_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-account-note-too-long",
            ACCOUNT_NOTE_MAX_LEN.to_string(),
        ));
    }
    Ok(Some(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_input_clears_the_note() {
        assert_eq!(normalize_account_note(""), Ok(None));
        assert_eq!(normalize_account_note("  \r\n \n\t"), Ok(None));
    }

    #[test]
    fn line_endings_are_unified_and_outer_whitespace_is_trimmed() {
        assert_eq!(
            normalize_account_note("\r\n 家族。\r\n  - 2026-09 に招待\r\n"),
            Ok(Some("家族。\n  - 2026-09 に招待".to_string()))
        );
    }

    #[test]
    fn limit_is_counted_in_characters_not_bytes() {
        let at_limit = "あ".repeat(ACCOUNT_NOTE_MAX_LEN);
        assert_eq!(
            normalize_account_note(&at_limit),
            Ok(Some(at_limit.clone()))
        );
        let over = "あ".repeat(ACCOUNT_NOTE_MAX_LEN + 1);
        assert!(normalize_account_note(&over).is_err());
    }
}
