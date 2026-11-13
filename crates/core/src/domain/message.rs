//! Translation keys for messages returned to users (MT19).
//!
//! The Domain / Application layers **hold no translated text**; they return only translation keys
//! and interpolation values. Actual translation is done by the Presentation layer per
//! `Accept-Language` (separation of duties in `CLAUDE.md` "Internationalization"). This meets the
//! dual need of the user's language in api responses and the operations language (English) in
//! internal logs without copying text.
//!
//! `Display` prints the key (and values) as is. Operational and audit logs keep the untranslated
//! key, so they are greppable regardless of language settings, and changing translations does not
//! break log search.

use std::fmt;

/// A translation key and the value interpolated into the translation's `{ $value }` (target URI,
/// scope name, etc.).
///
/// Keys are limited to static strings (with dynamic keys, the mapping to translation resources is
/// unknown until runtime and "keys without translations" silently multiply). Only values are taken
/// at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKey {
    key: &'static str,
    value: Option<String>,
}

impl MessageKey {
    /// A message without an interpolation value.
    pub const fn new(key: &'static str) -> Self {
        Self { key, value: None }
    }

    /// A message with an interpolation value (inserted into the translation's `{ $value }`).
    pub fn with_value(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key,
            value: Some(value.into()),
        }
    }

    pub fn key(&self) -> &'static str {
        self.key
    }

    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Display for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}: {value}", self.key),
            None => write!(f, "{}", self.key),
        }
    }
}

impl From<&'static str> for MessageKey {
    fn from(key: &'static str) -> Self {
        Self::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_the_key_so_logs_stay_greppable() {
        assert_eq!(
            MessageKey::new("api-client-scopes-empty").to_string(),
            "api-client-scopes-empty"
        );
        assert_eq!(
            MessageKey::with_value("api-client-scope-unsupported", "offline_access").to_string(),
            "api-client-scope-unsupported: offline_access"
        );
    }

    #[test]
    fn value_is_optional() {
        assert_eq!(MessageKey::new("k").value(), None);
        assert_eq!(MessageKey::with_value("k", "v").value(), Some("v"));
    }
}
