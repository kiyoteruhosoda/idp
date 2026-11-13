//! Internationalization of the API layer (MT19).
//!
//! Decides the display language from the `Accept-Language` header and translates API error messages.
//! **Error codes are language-invariant** (the `error` field is fixed); only `message` is translated.
//! Default locale is `ja` (system default, `CLAUDE.md` "国際化"). Only `Accept-Language` is consulted;
//! cookies, sessions, URL queries and DB user settings are not (deciding the display language is web's job).
//!
//! The Domain / Application layers hold no translations and return [`crate::domain::message::MessageKey`].
//! [`ApiMessages::get_message`] translates it (a boundary so wording is not copied across layers).
//!
//! **Not translated**:
//!
//! * OAuth 2.0 / OIDC protocol errors (`/token`, `/authorize`, `/introspect`, `/revoke`,
//!   `/userinfo`). Not only `error` but also `error_description` are machine/developer values that RFC 6749 §4.1.2.1
//!   defines as "for client developers", treated as fixed strings reaching the RP.
//!   RP logs and automation may depend on the wording, so the language does not vary per request.
//! * The body of 500 (`server_error`). Internal error details are not exposed to clients; a fixed string is returned
//!   ([`crate::presentation::error::ApiError`]). The user has no action to take, so translating gains
//!   nothing while adding locale-resolution paths.
//! * Internal logs and audit logs (unified in the ops language = English, `CLAUDE.md` "ログ").
//!
//! `FluentBundle` is `!Send`, so it cannot be held across request boundaries.
//! Created per request with `ApiMessages::new(locale)`.

use crate::domain::message::MessageKey;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::{langid, LanguageIdentifier};

const EN_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/en/main.ftl"
));
const JA_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/ja/main.ftl"
));

/// Locale used for API responses (decided from `Accept-Language`; default `Ja`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiLocale {
    En,
    Ja,
}

impl ApiLocale {
    /// Decides the locale from the `Accept-Language` header value.
    /// Quality values are ignored; first match wins. Unsupported or unspecified falls back to the default `Ja`.
    /// Region codes are ignored (`ja-JP` -> `Ja`, `en-US` -> `En`).
    pub fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return ApiLocale::Ja;
        };
        for part in header.split(',') {
            let tag = part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if tag == "ja" || tag.starts_with("ja-") {
                return ApiLocale::Ja;
            }
            if tag == "en" || tag.starts_with("en-") {
                return ApiLocale::En;
            }
        }
        ApiLocale::Ja
    }

    fn ftl(&self) -> &'static str {
        match self {
            ApiLocale::En => EN_FTL,
            ApiLocale::Ja => JA_FTL,
        }
    }

    fn lang_id(&self) -> LanguageIdentifier {
        match self {
            ApiLocale::En => langid!("en"),
            ApiLocale::Ja => langid!("ja"),
        }
    }
}

/// axum extractor: `Accept-Language` -> `ApiLocale`.
/// Returns the default `Ja` if the header is missing or unsupported.
impl<S> axum::extract::FromRequestParts<S> for ApiLocale
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok());
        Ok(ApiLocale::from_accept_language(header))
    }
}

/// Translation dictionary for one API request. Created per request (`FluentBundle` is `!Send`).
pub struct ApiMessages {
    bundle: FluentBundle<FluentResource>,
}

impl ApiMessages {
    pub fn new(locale: ApiLocale) -> Self {
        let resource =
            FluentResource::try_new(locale.ftl().to_string()).unwrap_or_else(|(res, errors)| {
                tracing::error!(?errors, "fluent resource has syntax errors");
                res
            });
        let mut bundle = FluentBundle::new(vec![locale.lang_id()]);
        bundle.set_use_isolating(false);
        if let Err(errors) = bundle.add_resource(resource) {
            tracing::error!(?errors, "failed to add fluent resource");
        }
        Self { bundle }
    }

    /// Gets a message by translation key. Undefined keys return the key name as is (fail-soft).
    pub fn get(&self, key: &str) -> String {
        self.format(key, None)
    }

    /// Translates a [`MessageKey`] returned by the Domain / Application layers (MT19).
    /// The placeholder value goes into the translation's `{ $value }`.
    pub fn get_message(&self, message: &MessageKey) -> String {
        match message.value() {
            Some(value) => {
                let mut args = FluentArgs::new();
                args.set("value", value);
                self.format(message.key(), Some(&args))
            }
            None => self.format(message.key(), None),
        }
    }

    fn format(&self, key: &str, args: Option<&FluentArgs>) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing api translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut errors = Vec::new();
        let value = self.bundle.format_pattern(pattern, args, &mut errors);
        if !errors.is_empty() {
            tracing::warn!(key, ?errors, "fluent formatting errors");
        }
        value.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_ja_when_no_header() {
        assert_eq!(ApiLocale::from_accept_language(None), ApiLocale::Ja);
    }

    #[test]
    fn selects_ja_for_ja_tags() {
        assert_eq!(ApiLocale::from_accept_language(Some("ja")), ApiLocale::Ja);
        assert_eq!(
            ApiLocale::from_accept_language(Some("ja-JP")),
            ApiLocale::Ja
        );
    }

    #[test]
    fn selects_en_for_en_tags() {
        assert_eq!(ApiLocale::from_accept_language(Some("en")), ApiLocale::En);
        assert_eq!(
            ApiLocale::from_accept_language(Some("en-US,ja;q=0.8")),
            ApiLocale::En
        );
    }

    #[test]
    fn falls_back_to_ja_for_unsupported_language() {
        assert_eq!(
            ApiLocale::from_accept_language(Some("fr-FR")),
            ApiLocale::Ja
        );
        assert_eq!(
            ApiLocale::from_accept_language(Some("zh-CN,ko;q=0.5")),
            ApiLocale::Ja
        );
    }

    #[test]
    fn api_messages_translates_known_keys() {
        let en = ApiMessages::new(ApiLocale::En);
        assert_eq!(en.get("api-user-not-found"), "User not found.");

        let ja = ApiMessages::new(ApiLocale::Ja);
        assert_eq!(ja.get("api-user-not-found"), "ユーザーが見つかりません。");
    }

    #[test]
    fn api_messages_returns_key_for_unknown_keys() {
        let msg = ApiMessages::new(ApiLocale::En);
        assert_eq!(msg.get("no-such-api-key"), "no-such-api-key");
    }

    #[test]
    fn message_keys_interpolate_their_value() {
        let en = ApiMessages::new(ApiLocale::En);
        let msg = en.get_message(&MessageKey::with_value("api-password-too-short", "8"));
        assert!(msg.contains('8'), "{msg}");
        assert!(
            !msg.contains("$value"),
            "placeholder must be substituted: {msg}"
        );

        let ja = ApiMessages::new(ApiLocale::Ja);
        let msg = ja.get_message(&MessageKey::with_value("api-password-too-short", "8"));
        assert!(msg.contains('8'), "{msg}");
    }

    /// `api-*` keys used in code must have translations in **both en and ja**.
    /// With only one, users of the other language see the key name (`api-client-scope-unsupported`) as is.
    /// A missing translation would go unnoticed, so keys are extracted from source and compared.
    #[test]
    fn every_api_message_key_used_in_code_is_translated_in_both_locales() {
        let sources = [
            include_str!("handlers/admin_clients.rs"),
            include_str!("handlers/admin_invitations.rs"),
            include_str!("handlers/admin_members.rs"),
            include_str!("handlers/admin_permissions.rs"),
            include_str!("handlers/admin_saml_service_providers.rs"),
            include_str!("handlers/admin_signing_keys.rs"),
            include_str!("handlers/admin_system_settings.rs"),
            include_str!("handlers/admin_tenants.rs"),
            include_str!("handlers/admin_users.rs"),
            include_str!("handlers/admin_audit.rs"),
            include_str!("handlers/invitations.rs"),
            include_str!("handlers/register.rs"),
            include_str!("handlers/mod.rs"),
            // Where the MessageKey returned by the Domain / Application layers is defined.
            include_str!("../../../core/src/domain/values.rs"),
            include_str!("../../../core/src/domain/password.rs"),
            include_str!("../../../core/src/domain/saml_service_provider.rs"),
            include_str!("../../../core/src/application/client_management.rs"),
            include_str!("../../../core/src/application/invitation.rs"),
            include_str!("../../../core/src/application/key_service.rs"),
            include_str!("../../../core/src/application/permission_management.rs"),
            include_str!("../../../core/src/application/register.rs"),
            include_str!("../../../core/src/application/tenant_management.rs"),
            include_str!("../../../core/src/application/user_lifecycle.rs"),
            include_str!("../../../core/src/application/user_management.rs"),
        ];

        let mut keys: Vec<String> = Vec::new();
        for source in sources {
            for (index, _) in source.match_indices("\"api-") {
                let rest = &source[index + 1..];
                let Some(end) = rest.find('"') else { continue };
                let key = &rest[..end];
                if key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    keys.push(key.to_string());
                }
            }
        }
        keys.sort();
        keys.dedup();
        assert!(
            keys.len() > 40,
            "expected to find the api keys, got {keys:?}"
        );

        for locale in [ApiLocale::En, ApiLocale::Ja] {
            let messages = ApiMessages::new(locale);
            let missing: Vec<&String> = keys
                .iter()
                .filter(|key| messages.get(key) == **key)
                .collect();
            assert!(
                missing.is_empty(),
                "{locale:?} is missing translations for {missing:?}"
            );
        }
    }
}
