//! Internationalization of the login screen (`fluent`, `CLAUDE.md` "Internationalization").
//!
//! Translation resources `i18n/<lang>/main.ftl` at the repository root are embedded into the binary. New messages are
//! defined in English and Japanese translations are added manually to the `ja` resource. The MVP i18n target is only the login screen.
//! (Under ADR-0007 P3, i18n is planned to move to the web crate. For now it is referenced relative to the crate root.)

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

/// Supported locales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Ja,
}

impl Locale {
    /// Decides the display locale from the `Accept-Language` header (the MVP has 2 choices: en / ja).
    /// Unsupported or unspecified falls back to the default `Ja` (MT19: system default unified to `ja`).
    pub fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return Locale::Ja;
        };
        // Simple implementation that ignores quality values and picks the first supported language.
        header
            .split(',')
            .find_map(|part| Locale::from_language_tag(part.split(';').next().unwrap_or("")))
            .unwrap_or(Locale::Ja)
    }

    /// Picks the display locale from the authorization request's `ui_locales` (OIDC Core §3.1.2.1; space-separated BCP47 tags
    /// in the RP's preferred order). `None` if none is supported (falls through to the next priority).
    ///
    /// Unlike `Accept-Language`, it **does not round to the default**. The RP's request is weaker than the user's own choice
    /// (`?lang=`, user setting, cookie) and stronger than the browser language, so rounding unsupported values to `Ja`
    /// would overtake the browser language and impose the default.
    pub fn from_ui_locales(value: &str) -> Option<Locale> {
        value.split_whitespace().find_map(Locale::from_language_tag)
    }

    /// Maps a single language tag (`ja` / `ja-JP` / `en-US`) to a supported locale. Region codes are ignored
    /// (`CLAUDE.md` "Internationalization": decided by language code only). Unsupported or invalid values give `None`.
    fn from_language_tag(tag: &str) -> Option<Locale> {
        let tag = tag.trim().to_ascii_lowercase();
        let language = tag.split('-').next().unwrap_or("");
        match language {
            "ja" => Some(Locale::Ja),
            "en" => Some(Locale::En),
            _ => None,
        }
    }

    /// Looks up the locale from a language tag (`ja` / `en`). Unsupported or invalid values give `None`.
    pub fn from_tag(tag: &str) -> Option<Locale> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "ja" => Some(Locale::Ja),
            "en" => Some(Locale::En),
            _ => None,
        }
    }

    /// Returns the language tag (`ja` / `en`) (used for saving the cookie and the selector's initial selection).
    pub fn as_tag(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ja => "ja",
        }
    }

    /// Display language decision chain (MT20):
    /// `?lang=` > user setting (DB) > Cookie(`lang`) > `Accept-Language` > default `Ja`.
    /// Invalid or unsupported values are ignored and fall back to the next priority.
    ///
    /// The authorization request's `ui_locales` (G12) sits between the cookie and `Accept-Language`, but it exists only
    /// for requests during an OIDC flow, so it is not a parameter. The [`crate::display_preferences`] middleware
    /// normalizes the decided language into the `lang` cookie before calling this function.
    pub fn resolve(
        query_lang: Option<&str>,
        user_language: Option<&str>,
        cookie_lang: Option<&str>,
        accept_language: Option<&str>,
    ) -> Locale {
        if let Some(locale) = query_lang.and_then(Locale::from_tag) {
            return locale;
        }
        if let Some(locale) = user_language.and_then(Locale::from_tag) {
            return locale;
        }
        if let Some(locale) = cookie_lang.and_then(Locale::from_tag) {
            return locale;
        }
        Locale::from_accept_language(accept_language)
    }

    fn ftl(&self) -> &'static str {
        match self {
            Locale::En => EN_FTL,
            Locale::Ja => JA_FTL,
        }
    }

    fn lang_id(&self) -> LanguageIdentifier {
        match self {
            Locale::En => langid!("en"),
            Locale::Ja => langid!("ja"),
        }
    }
}

/// Message dictionary for one rendering of the login screen.
pub struct Messages {
    bundle: FluentBundle<FluentResource>,
    /// The decided display language. Output in `<html lang>` and also used for date formatting in the browser
    /// (ADR-0048). Rendering uses **this screen's language**, not the viewer's browser language,
    /// so it comes from the same source as the translations.
    locale: Locale,
}

impl Messages {
    pub fn new(locale: Locale) -> Self {
        let resource =
            FluentResource::try_new(locale.ftl().to_string()).unwrap_or_else(|(res, errors)| {
                tracing::error!(?errors, "fluent resource has syntax errors");
                res
            });
        let mut bundle = FluentBundle::new(vec![locale.lang_id()]);
        // Embedded in HTML, so Unicode isolation characters (FSI/PDI) are not inserted.
        bundle.set_use_isolating(false);
        if let Err(errors) = bundle.add_resource(resource) {
            tracing::error!(?errors, "failed to add fluent resource");
        }
        Self { bundle, locale }
    }

    /// The display language tag (`ja` / `en`). Output in `<html lang>`.
    pub fn lang(&self) -> &'static str {
        self.locale.as_tag()
    }

    /// Gets a message by translation key. Undefined keys return the key name as is (fail-soft).
    pub fn get(&self, key: &str) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut errors = Vec::new();
        let value = self.bundle.format_pattern(pattern, None, &mut errors);
        if !errors.is_empty() {
            tracing::warn!(key, ?errors, "fluent formatting errors");
        }
        value.into_owned()
    }

    /// Gets a message with one interpolated value (wording like `Sign in to { $client }`).
    /// Undefined keys return the key name as is (same fail-soft as [`Self::get`]).
    ///
    /// It takes just one argument because that is all that is needed now. When more are needed,
    /// widen it to take a set of arguments (Askama template expressions cannot write array literals,
    /// so the call shape stays a plain positional argument).
    pub fn get_arg(&self, key: &str, arg_name: &str, value: &str) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut args = FluentArgs::new();
        args.set(arg_name.to_string(), value.to_string());
        let mut errors = Vec::new();
        let formatted = self
            .bundle
            .format_pattern(pattern, Some(&args), &mut errors);
        if !errors.is_empty() {
            tracing::warn!(key, ?errors, "fluent formatting errors");
        }
        formatted.into_owned()
    }

    /// Gets a message with multiple interpolated values (the entry point for handlers. Askama template expressions
    /// cannot write array literals, so templates use [`Self::get_arg`]).
    /// Undefined keys return the key name as is (same fail-soft as [`Self::get`]).
    pub fn get_args(&self, key: &str, values: &[(&str, &str)]) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut args = FluentArgs::new();
        for (name, value) in values {
            args.set(name.to_string(), value.to_string());
        }
        let mut errors = Vec::new();
        let formatted = self
            .bundle
            .format_pattern(pattern, Some(&args), &mut errors);
        if !errors.is_empty() {
            tracing::warn!(key, ?errors, "fluent formatting errors");
        }
        formatted.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The translation resources load without syntax errors.**
    ///
    /// Fluent syntax errors do not stop loading — only the broken entries drop, and the screen shows the key name
    /// (a string like `admin-settings-sms-note`) as is. An ERROR remains in the startup log,
    /// but nobody notices unless they look. In fact, an entry with JSON braces in its text was
    /// broken this way (braces are the variable interpolation symbol, so a literal is written as `{"{"}`).
    #[test]
    fn every_bundled_translation_parses_without_errors() {
        for locale in [Locale::En, Locale::Ja] {
            if let Err((_, errors)) = FluentResource::try_new(locale.ftl().to_string()) {
                panic!("{:?} has fluent syntax errors: {errors:?}", locale);
            }
        }
    }

    /// Wording containing braces is output **with the braces** after escaping (confirms the escaping is written
    /// correctly; if broken, admins cannot learn the JSON shape to give to the relay).
    #[test]
    fn a_message_with_literal_braces_renders_them() {
        for locale in [Locale::En, Locale::Ja] {
            let rendered = Messages::new(locale).get("admin-settings-sms-note");
            assert!(
                rendered.contains(r#"{"to""#),
                "{locale:?}: expected literal JSON braces, got {rendered}"
            );
        }
    }

    #[test]
    fn selects_locale_from_accept_language() {
        assert_eq!(Locale::from_accept_language(None), Locale::Ja);
        assert_eq!(
            Locale::from_accept_language(Some("ja,en-US;q=0.9")),
            Locale::Ja
        );
        assert_eq!(
            Locale::from_accept_language(Some("en-US,ja;q=0.8")),
            Locale::En
        );
        assert_eq!(Locale::from_accept_language(Some("fr-FR")), Locale::Ja);
    }

    #[test]
    fn resolve_prefers_query_then_user_language_then_cookie_then_accept_language() {
        // ?lang= has top priority.
        assert_eq!(
            Locale::resolve(Some("ja"), Some("en"), Some("en"), Some("en-US")),
            Locale::Ja
        );
        // If ?lang= is invalid, the user setting (DB).
        assert_eq!(
            Locale::resolve(Some("fr"), Some("ja"), Some("en"), Some("en-US")),
            Locale::Ja
        );
        // If ?lang= and the user setting are invalid, the cookie.
        assert_eq!(
            Locale::resolve(Some("fr"), Some("zz"), Some("ja"), Some("en-US")),
            Locale::Ja
        );
        // If none of these, Accept-Language.
        assert_eq!(
            Locale::resolve(None, None, None, Some("ja,en;q=0.8")),
            Locale::Ja
        );
        // If all are invalid/unspecified, the default Ja (MT19: system default unified to ja).
        assert_eq!(
            Locale::resolve(Some("fr"), Some("zz"), Some("zz"), Some("fr")),
            Locale::Ja
        );
    }

    /// `ui_locales` (G12) are space-separated tags in the RP's preferred order. Supported languages are searched from the front,
    /// ignoring region codes. `None` if none (= fall through to the browser language; not rounded to the default).
    #[test]
    fn selects_locale_from_ui_locales() {
        assert_eq!(Locale::from_ui_locales("en"), Some(Locale::En));
        assert_eq!(Locale::from_ui_locales("en-GB en-US"), Some(Locale::En));
        // Unsupported languages are skipped and the next tag is checked.
        assert_eq!(Locale::from_ui_locales("fr-CA fr ja-JP"), Some(Locale::Ja));
        // Runs of whitespace and leading/trailing whitespace are also treated as separators.
        assert_eq!(Locale::from_ui_locales("  ja   en "), Some(Locale::Ja));
        // With no supported language, do not decide (do not overtake `Accept-Language` and impose the default ja).
        assert_eq!(Locale::from_ui_locales("fr de zh-CN"), None);
        assert_eq!(Locale::from_ui_locales(""), None);
    }

    #[test]
    fn from_tag_and_as_tag_roundtrip() {
        assert_eq!(Locale::from_tag("JA"), Some(Locale::Ja));
        assert_eq!(Locale::from_tag(" en "), Some(Locale::En));
        assert_eq!(Locale::from_tag("fr"), None);
        assert_eq!(Locale::Ja.as_tag(), "ja");
        assert_eq!(Locale::En.as_tag(), "en");
    }

    #[test]
    fn resolves_messages_in_both_locales() {
        let en = Messages::new(Locale::En);
        assert_eq!(en.get("login-title"), "Sign in");
        let ja = Messages::new(Locale::Ja);
        assert_eq!(ja.get("login-title"), "サインイン");
        // Undefined keys return the key name.
        assert_eq!(en.get("no-such-key"), "no-such-key");
    }
}
