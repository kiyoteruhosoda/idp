//! Deciding display settings (language, color scheme) (MT20. The separation of duties in `CLAUDE.md` "Internationalization").
//!
//! Language and color scheme are decided by **the same order and the same inputs** (`?...=` > user setting > cookie), and
//! both user settings are in the single `/internal/account/profile` response. Separate middlewares would call the api
//! twice per screen render while signed in, so they are combined into one.
//!
//! **web decides the display language**; the api only looks at `Accept-Language`. The decision order is first-wins:
//! `?lang=` > user setting (DB `users.language`) > Cookie(`lang`) > the authorization request's `ui_locales`
//! (G12) > the browser's `Accept-Language` > default `ja`. Invalid or unsupported values are ignored and fall to the next.
//!
//! `ui_locales` is below the cookie and above the browser language because it is **the RP's wish**, not the user's
//! own choice. A user who has chosen a language even once (has a `lang` cookie) does not get their screen switched for
//! the RP's convenience, but for users who chose nothing, the RP's preference beats the browser default.
//!
//! The implementation is consolidated into one middleware. Collecting the 4 inputs again per handler would make
//! priorities diverge as screens are added (before MT20, screens actually differed in whether they looked at `?lang=`).
//!
//! The color scheme order is `?theme=` > user setting (`users.theme`) > Cookie(`theme`) > OS setting.
//! Unlike language, **downstream handlers do not read the color scheme** — it is applied by `assets/theme.js` in the browser,
//! and the server's only job is to keep the `theme` cookie in line with the user's choice ([`crate::theme`]).
//!
//! The decision is passed downstream **by rewriting the request's `lang` cookie header**. Handlers just call
//! `handlers::locale` (cookie > `Accept-Language` > default) as before and thereby follow the decision order.
//! In the response, the cookie is saved only when there was an explicit choice (a valid `?lang=` / `?theme=`).
//!
//! ⚠ **This does not write to user settings (DB)** (task #79). `?lang=` / `?theme=` are GETs and
//! can be attached to any screen's URL — external links or an RP's login entry (the SSO cookie is
//! `SameSite=Lax`, so it rides along on top-level navigations) could rewrite the user's saved settings.
//! GET `?lang=` / `?theme=` are only **temporary switches** (that screen's display and the cookie); saving is
//! limited to `POST /{tenant_id}/settings/display` sent from the settings screen or the admin console header (with a CSRF
//! token; [`crate::handlers::user_settings::save_display_preferences`]). While signed in the user setting
//! beats the cookie, so a temporary switch reverts to the saved value on the next screen (per the decision order).
//!
//! Fetching the user settings needs one request to the api (`/internal/account/profile`),
//! **once per HTML screen render while signed in**. It is not called when `?lang=` already decided it or when there is
//! no SSO cookie. It is a local hop, and the admin console already calls the api several times per screen, so the
//! relative increase is small. Caching with the cookie as the source of truth is not used, as it could not follow language changes on other devices.
//!
//! The fetched profile response is attached to the request extensions as [`FetchedAccountProfile`] and passed downstream
//! (task #80). The settings screen uses the same response for the display name and login identifier, so the api is not called again.
//! What is attached is **the response itself**; the [`StoredPreferences`] used for deciding display settings stays an
//! internal derivation of the middleware (display names etc. not needed for the decision are kept out of the decision type).

use crate::cookies;
use crate::i18n::Locale;
use crate::login_context::RpLoginContext;
use crate::state::WebState;
use crate::theme::Theme;
use assay_contracts::auth::{InternalAccountProfileRequest, InternalAccountProfileResponse};
use axum::extract::{Request, State};
use axum::http::header::{HeaderValue, COOKIE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Extracts one parameter from the URL query (`lang` in `?a=1&lang=en` → `Some("en")`).
/// Values are not decoded (neither language tags nor color schemes contain percent-encoded characters).
fn query_value<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix(prefix.as_str()))
}

/// Middleware that decides the display language and applies it to the request.
///
/// To convey the decided language to downstream handlers, the `lang` in the request's `Cookie` header is replaced with the
/// decided value (normalizing the input `handlers::locale` reads into one). Other cookies (SSO etc.) are kept.
pub async fn resolve_display_preferences(
    State(state): State<WebState>,
    mut request: Request,
    next: Next,
) -> Response {
    let query = request.uri().query();
    let explicit_locale = query_value(query, "lang").and_then(Locale::from_tag);
    let explicit_theme = query_value(query, "theme").and_then(Theme::from_tag);
    let cookie_theme =
        cookies::get(request.headers(), cookies::THEME_COOKIE).and_then(|t| Theme::from_tag(&t));
    let sso = cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE);

    // User settings for language and color scheme are fetched together just once. The api is not called when both
    // are decided by `?...=` or when there is no SSO cookie.
    // The fetched response is passed downstream (settings screen). If not fetched, no extension is attached.
    let stored = match &sso {
        Some(sso) if explicit_locale.is_none() || explicit_theme.is_none() => {
            let profile = fetch_account_profile(&state, sso).await;
            let stored = StoredPreferences::from_profile(profile.as_ref());
            request
                .extensions_mut()
                .insert(FetchedAccountProfile(profile));
            stored
        }
        _ => StoredPreferences::default(),
    };

    // Decision order 1: a valid `?lang=`. 2: user setting. 3: cookie (read as is by the downstream
    // `handlers::locale`). 4: the authorization request's `ui_locales`. If none, `Accept-Language`.
    let decided = explicit_locale
        .or(stored.language)
        .or_else(|| requested_locale(&request));
    if let Some(locale) = decided {
        overwrite_lang_cookie(&mut request, locale);
    }

    let theme_to_store = theme_cookie_to_write(explicit_theme, stored.theme, cookie_theme);

    let response = next.run(request).await;

    // The `lang` cookie is written only for an explicit choice (`?lang=`) (not rewritten to reflect the browser language,
    // user setting or `ui_locales`. Rewriting it from the user setting would keep an old cookie overwriting back when the
    // setting is changed on another device. `ui_locales` is the RP's wish, not the user's choice).
    // Nothing is written to user settings (DB) (see the module doc).
    if explicit_locale.is_none() && theme_to_store.is_none() {
        return response;
    }
    let mut set_cookies = state.set_cookies();
    if let Some(locale) = explicit_locale {
        set_cookies = set_cookies.set_local(
            cookies::LANG_COOKIE,
            locale.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    if let Some(theme) = theme_to_store {
        set_cookies = set_cookies.set_preference(
            cookies::THEME_COOKIE,
            theme.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    (set_cookies.into_headers(), response).into_response()
}

/// Valid locale indicated by the request's `lang` cookie (`None` if unset or unsupported).
fn cookie_locale(request: &Request) -> Option<Locale> {
    cookies::get(request.headers(), cookies::LANG_COOKIE).and_then(|tag| Locale::from_tag(&tag))
}

/// Decision order 4: the display locale requested by an in-progress authorization request via `ui_locales` (G12).
/// `None` outside an OIDC flow or for unsupported values. The context was already fetched by the [`crate::login_context`] middleware.
///
/// Does not decide while a language chosen by the user (a valid `lang` cookie) remains (decision order 3 wins).
fn requested_locale(request: &Request) -> Option<Locale> {
    if cookie_locale(request).is_some() {
        return None;
    }
    request
        .extensions()
        .get::<RpLoginContext>()?
        .ui_locales
        .as_deref()
        .and_then(Locale::from_ui_locales)
}

/// The signed-in user's profile response fetched by the middleware (task #80). Passed downstream as a request extension.
///
/// The extension is **absent** when the middleware did not fetch it (no SSO cookie, or the display settings
/// were decided by both `?lang=` and `?theme=`), and handlers that need it call
/// [`fetch_account_profile`] themselves. An inner `None` means the fetch failed (already logged), and it is
/// not re-fetched (the result would not change within the same request).
#[derive(Debug, Clone)]
pub struct FetchedAccountProfile(pub Option<InternalAccountProfileResponse>);

/// Fetches the signed-in user's profile from the api once. A fetch failure gives `None` (with a warning log).
/// Callers do not break the screen (it is only for display; falling back to blanks or cookie / browser defaults suffices).
pub async fn fetch_account_profile(
    state: &WebState,
    sso: &str,
) -> Option<InternalAccountProfileResponse> {
    let request = InternalAccountProfileRequest {
        sso_session_id: sso.to_string(),
    };
    match state.api.account_profile(&request).await {
        Ok(profile) => Some(profile),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the user's account profile");
            None
        }
    }
}

/// The signed-in user's saved display settings (`None` if unset, unsupported or the fetch failed).
#[derive(Debug, Default, Clone, Copy)]
struct StoredPreferences {
    language: Option<Locale>,
    theme: Option<Theme>,
}

impl StoredPreferences {
    /// Extracts only the values used for deciding display settings from the profile response. Fetch failure or session expiry
    /// are treated as unset (falling back to cookie / browser defaults).
    fn from_profile(profile: Option<&InternalAccountProfileResponse>) -> Self {
        match profile {
            Some(InternalAccountProfileResponse::Ok {
                language, theme, ..
            }) => Self {
                language: language.as_deref().and_then(Locale::from_tag),
                theme: theme.as_deref().and_then(Theme::from_tag),
            },
            _ => Self::default(),
        }
    }
}

/// The value the `theme` cookie should be rewritten to (`None` if not rewritten).
///
/// Downstream handlers do not read the color scheme, so the middleware only decides "what to align the cookie to".
///
/// - An explicit choice (`?theme=`) is always written.
/// - The user setting is written **only when it differs from the cookie** (to catch up with a setting changed on another device).
///   Writing every time would attach a same-value `Set-Cookie` to every screen.
/// - If neither exists, nothing is written (the server does not erase a choice left on a signed-out user's device).
fn theme_cookie_to_write(
    explicit: Option<Theme>,
    stored: Option<Theme>,
    in_cookie: Option<Theme>,
) -> Option<Theme> {
    explicit.or_else(|| stored.filter(|stored| Some(*stored) != in_cookie))
}

/// Rebuilds the request's `Cookie` header into one with only `lang` replaced by `locale`.
///
/// `lang` is removed and re-added so the value downstream reads is unique even with multiple `Cookie` headers or
/// duplicate same-name cookies (`cookies::get` returns the first value found).
fn overwrite_lang_cookie(request: &mut Request, locale: Locale) {
    let mut pairs: Vec<String> = request
        .headers()
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("").trim();
            name != cookies::LANG_COOKIE
        })
        .map(str::to_string)
        .collect();
    pairs.push(format!("{}={}", cookies::LANG_COOKIE, locale.as_tag()));

    let joined = pairs.join("; ");
    let Ok(value) = HeaderValue::from_str(&joined) else {
        // The original cookie contains non-ASCII etc. Give up overriding the language and keep the original header.
        tracing::warn!("could not rebuild the cookie header while resolving the language");
        return;
    };
    request.headers_mut().remove(COOKIE);
    request.headers_mut().insert(COOKIE, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn extracts_a_named_parameter_from_the_query_string() {
        assert_eq!(query_value(None, "lang"), None);
        assert_eq!(query_value(Some("lang=en"), "lang"), Some("en"));
        assert_eq!(query_value(Some("error=csrf&lang=ja"), "lang"), Some("ja"));
        assert_eq!(
            query_value(Some("q=lang=en"), "lang"),
            None,
            "only a whole pair"
        );
        // Unknown/invalid values are discarded by `Locale::from_tag` / `Theme::from_tag`
        // (the raw value is returned here).
        assert_eq!(query_value(Some("lang=fr"), "lang"), Some("fr"));
        assert_eq!(query_value(Some("lang="), "lang"), Some(""));

        // Split by name (do not confuse `lang` and `theme`).
        assert_eq!(
            query_value(Some("lang=en&theme=dark"), "theme"),
            Some("dark")
        );
        assert_eq!(query_value(Some("lang=en"), "theme"), None);
    }

    /// Conditions for rewriting the color scheme cookie (see the doc of [`theme_cookie_to_write`]).
    #[test]
    fn the_theme_cookie_follows_the_explicit_choice_then_the_stored_setting() {
        // An explicit choice wins regardless of what the cookie or user setting holds.
        assert_eq!(
            theme_cookie_to_write(Some(Theme::Dark), Some(Theme::Light), Some(Theme::Light)),
            Some(Theme::Dark)
        );
        // Catch up with a user setting changed on another device.
        assert_eq!(
            theme_cookie_to_write(None, Some(Theme::Dark), Some(Theme::Light)),
            Some(Theme::Dark)
        );
        assert_eq!(
            theme_cookie_to_write(None, Some(Theme::Dark), None),
            Some(Theme::Dark)
        );
        // If they match, do not rewrite (no wasted Set-Cookie on every screen).
        assert_eq!(
            theme_cookie_to_write(None, Some(Theme::Dark), Some(Theme::Dark)),
            None
        );
        // When signed out (no user setting), the server does not erase a choice left on the device.
        assert_eq!(theme_cookie_to_write(None, None, Some(Theme::Dark)), None);
        assert_eq!(theme_cookie_to_write(None, None, None), None);
    }

    fn request_with_cookies(cookies: &[&str]) -> Request {
        let mut builder = Request::builder().uri("/");
        for cookie in cookies {
            builder = builder.header(COOKIE, *cookie);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn overwrite_keeps_other_cookies_and_replaces_lang() {
        let mut request = request_with_cookies(&["sso_session_id=sess; lang=ja; other=x"]);
        overwrite_lang_cookie(&mut request, Locale::En);
        assert_eq!(
            cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE),
            Some("sess".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("en".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), "other"),
            Some("x".to_string())
        );
    }

    /// Even if `lang` appears in multiple headers or duplicates, downstream reads a single decided value.
    #[test]
    fn overwrite_collapses_duplicate_lang_cookies() {
        let mut request = request_with_cookies(&["lang=ja", "lang=fr; sso_session_id=sess"]);
        overwrite_lang_cookie(&mut request, Locale::En);
        let header = request
            .headers()
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("cookie header");
        assert_eq!(header.matches("lang=").count(), 1, "{header}");
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("en".to_string())
        );
        assert_eq!(
            cookies::get(request.headers(), cookies::SSO_SESSION_COOKIE),
            Some("sess".to_string())
        );
    }

    fn request_with_ui_locales(cookies: &[&str], ui_locales: &str) -> Request {
        let mut request = request_with_cookies(cookies);
        request.extensions_mut().insert(RpLoginContext {
            ui_locales: Some(ui_locales.to_string()),
            ..RpLoginContext::default()
        });
        request
    }

    /// Decision order 4 (G12): `ui_locales` is weaker than the user's chosen language and stronger than the browser language.
    /// While a valid choice remains in the cookie, it is not switched by the RP's request.
    #[test]
    fn ui_locales_yields_to_the_language_the_user_chose() {
        assert_eq!(
            requested_locale(&request_with_ui_locales(&["lang=ja"], "en")),
            None,
            "the user's own choice wins"
        );
        // If the stored value is unsupported (= invalid as a choice), the RP's request is taken.
        assert_eq!(
            requested_locale(&request_with_ui_locales(&["lang=fr"], "en")),
            Some(Locale::En)
        );
        assert_eq!(
            requested_locale(&request_with_ui_locales(&[], "fr en-GB")),
            Some(Locale::En)
        );
        // A request containing no supported language decides nothing (downstream uses `Accept-Language`).
        assert_eq!(requested_locale(&request_with_ui_locales(&[], "fr")), None);
    }

    /// Requests outside an OIDC flow (no context attached) decide nothing.
    #[test]
    fn ui_locales_is_absent_outside_the_authorization_flow() {
        assert_eq!(requested_locale(&request_with_cookies(&[])), None);
        let mut request = request_with_cookies(&[]);
        request.extensions_mut().insert(RpLoginContext::default());
        assert_eq!(requested_locale(&request), None);
    }

    #[test]
    fn overwrite_adds_the_cookie_when_none_was_sent() {
        let mut request = request_with_cookies(&[]);
        overwrite_lang_cookie(&mut request, Locale::Ja);
        assert_eq!(
            cookies::get(request.headers(), cookies::LANG_COOKIE),
            Some("ja".to_string())
        );
    }
}
