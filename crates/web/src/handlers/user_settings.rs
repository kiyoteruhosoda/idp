//! User self-service settings screen (web. `/{tenant_id}/settings`. MT15, MT20).
//!
//! Signed-in users (holding an SSO session) access their own password change, display language choice and MFA (TOTP /
//! Passkey) management entry points here. Password change is delegated to the api's `POST /internal/account/change-password`,
//! and MFA leads to the existing `/{tenant_id}/account/*` screens.
//!
//! Display settings (language, color scheme; MT20) are saved only by [`save_display_preferences`]
//! (`POST /{tenant_id}/settings/display`). GET `?lang=` / `?theme=` are temporary switches
//! (the [`crate::display_preferences`] middleware only applies them to the cookie and that screen's display)
//! and are not written to the user settings (DB) (task #79).
//!
//! All state changes on this screen (display name, password, language, color scheme) are protected by the CSRF
//! synchronizer token (`console_csrf_token`, derived from the SSO session id) (task #79, #118). It does not rely on the
//! SameSite=Lax SSO cookie alone — the same practice as other user screens (session list, authenticators).
//! If the token does not match, nothing is saved; it returns to the settings screen and reports via a banner.

use super::internal_call_status;
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::display_preferences::{fetch_account_profile, FetchedAccountProfile};
use crate::dto::{AccountNameForm, AccountPasswordForm, DisplayPreferencesForm, SettingsQuery};
use crate::handlers::{forwarded_context, found, locale, see_other, step_up};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, UserSettings};
use crate::tenant::WebTenant;
use crate::theme::Theme;
use assay_contracts::auth::{
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountProfileResponse, InternalAccountUpdateLanguageRequest,
    InternalAccountUpdateLanguageResponse, InternalAccountUpdateNameRequest,
    InternalAccountUpdateNameResponse, InternalAccountUpdateThemeRequest,
    InternalAccountUpdateThemeResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// Settings screen (`GET /{tenant_id}/settings`).
///
/// Interpreting `?lang=` / `?theme=` (temporary switch) and saving the cookie are done for every screen by the
/// [`crate::display_preferences::resolve_display_preferences`] middleware
/// (MT20). This only renders with the decided values; the selectors POST to [`save_display_preferences`]
/// with a CSRF token (task #79).
pub async fn page(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
    fetched: Option<Extension<FetchedAccountProfile>>,
) -> Response {
    let locale = locale(&headers);
    let from_admin = query.from.as_deref() == Some("admin");

    // Not signed in / session expired goes to the login screen (task #121). Same shape as other account screens
    // such as authenticators and the session list (no return destination attached).
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    // Prefill values for display name and login identifier. The profile fetched by the display settings middleware is
    // reused without calling the api again (task #80). Only when the middleware did not fetch it (decided by both `?lang=`
    // and `?theme=`) is it fetched here. On fetch failure it renders with empty strings (fail-soft).
    let profile = match fetched {
        Some(Extension(FetchedAccountProfile(profile))) => profile,
        None => fetch_account_profile(&state, &sso).await,
    };
    if matches!(
        profile,
        Some(InternalAccountProfileResponse::SessionExpired)
    ) {
        return found(&format!("{}/login", tenant.prefix()));
    }
    let (current_name, preferred_username, stored_theme) = match profile {
        Some(InternalAccountProfileResponse::Ok {
            name,
            preferred_username,
            theme,
            ..
        }) => (
            name.unwrap_or_default(),
            preferred_username.unwrap_or_default(),
            theme,
        ),
        _ => (String::new(), String::new(), None),
    };
    // Same decision order as the middleware (`?theme=` > user setting > cookie). **Reading `?theme=` here too**
    // is the key point: the temporary-switch cookie is written in the response, so in this request both the cookie and
    // the user setting still return the pre-switch value. Without reading it, "the screen switched but the selector
    // stayed" would appear.
    // Unselected (no `?theme=`, DB or cookie) is shown as "follow the OS" selected —
    // the selector has no "unselected" option, and the actual appearance does follow the OS.
    let current_theme = query
        .theme
        .as_deref()
        .and_then(Theme::from_tag)
        .or_else(|| stored_theme.as_deref().and_then(Theme::from_tag))
        .or_else(|| cookies::get(&headers, cookies::THEME_COOKIE).and_then(|t| Theme::from_tag(&t)))
        .unwrap_or(Theme::System);

    let csrf = console_csrf_token(&sso, state.config.csrf_secret());

    // Messages contains a FluentBundle and is !Send, so render first and drop it so it does not live across an await.
    let body = {
        let messages = Messages::new(locale);
        render(&UserSettings {
            messages: &messages,
            tenant: &tenant.prefix(),
            current_lang: locale.as_tag(),
            current_theme: current_theme.as_tag(),
            current_name: &current_name,
            preferred_username: &preferred_username,
            saved_key: query.saved.as_deref().and_then(saved_key_for),
            error_key: query.error.as_deref().and_then(error_key_for),
            from_admin,
            csrf: &csrf,
        })
    };

    Html(body).into_response()
}

/// Self-service password change (`POST /{tenant_id}/settings/password`).
pub async fn change_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AccountPasswordForm>,
) -> Response {
    let base = format!("{}/settings", tenant.prefix());
    // Keep the admin-console-originated context (back link) across the PRG redirect.
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{base}?error=session{suffix}"));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("self-service password change rejected: csrf token mismatch");
        return found(&format!("{base}?error=csrf{suffix}"));
    }
    if form.new_password != form.new_password_confirm {
        return found(&format!("{base}?error=mismatch{suffix}"));
    }
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountChangePasswordRequest {
        sso_session_id: sso,
        current_password: form.current_password,
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .account_change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "account change-password call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    match outcome {
        InternalAccountChangePasswordResponse::Ok => {
            found(&format!("{base}?saved=password{suffix}"))
        }
        InternalAccountChangePasswordResponse::SessionExpired => {
            found(&format!("{base}?error=session{suffix}"))
        }
        InternalAccountChangePasswordResponse::InvalidCurrentPassword => {
            found(&format!("{base}?error=invalid-current{suffix}"))
        }
        InternalAccountChangePasswordResponse::WeakPassword { reason } => {
            let code = super::password_rejection_error_code(reason, "weak");
            found(&format!("{base}?error={code}{suffix}"))
        }
        InternalAccountChangePasswordResponse::Internal => {
            found(&format!("{base}?error=internal{suffix}"))
        }
    }
}

/// Self-service display name change (`POST /{tenant_id}/settings/name`).
pub async fn change_name(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AccountNameForm>,
) -> Response {
    let base = format!("{}/settings", tenant.prefix());
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{base}?error=session{suffix}"));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("self-service name change rejected: csrf token mismatch");
        return found(&format!("{base}?error=csrf{suffix}"));
    }
    let request = InternalAccountUpdateNameRequest {
        sso_session_id: sso,
        name: form.name,
    };
    let outcome = match state.api.account_update_name(&request).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "account update-name call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    match outcome {
        InternalAccountUpdateNameResponse::Ok => found(&format!("{base}?saved=name{suffix}")),
        InternalAccountUpdateNameResponse::SessionExpired => {
            found(&format!("{base}?error=session{suffix}"))
        }
        InternalAccountUpdateNameResponse::Invalid => {
            found(&format!("{base}?error=name-invalid{suffix}"))
        }
        InternalAccountUpdateNameResponse::Internal => {
            found(&format!("{base}?error=internal{suffix}"))
        }
    }
}

/// Saves display settings (language, color scheme) (`POST /{tenant_id}/settings/display`. task #79).
///
/// **The only path** writing to user settings (`users.language` / `users.theme`). Sent by the settings screen's
/// selectors and the admin console header's language dropdown (when signed in). GET `?lang=` / `?theme=` are
/// temporary switches and are not saved ([`crate::display_preferences`]).
///
/// - If the CSRF token (`console_csrf_token`) does not match, nothing is saved; return to the settings screen with a banner.
/// - After saving, align the cookie too (kept as the previous choice after sign-out) and 303 back to the `return_to`
///   screen. `return_to` accepts only paths under this tenant (no open redirect), and the
///   `lang` / `theme` queries are dropped (so a temporary switch at the destination does not appear to override the save).
/// - Following on other devices is as before: stored in the DB, and while signed in the DB beats the cookie.
pub async fn save_display_preferences(
    State(state): State<WebState>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<DisplayPreferencesForm>,
) -> Response {
    let settings = format!("{}/settings", tenant.prefix());
    let suffix = if form.from.as_deref() == Some("admin") {
        "&from=admin"
    } else {
        ""
    };
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        tracing::warn!("display preference change rejected: csrf token mismatch");
        return see_other(&format!("{settings}?error=csrf{suffix}"));
    }
    let locale = form.lang.as_deref().and_then(Locale::from_tag);
    let theme = form.theme.as_deref().and_then(Theme::from_tag);

    if let Some(locale) = locale {
        let request = InternalAccountUpdateLanguageRequest {
            sso_session_id: sso.clone(),
            language: locale.as_tag().to_string(),
        };
        match state.api.account_update_language(&request).await {
            Ok(InternalAccountUpdateLanguageResponse::Ok) => {}
            Ok(InternalAccountUpdateLanguageResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(other) => {
                tracing::warn!(?other, "unexpected outcome from update-language");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "account update-language call to api failed");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
        }
    }
    if let Some(theme) = theme {
        let request = InternalAccountUpdateThemeRequest {
            sso_session_id: sso.clone(),
            theme: theme.as_tag().to_string(),
        };
        match state.api.account_update_theme(&request).await {
            Ok(InternalAccountUpdateThemeResponse::Ok) => {}
            Ok(InternalAccountUpdateThemeResponse::SessionExpired) => {
                return found(&format!("{}/login", tenant.prefix()));
            }
            Ok(other) => {
                tracing::warn!(?other, "unexpected outcome from update-theme");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "account update-theme call to api failed");
                return see_other(&format!("{settings}?error=internal{suffix}"));
            }
        }
    }

    let back = without_display_overrides(&step_up::safe_next(&tenant, form.return_to.as_deref()));
    let mut set_cookies = state.set_cookies();
    if let Some(locale) = locale {
        set_cookies = set_cookies.set_local(
            cookies::LANG_COOKIE,
            locale.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    if let Some(theme) = theme {
        set_cookies = set_cookies.set_preference(
            cookies::THEME_COOKIE,
            theme.as_tag(),
            cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
        );
    }
    (set_cookies.into_headers(), see_other(&back)).into_response()
}

/// Drops the temporary-switch queries (`lang` / `theme`) from the return destination.
///
/// Saving Japanese from the header on a screen that still carries a temporary switch (`/admin/clients?lang=en`) would,
/// after returning there as is, re-apply `?lang=en` and make the save look ineffective.
fn without_display_overrides(path: &str) -> String {
    let Some((base, query)) = path.split_once('?') else {
        return path.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let name = pair.split('=').next().unwrap_or("");
            !pair.is_empty() && name != "lang" && name != "theme"
        })
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    }
}

fn saved_key_for(saved: &str) -> Option<&'static str> {
    match saved {
        "password" => Some("user-settings-password-saved"),
        "name" => Some("user-settings-name-saved"),
        _ => None,
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "mismatch" => Some("user-settings-error-mismatch"),
        "invalid-current" => Some("user-settings-error-invalid-current"),
        "weak" => Some("user-settings-error-weak"),
        "breached" => Some("password-error-breached"),
        "reused" => Some("password-error-reused"),
        "session" => Some("user-settings-error-session"),
        "internal" => Some("user-settings-error-internal"),
        "name-invalid" => Some("user-settings-error-name-invalid"),
        // CSRF token mismatch (task #79, #118). Same wording as the session list and authenticator screens.
        "csrf" => Some("user-security-error-csrf"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_settings(from_admin: bool) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&UserSettings {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000000",
            current_lang: "ja",
            current_theme: "system",
            current_name: "",
            preferred_username: "",
            saved_key: None,
            error_key: None,
            from_admin,
            csrf: "test-csrf",
        })
    }

    /// The color scheme selector shows the saved value as selected (prevents it looking like the default after saving).
    #[test]
    fn the_appearance_selector_shows_the_saved_choice() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |current_theme| {
            render(&UserSettings {
                messages: &messages,
                tenant: "/t",
                current_lang: "ja",
                current_theme,
                current_name: "",
                preferred_username: "",
                saved_key: None,
                error_key: None,
                from_admin: false,
                csrf: "test-csrf",
            })
        };

        let html = render_with("dark");
        assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
        assert!(
            !html.contains(r#"<option value="light" selected>"#),
            "{html}"
        );

        // Unselected is shown as "follow the device setting" (matching the actual appearance).
        let html = render_with("system");
        assert!(
            html.contains(r#"<option value="system" selected>"#),
            "{html}"
        );
    }

    /// Drops only the temporary switches (`lang` / `theme`) from the return destination, keeping other queries.
    #[test]
    fn the_return_path_drops_only_the_temporary_switches() {
        assert_eq!(without_display_overrides("/t/admin"), "/t/admin");
        assert_eq!(without_display_overrides("/t/admin?lang=en"), "/t/admin");
        assert_eq!(
            without_display_overrides("/t/admin/clients?page=2&lang=en&theme=dark&q=x"),
            "/t/admin/clients?page=2&q=x"
        );
        // Other parameters that merely share a name prefix are not dropped.
        assert_eq!(
            without_display_overrides("/t/admin?language=x&themes=y"),
            "/t/admin?language=x&themes=y"
        );
        assert_eq!(without_display_overrides("/t/settings?"), "/t/settings");
    }

    #[test]
    fn back_link_to_admin_console_is_shown_only_when_opened_from_admin() {
        let html = render_settings(true);
        assert!(html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        // Form submissions (display name, display, password, sign-out) also carry the admin console context in hidden
        // fields (sign-out: when returning due to a token mismatch. task #143).
        assert_eq!(
            html.matches(r#"<input type="hidden" name="from" value="admin">"#)
                .count(),
            4
        );

        let html = render_settings(false);
        assert!(!html.contains("/00000000-0000-7000-8000-000000000000/admin\""));
        assert!(!html.contains(r#"name="from""#));
    }
}
