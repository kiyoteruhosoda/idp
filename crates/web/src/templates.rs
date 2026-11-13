//! Askama template definitions for server-rendered screens (one per `.html` under `templates/`).
//!
//! Replaces the old HTML assembly with `format!`. Templates use the `.html` extension, so
//! `{{ }}` output is **automatically HTML-escaped**, preventing stored XSS by default (manual calls to
//! the old `html::escape` are no longer needed). Each template calls `messages.get("key")` directly for text.
//!
//! Each template struct binds its `.html` via `#[template(path = ...)]` and is type-checked at
//! compile time (same idea as sqlx's compile-time query checking).

use crate::admin_dto::{
    ApplicationAssignmentView, ApplicationBindingCandidateView, ApplicationCurrentUserView,
    ApplicationServiceAccountAssignmentView, ApplicationView, AuditLogView, BindingCandidateGroup,
    ClientView, ResourceView, SamlServiceProviderView, SigningKeyView, TenantCreatedView,
    TenantView,
};
use crate::i18n::Messages;
use askama::Template;
use assay_contracts::admin::AuthenticationPolicyResponse;
use assay_contracts::admin::{ClientStatusResponse, UserSummaryResponse};
use assay_contracts::application_log::ApplicationLogEntryResponse;
use assay_contracts::auth::PasskeyCredentialInfo;
use assay_contracts::version::{
    BuildTimeVersionInfoProvider, SchemaVersionInfo, VersionInfo, VersionInfoProvider,
};

/// Cargo package version shown in shared UI such as the footer.
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Version label shown in the footer. When the Git version (`git describe`, embedded at build time)
/// is available, `v{package} ({git})`; otherwise only the package version (`v{package}`).
pub fn footer_version() -> String {
    let info = BuildTimeVersionInfoProvider::new(app_version()).version_info();
    // Print `unknown` even when no git version is embedded (build arg forgotten). Omitting it silently
    // would leave operators unable to tell "a screen that never shows it" from "forgot to pass it".
    format!("{} ({})", info.display_version(), info.git_version)
}

/// Builds the **script-free fallback** for times shown on screen (ADR-0048).
///
/// The api returns RFC 3339 UTC strings (`2026-09-09T11:20:04.512345Z`). Showing them as is
/// is not only long but also **not in the viewer's time zone**. In practice, narrow screens cut off
/// everything after the seconds, leaving "when" unreadable.
///
/// This returns the form `2026-09-09 11:20 UTC`. When the browser runs scripts,
/// `assets/local-time.js` replaces it with the viewer's time zone, so this is
/// **the value left when JavaScript did not run**. UTC is stated explicitly so that, when the
/// replacement does not happen, we never silently show a time that is 9 hours off.
///
/// Unparseable values are returned as is (a raw value is a better clue than showing nothing).
pub fn utc_short(value: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(value) {
        Ok(t) => t
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        Err(_) => value.to_string(),
    }
}

/// Cache-busting version appended to asset URLs (`/assets/app.css?v=...`).
///
/// Assets are bundled in the binary and change only per deploy, but with stable URLs intermediate caches
/// (CDN, browser) keep serving old assets until their TTL runs out (Cloudflare actually overrides
/// the origin's `max-age=0` and caches for 4 hours). Changing the URL itself on every deploy
/// forces fresh assets regardless of cache TTL.
///
/// The value is "package version-content digest of bundled assets". **The git version is not included** (ADR-0034).
/// This URL also appears on the unauthenticated login screen (`page.html`), so mixing in the git version
/// would let outsiders read the running commit, defeating the point of removing the version from the
/// footer. Any change in asset content always changes the digest, so the digest alone suffices for cache busting.
/// Characters other than those safe in a query value (alphanumerics, `.` `-` `_`) are replaced with `-`.
pub fn asset_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let digest = embedded_assets_digest();
        format!("{}-{digest:016x}", app_version())
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    })
}

/// Content digest of bundled assets referenced via `?v=` URLs. Used only for cache busting, so
/// no cryptographic strength is needed (FNV-1a 64bit). Webfonts are excluded: they use stable URLs
/// (relative references in the FA CSS) that cannot carry a query, so changing the digest would not change their URL.
fn embedded_assets_digest() -> u64 {
    [
        crate::handlers::stylesheet::APP_CSS,
        crate::handlers::console_script::CONSOLE_JS,
        crate::handlers::submit_feedback_script::SUBMIT_FEEDBACK_JS,
        crate::handlers::react_assets::APP_JS,
        crate::handlers::vendor_assets::BOOTSTRAP_CSS,
        crate::handlers::vendor_assets::BOOTSTRAP_JS,
        crate::handlers::vendor_assets::FONTAWESOME_CSS,
        // Page-specific scripts (SEC12) are also served with `?v=` and `immutable`, so their content goes into
        // the digest. If forgotten, a deploy that only fixes JS (a build whose git version is `unknown`) keeps
        // the same URL and browsers keep the old script.
        crate::handlers::page_scripts::PASSKEY_LOGIN_JS,
        crate::handlers::page_scripts::PASSKEY_REGISTER_JS,
        crate::handlers::page_scripts::PASSWORD_VISIBILITY_JS,
        crate::handlers::page_scripts::RP_LOGOUT_JS,
        crate::handlers::page_scripts::AUTO_SUBMIT_JS,
        crate::handlers::page_scripts::CLIENT_FORM_JS,
        crate::handlers::page_scripts::LOCAL_TIME_JS,
    ]
    .into_iter()
    .fold(0xcbf2_9ce4_8422_2325, |hash, asset| {
        fnv1a64(hash, asset.as_bytes())
    })
}

/// FNV-1a 64bit hash (folds `bytes` into `hash` as the initial value).
fn fnv1a64(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_dto::{
        RuntimeSettingView, SettingChoiceView, SystemSettingsView, TenantOverrideView,
        TenantSettingView, TenantSettingsListView,
    };
    use crate::i18n::{Locale, Messages};

    /// Second-based settings are shown with a readable duration (owner: "seconds are hard to read", task #887).
    #[test]
    fn seconds_are_shown_with_a_readable_duration() {
        let ja = Messages::new(Locale::Ja);
        let en = Messages::new(Locale::En);
        assert_eq!(duration_label(&ja, 604_800).as_deref(), Some("7 日"));
        assert_eq!(duration_label(&ja, 28_800).as_deref(), Some("8 時間"));
        assert_eq!(duration_label(&ja, 2_592_000).as_deref(), Some("30 日"));
        assert_eq!(
            duration_label(&ja, 95_400).as_deref(),
            Some("1 日 2 時間 30 分")
        );
        assert_eq!(duration_label(&ja, 0), None);
        assert_eq!(duration_label(&en, 86_400).as_deref(), Some("1 day"));
        assert_eq!(duration_label(&en, 900).as_deref(), Some("15 minutes"));
        assert!(is_seconds_setting("SSO_IDLE_TTL_SECS"));
        assert!(!is_seconds_setting("PASSWORD_MAX_AGE_DAYS"));
    }

    /// The sidebar and the home page must not lay out menus on their own.
    ///
    /// ⚠ **This was actually broken for a while** -- "External IdP" was only in the sidebar and
    /// "Authentication policies" only on home; neither was a subset of the other, so users could not
    /// even read it as "abbreviated". As long as both render from [`CONSOLE_NAV`], drift **cannot be written**.
    /// The moment someone writes an `href` directly, this fails.
    #[test]
    fn the_console_menu_is_the_only_place_that_lists_admin_screens() {
        // Only the link to home itself (the sidebar's first item "Console top") lives outside the definition.
        const ALLOWED: &str = "{{ tenant }}/admin\"";
        for (name, source) in [
            (
                "layout.html",
                include_str!("../templates/console/layout.html"),
            ),
            ("home.html", include_str!("../templates/console/home.html")),
        ] {
            for (n, line) in source.lines().enumerate() {
                if !line.contains("{{ tenant }}/admin") || line.contains(ALLOWED) {
                    continue;
                }
                // Authentication actions (log out, switch tenant) are header controls, not menu items.
                if line.contains("/admin/logout") || line.contains("/admin/switch-tenant") {
                    continue;
                }
                // The endpoint the new-version notice polls (not a screen).
                if line.contains("/admin/version/current") {
                    continue;
                }
                panic!(
                    "{name}:{} writes a menu directly; add it to CONSOLE_NAV: {}",
                    n + 1,
                    line.trim()
                );
            }
        }
    }

    /// Menu translation keys must exist in both languages.
    ///
    /// ⚠ **A state where only the description keys were missing actually existed** -- "External IdP" was only
    /// in the sidebar, which does not show descriptions, so nobody defined `-desc`. As soon as it was put
    /// on home, the raw key name appeared on screen (`Messages::get` returns unknown keys as is).
    #[test]
    fn every_menu_entry_has_both_a_name_and_a_description() {
        for locale in [Locale::Ja, Locale::En] {
            let messages = Messages::new(locale);
            for group in CONSOLE_NAV {
                for key in [group.label, group.description] {
                    assert_ne!(messages.get(key), key, "{key} untranslated ({locale:?})");
                }
                for item in group.items {
                    for key in [item.label, item.description] {
                        assert_ne!(messages.get(key), key, "{key} untranslated ({locale:?})");
                    }
                }
            }
        }
    }

    /// Groups and destinations must not be duplicated (never place the same screen in two places).
    #[test]
    fn the_console_menu_lists_each_screen_once() {
        let mut seen = std::collections::BTreeSet::new();
        for group in CONSOLE_NAV {
            for item in group.items {
                assert!(seen.insert(item.path), "{} is listed twice", item.path);
            }
        }
    }

    /// Detects mismatches between fields the form submits and fields the handler requires (ADR-0032).
    ///
    /// `usage` is a **required** field of `NewClientForm` / `EditClientForm`, so if the template stops
    /// rendering it, registration returns 400. In fact, when this field was added only the E2E script did not
    /// send it and CI failed -- pin the renderer/receiver correspondence here, not on a slow path.
    #[test]
    fn the_client_form_renders_the_controls_the_handler_requires() {
        let messages = Messages::new(Locale::Ja);
        let values = ClientFormValues::default_new();
        let form = ClientForm {
            messages: &messages,
            tenant: "/019f6514-08ea-7138-ad71-838a7bdd3575",
            admin: None,
            csrf: &"0".repeat(64),
            error: None,
            heading: "新規クライアント",
            action: "/x/admin/clients/new",
            is_new: true,
            values: &values,
            list_href: "/x/admin/clients".to_string(),
        };
        let html = render(&form);
        for control in [
            r#"name="app_name""#,
            r#"name="usage""#,
            r#"name="client_type""#,
            r#"name="redirect_uris""#,
            r#"name="scope_profile""#,
            r#"name="scope_email""#,
            r#"name="scope_offline_access""#,
            r#"name="csrf_token""#,
        ] {
            assert!(html.contains(control), "{control} is not rendered");
        }
        // The entry point decides the usage, so the form shows no choice and carries it as hidden (ADR-0038).
        // `usage` is required by the handler, so if the hidden field disappears registration returns 400.
        assert!(
            html.contains(
                r#"<input type="hidden" id="client-usage" name="usage" value="user_login">"#
            ),
            "{html}"
        );
        assert!(
            !html.contains(r#"<select class="form-select" id="client-usage""#),
            "no usage select is shown: {html}"
        );
        // `openid` cannot be removed (it has no input; the handler always adds it).
        assert!(html.contains(r#"id="client-scope-openid""#), "{html}");
        assert!(
            !html.contains(r#"name="scope_openid""#),
            "openid must not be a submitted input: {html}"
        );
    }

    /// ADR-0032: usage is decided by whether `client_credentials` is present.
    #[test]
    fn usage_reflects_what_the_client_can_actually_do() {
        let login = vec!["authorization_code".to_string()];
        let system = vec!["client_credentials".to_string()];
        let uris = vec!["https://a.example.com/cb".to_string()];
        assert_eq!(
            usage_from_registration(&login, &uris),
            client_usage::USER_LOGIN
        );
        assert_eq!(usage_from_registration(&system, &[]), client_usage::SYSTEM);
        // Even with no grant at all (should not happen), do not treat it as a system client.
        assert_eq!(usage_from_registration(&[], &[]), client_usage::USER_LOGIN);
        // The "both" shape (the api does not allow creating it). Reading it as system hides the redirect_uri field,
        // and merely saving would erase the registered redirect URIs. Lean toward keeping the URIs.
        let both = vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ];
        assert_eq!(
            usage_from_registration(&both, &uris),
            client_usage::USER_LOGIN
        );
    }

    #[test]
    fn asset_version_is_url_safe_and_non_empty() {
        let v = asset_version();
        assert!(!v.is_empty());
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
    }

    /// So that the URL changes with asset content even in builds without an injected git version,
    /// the version always includes the content digest.
    #[test]
    fn asset_version_includes_content_digest() {
        let digest = format!("{:016x}", embedded_assets_digest());
        assert!(asset_version().ends_with(&digest));
    }

    #[test]
    fn content_digest_changes_when_asset_bytes_change() {
        let base = 0xcbf2_9ce4_8422_2325;
        assert_ne!(
            fnv1a64(base, b"body { color: red }"),
            fnv1a64(base, b"body { color: blue }")
        );
        assert_ne!(fnv1a64(base, b""), fnv1a64(fnv1a64(base, b"a"), b""));
    }

    /// The restart-wait screen must "return to the settings screen on its own" and "have no clickable links"
    /// (ADR-0017). web stops right after returning this screen, so any navigation would leave every link
    /// unreachable for a few seconds, looking broken.
    #[test]
    fn the_restarting_page_reloads_itself_and_offers_no_console_navigation() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&Restarting {
            messages: &messages,
            settings_href: "/t/admin/settings",
            retry_after_seconds: 20,
        });
        assert!(
            html.contains(r#"<meta http-equiv="refresh" content="20;url=/t/admin/settings">"#),
            "{html}"
        );
        assert!(
            !html.contains("<nav"),
            "no navigation while both are down: {html}"
        );
        assert!(!html.contains("/admin/logout"), "{html}");
    }

    /// Rows that cannot be operated on individually (primary identifier, primary email) get no action buttons.
    ///
    /// ⚠ **Do not decide by whether a row exists.** Since AP15b the primary identifier is also a registry row
    /// and always has an `id`, so deciding by `id` alone shows **buttons that always fail when pressed** (the api
    /// rejects on `primary_of_user IS NULL` / `primary_email_of_user IS NULL`).
    #[test]
    fn rows_that_cannot_be_operated_on_show_no_buttons() {
        let messages = Messages::new(Locale::Ja);
        let render_row = |is_primary: bool, is_primary_email: bool| {
            render(&LoginIdentifiersConsole {
                messages: &messages,
                tenant: "/t",
                admin: Some(ConsoleAdmin {
                    label: "admin",
                    tenant_name: Some("Acme"),
                    permissions: &["idp.tenant.admin".to_string()],
                    csrf_token: "test-console-csrf",
                }),
                csrf: "csrf-token",
                user_id: "11111111-1111-1111-1111-111111111111",
                identifiers: &[LoginIdentifierRow {
                    id: Some("22222222-2222-2222-2222-222222222222"),
                    identifier_type: "email",
                    type_label: "メールアドレス".to_string(),
                    display_value: "u@example.com",
                    normalized_value: "u@example.com",
                    is_active: true,
                    is_primary,
                    is_primary_email,
                }],
                type_options: &[],
                error_key: None,
                notice_key: None,
            })
        };

        let ordinary = render_row(false, false);
        assert!(ordinary.contains("/active"), "{ordinary}");
        assert!(ordinary.contains("/delete"), "{ordinary}");

        for (is_primary, is_primary_email) in [(true, false), (false, true)] {
            let html = render_row(is_primary, is_primary_email);
            assert!(!html.contains("/active"), "{html}");
            assert!(!html.contains("/delete"), "{html}");
            assert!(
                html.contains(&messages.get("admin-login-identifiers-primary-hint")),
                "{html}"
            );
        }

        // The primary email row is shown under a heading separate from the primary identifier (otherwise one cannot tell how to fix it).
        let primary_email = render_row(false, true);
        assert!(
            primary_email.contains(&messages.get("admin-login-identifiers-primary-email")),
            "{primary_email}"
        );
    }

    /// Promote-to-primary-email is shown **only on email-type rows** (ADR-0052). Showing it on phone numbers
    /// or employee numbers would show buttons that always fail (the api rejects by type).
    #[test]
    fn only_email_rows_offer_the_promotion_to_primary_email() {
        let messages = Messages::new(Locale::Ja);
        let render_row = |identifier_type: &str, is_primary_email: bool| {
            render(&LoginIdentifiersConsole {
                messages: &messages,
                tenant: "/t",
                admin: Some(ConsoleAdmin {
                    label: "admin",
                    tenant_name: Some("Acme"),
                    permissions: &["idp.tenant.admin".to_string()],
                    csrf_token: "test-console-csrf",
                }),
                csrf: "csrf-token",
                user_id: "11111111-1111-1111-1111-111111111111",
                identifiers: &[LoginIdentifierRow {
                    id: Some("22222222-2222-2222-2222-222222222222"),
                    identifier_type,
                    type_label: "種別".to_string(),
                    display_value: "u@example.com",
                    normalized_value: "u@example.com",
                    is_active: true,
                    is_primary: false,
                    is_primary_email,
                }],
                type_options: &[],
                error_key: None,
                notice_key: None,
            })
        };

        let alias_email = render_row("email", false);
        assert!(alias_email.contains("/primary-email"), "{alias_email}");
        assert!(
            alias_email.contains(&messages.get("admin-login-identifiers-promote-email")),
            "{alias_email}"
        );

        // Not shown for other types.
        for other in ["username", "phone_number", "employee_number"] {
            let html = render_row(other, false);
            assert!(!html.contains("/primary-email"), "{other}: {html}");
        }

        // A row that is already the primary email is not a target at all (no promote button either).
        let already_primary = render_row("email", true);
        assert!(
            !already_primary.contains("/primary-email"),
            "{already_primary}"
        );
    }

    /// Tenant settings show the email-login toggle reflecting the current state (ADR-0050 decision 3).
    #[test]
    fn the_tenant_settings_show_the_email_login_toggle() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |enabled: bool| {
            render(&AdminSettings {
                messages: &messages,
                tenant: "/t",
                admin: Some(ConsoleAdmin {
                    label: "admin",
                    tenant_name: Some("Acme"),
                    permissions: &["idp.tenant.admin".to_string()],
                    csrf_token: "test-console-csrf",
                }),
                tenant_id: "00000000-0000-7000-8000-000000000000",
                tenant_name: "Acme",
                tenant_status: "ACTIVE",
                tenant_self_registration: false,
                tenant_email_login: enabled,
                csrf: "csrf-token",
                saved: false,
                error_key: None,
                tenant_settings: None,
                tenant_smtp: None,
                system: None,
                pending_api_keys: &[],
                stale_web_keys: &[],
                filter: &crate::settings_filter::SettingsFilter::default(),
                tenant_values_total: 0,
                runtime_total: 0,
            })
        };

        let off = render_with(false);
        assert!(off.contains("name=\"email_login_enabled\""), "{off}");
        assert!(
            off.contains(&messages.get("admin-settings-email-login")),
            "{off}"
        );

        /// Extracts only the toggle's `<input>` tag (so it is not confused with the self-registration toggle).
        fn toggle_input(html: &str) -> String {
            let start = html.find(r#"id="email_login_enabled""#).expect("toggle");
            let end = html[start..].find('>').expect("tag end");
            html[start..start + end].to_string()
        }

        assert!(!toggle_input(&off).contains("checked"), "{off}");
        let on = render_with(true);
        assert!(toggle_input(&on).contains("checked"), "{on}");
    }

    fn tenant_setting(
        key: &str,
        kind: &str,
        value: &str,
        origin: &str,
        whole: &str,
    ) -> TenantSettingView {
        TenantSettingView {
            key: key.to_string(),
            description: format!("{key} の説明"),
            kind: kind.to_string(),
            choices: Vec::new(),
            value: value.to_string(),
            origin: origin.to_string(),
            whole_idp_value: whole.to_string(),
        }
    }

    fn render_settings_page(
        messages: &Messages,
        tenant_settings: Option<&TenantSettingsListView>,
        system: Option<&SystemSettingsView>,
    ) -> String {
        render(&AdminSettings {
            messages,
            tenant: "/t",
            admin: Some(ConsoleAdmin {
                label: "admin",
                tenant_name: Some("Acme"),
                permissions: &["idp.tenant.admin".to_string()],
                csrf_token: "test-console-csrf",
            }),
            tenant_id: "00000000-0000-7000-8000-000000000000",
            tenant_name: "Acme",
            tenant_status: "ACTIVE",
            tenant_self_registration: false,
            tenant_email_login: false,
            csrf: "csrf-token",
            saved: false,
            error_key: None,
            tenant_settings,
            tenant_smtp: None,
            system,
            pending_api_keys: &[],
            stale_web_keys: &[],
            filter: &crate::settings_filter::SettingsFilter::default(),
            tenant_values_total: 0,
            runtime_total: 0,
        })
    }

    /// Shows the filter form, writes back the conditions, and shows the pre-filter count and "no matches".
    /// The runtime-setting kind is shown only when that list is viewable (root).
    #[test]
    fn the_settings_filter_keeps_its_condition_and_shows_counts() {
        let messages = Messages::new(Locale::Ja);
        let filter = crate::settings_filter::SettingsFilter::new(Some("zzz"), Some("1"), None);
        let empty = TenantSettingsListView { settings: vec![] };
        let html = render(&AdminSettings {
            messages: &messages,
            tenant: "/t",
            admin: Some(ConsoleAdmin {
                label: "admin",
                tenant_name: Some("Acme"),
                permissions: &["idp.tenant.admin".to_string()],
                csrf_token: "test-console-csrf",
            }),
            tenant_id: "00000000-0000-7000-8000-000000000000",
            tenant_name: "Acme",
            tenant_status: "ACTIVE",
            tenant_self_registration: false,
            tenant_email_login: false,
            csrf: "csrf-token",
            saved: false,
            error_key: None,
            tenant_settings: Some(&empty),
            tenant_smtp: None,
            system: None,
            pending_api_keys: &[],
            stale_web_keys: &[],
            filter: &filter,
            tenant_values_total: 16,
            runtime_total: 0,
        });
        assert!(html.contains("id=\"settings-filter\""), "{html}");
        assert!(html.contains("value=\"zzz\""), "{html}");
        assert!(
            html.contains("id=\"settings-filter-mine\" name=\"mine\" value=\"1\" checked"),
            "{html}"
        );
        // Without root, the runtime-setting kind is not shown.
        assert!(!html.contains("id=\"settings-filter-runtime\""), "{html}");
        assert!(html.contains("0 / 16"), "{html}");
        assert!(
            html.contains(&messages.get("admin-settings-filter-none")),
            "{html}"
        );
        assert!(
            html.contains(&messages.get("admin-settings-filter-clear")),
            "{html}"
        );
    }

    fn render_with_tenant_smtp(
        messages: &Messages,
        tenant_smtp: Option<&crate::admin_dto::TenantSmtpView>,
    ) -> String {
        render(&AdminSettings {
            messages,
            tenant: "/t",
            admin: Some(ConsoleAdmin {
                label: "admin",
                tenant_name: Some("Acme"),
                permissions: &["idp.smtp:write".to_string()],
                csrf_token: "test-console-csrf",
            }),
            tenant_id: "00000000-0000-7000-8000-000000000000",
            tenant_name: "Acme",
            tenant_status: "ACTIVE",
            tenant_self_registration: false,
            tenant_email_login: false,
            csrf: "csrf-token",
            saved: false,
            error_key: None,
            tenant_settings: None,
            tenant_smtp,
            system: None,
            pending_api_keys: &[],
            stale_web_keys: &[],
            filter: &crate::settings_filter::SettingsFilter::default(),
            tenant_values_total: 0,
            runtime_total: 0,
        })
    }

    /// The tenant's mail route (ADR-0058 §8). Without permission the whole section is hidden. When following the global
    /// route, say so and do not show "revert to global route". ⚠ Passwords are never rendered (only whether set).
    #[test]
    fn the_tenant_mail_route_section_follows_its_origin() {
        let messages = Messages::new(Locale::Ja);

        let hidden = render_with_tenant_smtp(&messages, None);
        assert!(!hidden.contains("id=\"tenant-smtp\""), "{hidden}");

        let inherited = crate::admin_dto::TenantSmtpView {
            inherited: true,
            ..Default::default()
        };
        let html = render_with_tenant_smtp(&messages, Some(&inherited));
        assert!(html.contains("id=\"tenant-smtp\""), "{html}");
        assert!(
            html.contains(&messages.get("admin-tenant-smtp-inherited")),
            "{html}"
        );
        assert!(!html.contains("/admin/settings/smtp/clear"), "{html}");

        let own = crate::admin_dto::TenantSmtpView {
            inherited: false,
            smtp_host: "smtp.tenant.example".into(),
            smtp_port: Some(587),
            smtp_username: "tenant-user".into(),
            smtp_password_set: true,
            smtp_from_address: "noreply@tenant.example".into(),
            smtp_use_tls: true,
        };
        let html = render_with_tenant_smtp(&messages, Some(&own));
        assert!(
            html.contains(&messages.get("admin-tenant-smtp-own")),
            "{html}"
        );
        assert!(html.contains("value=\"smtp.tenant.example\""), "{html}");
        assert!(html.contains("/admin/settings/smtp/clear"), "{html}");
        assert!(
            html.contains(&messages.get("admin-settings-smtp-password-set")),
            "{html}"
        );
    }

    /// Extracts the `<li>` of one item (to check each item's display without mixing it with others).
    fn tenant_value_item(html: &str, key: &str) -> String {
        let marker = format!("id=\"tenant-value-{key}\"");
        let start = html
            .find(&marker)
            .unwrap_or_else(|| panic!("{key}: {html}"));
        let end = html[start..].find("</li>").expect("item end");
        html[start..start + end].to_string()
    }

    /// ⚠ Never show only the value (ADR-0058 §6). Always show whether it "follows the global setting" or
    /// "was set by this tenant", alongside the global value. "Revert to global" appears only for items set by this tenant.
    #[test]
    fn tenant_values_show_where_each_value_comes_from_and_the_whole_idp_value() {
        let messages = Messages::new(Locale::Ja);
        let list = TenantSettingsListView {
            settings: vec![
                tenant_setting(
                    "PASSWORD_MIN_LENGTH",
                    "UNSIGNED_INTEGER",
                    "16",
                    "TENANT_OVERRIDE",
                    "8",
                ),
                tenant_setting(
                    "LOGIN_MAX_FAILED_ATTEMPTS",
                    "UNSIGNED_INTEGER",
                    "10",
                    "INHERITED",
                    "10",
                ),
                tenant_setting(
                    "PASSWORD_BREACH_CHECK_ENABLED",
                    "BOOLEAN",
                    "false",
                    "INHERITED",
                    "false",
                ),
                tenant_setting("A_KEY_WITHOUT_A_LABEL", "TEXT", "x", "INHERITED", "x"),
            ],
        };
        let html = render_settings_page(&messages, Some(&list), None);

        let overridden = tenant_value_item(&html, "PASSWORD_MIN_LENGTH");
        assert!(
            overridden.contains(&messages.get("admin-tenant-values-origin-override")),
            "{overridden}"
        );
        assert!(overridden.contains(&messages.get("admin-tenant-setting-PASSWORD_MIN_LENGTH")));
        assert!(overridden.contains("<code>16</code>"), "{overridden}");
        assert!(
            overridden.contains("<code>8</code>"),
            "whole-IdP value: {overridden}"
        );
        assert!(
            overridden.contains("/admin/settings/tenant/keys/clear"),
            "{overridden}"
        );

        let inherited = tenant_value_item(&html, "LOGIN_MAX_FAILED_ATTEMPTS");
        assert!(
            inherited.contains(&messages.get("admin-tenant-values-origin-inherited")),
            "{inherited}"
        );
        assert!(!inherited.contains(&messages.get("admin-tenant-values-origin-override")));
        assert!(
            !inherited.contains("/admin/settings/tenant/keys/clear"),
            "{inherited}"
        );
        assert!(inherited.contains("type=\"number\""), "{inherited}");

        let boolean = tenant_value_item(&html, "PASSWORD_BREACH_CHECK_ENABLED");
        assert!(boolean.contains("<select"), "{boolean}");
        assert!(boolean.contains(&format!(
            "<code>{}</code>",
            messages.get("admin-tenant-values-false")
        )));

        // Even a key without a translation keeps its item; the key itself becomes the heading.
        let unlabeled = tenant_value_item(&html, "A_KEY_WITHOUT_A_LABEL");
        assert!(unlabeled.contains("A_KEY_WITHOUT_A_LABEL"), "{unlabeled}");
        assert!(
            !unlabeled.contains("admin-tenant-setting-A_KEY"),
            "{unlabeled}"
        );
    }

    /// When unreadable (`None`), the whole section is hidden.
    #[test]
    fn tenant_values_are_hidden_without_the_read_permission() {
        let messages = Messages::new(Locale::Ja);
        let html = render_settings_page(&messages, None, None);
        assert!(!html.contains("id=\"tenant-values\""), "{html}");
    }

    /// Options that could lock people out read as "confirmation before saving" even before being chosen.
    #[test]
    fn choices_that_can_lock_people_out_are_marked() {
        let messages = Messages::new(Locale::Ja);
        let mut item = tenant_setting(
            "AUTH_POLICY_DEFAULT_EFFECT",
            "CHOICE",
            "allow",
            "INHERITED",
            "allow",
        );
        item.choices = vec![
            SettingChoiceView {
                value: "allow".to_string(),
                locks_out: false,
            },
            SettingChoiceView {
                value: "deny".to_string(),
                locks_out: true,
            },
        ];
        let list = TenantSettingsListView {
            settings: vec![item],
        };
        let html = tenant_value_item(
            &render_settings_page(&messages, Some(&list), None),
            "AUTH_POLICY_DEFAULT_EFFECT",
        );
        let note = messages.get("admin-tenant-values-choice-locks-out");
        assert!(html.contains(&format!("deny（{note}）")), "{html}");
        assert!(!html.contains(&format!("allow（{note}）")), "{html}");
    }

    /// The global settings screen shows, for tenant-overridable keys, the "following" count and the "deviating tenants".
    #[test]
    fn whole_idp_settings_show_how_tenants_follow_each_overridable_key() {
        let messages = Messages::new(Locale::Ja);
        let system = SystemSettingsView {
            smtp_host: String::new(),
            smtp_port: None,
            smtp_username: String::new(),
            smtp_password_set: false,
            smtp_from_address: String::new(),
            smtp_use_tls: false,
            sms_gateway_url: String::new(),
            sms_auth_header: String::new(),
            sms_auth_token_set: false,
            sms_sender_id: String::new(),
            runtime_settings: vec![
                RuntimeSettingView {
                    key: "LOGIN_LOCK_DURATION_SECS".to_string(),
                    tenant_overridable: true,
                    tenants_following: Some(3),
                    tenants_overriding: vec![TenantOverrideView {
                        tenant_id: "t-1".to_string(),
                        tenant_name: "Branch Office".to_string(),
                        value: "1234".to_string(),
                    }],
                    ..Default::default()
                },
                RuntimeSettingView {
                    key: "ACCESS_TOKEN_TTL_SECS".to_string(),
                    ..Default::default()
                },
            ],
        };
        let html = render_settings_page(&messages, None, Some(&system));
        assert!(
            html.contains(&messages.get_arg(
                "admin-settings-runtime-tenants-following",
                "count",
                "3"
            )),
            "{html}"
        );
        assert!(html.contains(&messages.get_arg(
            "admin-settings-runtime-tenants-overriding",
            "count",
            "1"
        )));
        assert!(html.contains("Branch Office: <code>1234</code>"), "{html}");
        // Not shown for keys tenants cannot change.
        assert_eq!(
            html.matches(&messages.get("admin-settings-runtime-tenant-overridable"))
                .count(),
            1
        );
    }

    /// The confirmation screen resends the same value with `confirmed` added.
    #[test]
    fn the_confirmation_page_resends_the_value_with_confirmed() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&AdminTenantSettingConfirm {
            messages: &messages,
            tenant: "/t",
            admin: None,
            csrf: "csrf-token",
            key: "APPLICATION_ASSIGNMENT_ENFORCEMENT",
            label: "label",
            description: "",
            current_value: Some("record_only"),
            value: "enforce",
        });
        assert!(html.contains("name=\"confirmed\" value=\"1\""), "{html}");
        assert!(html.contains("name=\"value\" value=\"enforce\""), "{html}");
        assert!(html.contains("<code>record_only</code>"), "{html}");
        assert!(html.contains(&messages.get("admin-tenant-value-confirm-lead")));
    }

    /// The login screen uses the authorization request's `login_hint` as the username field's initial value (G12). The
    /// value is an arbitrary string from the RP, so also verify it is HTML-escaped as an attribute value.
    #[test]
    fn the_login_form_prefills_the_username_from_the_login_hint() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |login_hint| {
            render(&LoginTemplate {
                messages: &messages,
                tenant_prefix: "/t",
                csrf: "csrf-token",
                error_key: None,
                login_hint,
                client_name: None,
                tenant_name: None,
                app_approval_offered: false,
            })
        };

        /// Extracts only the username field's `<input>` tag (so it is not confused with other inputs).
        fn username_input(html: &str) -> String {
            let start = html.find(r#"id="login-username""#).expect("username input");
            let end = html[start..].find('>').expect("tag end");
            html[start..start + end].to_string()
        }

        let html = render_with(Some("alice@example.com"));
        assert!(
            username_input(&html).contains(r#"value="alice@example.com""#),
            "{html}"
        );

        // Without a hint there is no initial value (not even an empty value attribute).
        let html = render_with(None);
        assert!(!username_input(&html).contains("value="), "{html}");

        // A value that closes the attribute and injects another stays inside value, quotes and all escaped.
        let html = render_with(Some(r#"" autofocus onfocus="alert(1)"#));
        let tag = username_input(&html);
        assert!(tag.contains("alert(1)"), "the value is kept: {html}");
        // Quotes are escaped, so the value attribute is not closed and no `onfocus="..."` appears.
        assert!(
            !tag.contains(r#"onfocus=""#),
            "but never as an attribute: {html}"
        );
    }

    /// The sidebar and home **list the same destinations** (the symptom users first noticed).
    ///
    /// ⚠ Previously `/admin/external-idps` was only in the sidebar and
    /// `/admin/authentication-policies` only on home. Neither was a subset of the other, so it did not
    /// even read as "one side abbreviates". Home is rendered including the shared layout
    /// (= the sidebar), so **both can be counted in one render**.
    #[test]
    fn the_sidebar_and_the_home_cards_offer_the_same_screens() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            error_key: None,
            admin: Some(ConsoleAdmin {
                label: "admin",
                tenant_name: Some("Acme"),
                // The api returns the list with implications expanded (a root admin also gets signing-key permissions).
                permissions: &["idp.system.admin".to_string(), "idp.keys:read".to_string()],
                csrf_token: "test-console-csrf",
            }),
        });

        for group in CONSOLE_NAV {
            for item in group.items {
                let href = format!("\"/t{}\"", item.path);
                assert_eq!(
                    html.matches(&href).count(),
                    2,
                    "{} must appear exactly once in both the sidebar and home",
                    item.path
                );
            }
        }
    }

    /// Screens not in the menu also resolve to the item they were opened from (source of the sidebar marker and tab title).
    #[test]
    fn every_admin_screen_resolves_to_the_menu_entry_it_was_opened_from() {
        fn entry(path: &str) -> Option<&'static str> {
            console_nav_item_for(path).map(|item| item.path)
        }
        // The item itself and screens under it.
        assert_eq!(entry("/admin/accounts"), Some("/admin/accounts"));
        assert_eq!(entry("/admin/clients/new"), Some("/admin/clients"));
        assert_eq!(
            entry("/admin/applications/0190/assignments"),
            Some("/admin/applications")
        );
        // Screens at other paths but opened from "Accounts" / "Settings".
        for path in [
            "/admin/users/new",
            "/admin/members/0190",
            "/admin/service-accounts/abc",
            "/admin/invitations",
        ] {
            assert_eq!(entry(path), Some("/admin/accounts"), "{path}");
        }
        assert_eq!(
            entry("/admin/system-settings/runtime"),
            Some("/admin/settings")
        );
        assert_eq!(entry("/admin/restart"), Some("/admin/settings"));
        // Screens belonging to no item. ⚠ `/admin/logs` must not capture `/admin/login`.
        for path in [
            "/admin",
            "/admin/login",
            "/admin/switch-tenant",
            "/settings",
            "",
        ] {
            assert_eq!(entry(path), None, "{path}");
        }
        // Items written as the opening source must exist in the menu (fix together when renaming an item).
        for (prefix, parent) in CONSOLE_NAV_PARENTS {
            assert_eq!(entry(parent), Some(*parent), "{prefix} -> {parent}");
        }
    }

    /// The shared layout marks the open screen on one sidebar item and in the tab title.
    ///
    /// ⚠ Before the marker, the sidebar looked the same on every screen and the tab title was
    /// "Admin console" everywhere (tabs side by side could not be told apart).
    #[test]
    fn the_layout_marks_the_open_screen_in_the_menu_and_the_tab_title() {
        let messages = Messages::new(Locale::Ja);
        let render_at = |path: &str| {
            crate::tenant::with_relative_path(path, || {
                render(&ConsoleHome {
                    messages: &messages,
                    tenant: "/t",
                    error_key: None,
                    admin: Some(ConsoleAdmin {
                        label: "admin",
                        tenant_name: Some("Acme"),
                        permissions: &["idp.system.admin".to_string()],
                        csrf_token: "test-console-csrf",
                    }),
                })
            })
        };
        let console = messages.get("admin-console-title");

        // Screens not in the menu (creating a user) still mark the item they were opened from, "Accounts".
        let html = render_at("/admin/users/new");
        assert_eq!(html.matches(r#"aria-current="page""#).count(), 1, "{html}");
        assert!(
            html.contains(r#"href="/t/admin/accounts" aria-current="page""#),
            "{html}"
        );
        assert!(
            html.contains(&format!(
                "<title>{} · {console}</title>",
                messages.get("admin-nav-accounts")
            )),
            "{html}"
        );

        // Home marks the home row, and the tab title is just "Admin console".
        let html = render_at("/admin");
        assert_eq!(html.matches(r#"aria-current="page""#).count(), 1, "{html}");
        assert!(
            html.contains(r#"href="/t/admin" aria-current="page""#),
            "{html}"
        );
        assert!(
            html.contains(&format!("<title>{console}</title>")),
            "{html}"
        );

        // Screens belonging to no item (switch tenant) mark nothing.
        let html = render_at("/admin/switch-tenant");
        assert!(!html.contains("aria-current"), "{html}");
    }

    /// A logged-in admin console carries the new-version notice widget, hidden.
    ///
    /// It holds, as attributes, the rendered build label (same as the footer) and the endpoint to query the
    /// running build; `assets/console.js` compares them. ⚠ If the endpoint path is not routed, the notice silently
    /// never appears (the query just ends in 404), so also check that it is routed.
    #[test]
    fn the_signed_in_console_carries_the_hidden_update_notice() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |admin| {
            render(&ConsoleHome {
                messages: &messages,
                tenant: "/t",
                error_key: None,
                admin,
            })
        };
        let signed_in = render_with(Some(ConsoleAdmin {
            label: "admin",
            tenant_name: Some("Acme"),
            permissions: &[],
            csrf_token: "test-console-csrf",
        }));
        assert!(
            signed_in.contains(&format!(
                r#"<div class="update-notice" role="status" hidden data-update-notice data-build="{}" data-build-check="/t/admin/version/current">"#,
                footer_version()
            )),
            "{signed_in}"
        );
        assert!(
            signed_in.contains(&messages.get("update-notice-message")),
            "{signed_in}"
        );
        assert!(
            crate::router::declared_route_paths().contains("/admin/version/current"),
            "the endpoint the notice polls is not routed"
        );

        // Not placed on logged-out screens (do not expose the running build on unauthenticated surfaces; ADR-0034).
        let signed_out = render_with(None);
        assert!(!signed_out.contains("data-update-notice"), "{signed_out}");
        assert!(!signed_out.contains("data-build="), "{signed_out}");
    }

    /// The three account settings screens show the same tabs and mark only the open screen's tab.
    #[test]
    fn the_account_screens_share_one_set_of_tabs() {
        let messages = Messages::new(Locale::Ja);
        let general = render(&UserSettings {
            messages: &messages,
            tenant: "/t",
            current_lang: "ja",
            current_theme: "system",
            current_name: "",
            preferred_username: "",
            saved_key: None,
            error_key: None,
            from_admin: false,
            csrf: "csrf",
        });
        let authenticators = render(&UserAuthenticators {
            messages: &messages,
            tenant: "/t",
            csrf: "csrf",
            authenticators: &[],
            recovery_codes_remaining: 0,
            sms_available: false,
            phone_registered: false,
            awaiting_phone_code: false,
            saved_key: None,
            error_key: None,
        });
        let security = render(&UserSecurity {
            messages: &messages,
            tenant: "/t",
            csrf: "csrf",
            sessions: &[],
            connected_apps: &[],
            devices: &[],
            current_device_registered: false,
            current_device_identified: true,
            passkey_fresh: false,
            resume_device_name: None,
            devices_alerts_enabled: true,
            approver_keys: &[],
            sign_ins: &[],
            sign_ins_older: None,
            sign_ins_paged: false,
            ssh_keys_enabled: false,
            ssh_keys: &[],
            ssh_keys_passkey_fresh: false,
            status: None,
            saved_key: None,
            error_key: None,
        });
        for (html, current) in [
            (&general, "/t/settings"),
            (&authenticators, "/t/settings/authenticators"),
            (&security, "/t/settings/security"),
        ] {
            for href in [
                "/t/settings",
                "/t/settings/authenticators",
                "/t/settings/security",
            ] {
                let marked = html.contains(&format!(r#"href="{href}" aria-current="page""#));
                assert_eq!(marked, href == current, "{href} on {current}: {html}");
            }
            // Sign-out is available from any tab.
            assert!(
                html.contains(r#"<form method="post" action="/t/logout""#),
                "{current}: {html}"
            );
        }
    }

    /// Screens requiring `idp.system.admin` (error/warning logs, tenant management) are not in the menu of
    /// admins without that permission. When they were shown, clicking led to a dead end with the api returning 403.
    #[test]
    fn the_console_hides_the_screens_this_admin_cannot_open() {
        let messages = Messages::new(Locale::Ja);
        let render_as = |permissions: &[String]| {
            render(&ConsoleHome {
                messages: &messages,
                tenant: "/t",
                error_key: None,
                admin: Some(ConsoleAdmin {
                    label: "admin",
                    tenant_name: Some("Acme"),
                    permissions,
                    csrf_token: "test-console-csrf",
                }),
            })
        };

        let tenant_admin = render_as(&["idp.members:read".to_string()]);
        assert!(!tenant_admin.contains("/t/admin/logs"), "{tenant_admin}");
        assert!(!tenant_admin.contains("/t/admin/tenants"), "{tenant_admin}");
        // Screens open regardless of permission remain (check that we do not hide too much).
        assert!(tenant_admin.contains("/t/admin/accounts"), "{tenant_admin}");
        // Signing keys are root-only (task #580). In child tenants the api drops idp.keys:* from the list.
        assert!(
            !tenant_admin.contains("/t/admin/signing-keys"),
            "{tenant_admin}"
        );
        let root_admin = render_as(&["idp.keys:read".to_string()]);
        assert!(root_admin.contains("/t/admin/signing-keys"), "{root_admin}");

        let system_admin = render_as(&["idp.system.admin".to_string()]);
        assert!(system_admin.contains("/t/admin/logs"), "{system_admin}");
        assert!(system_admin.contains("/t/admin/tenants"), "{system_admin}");

        // An empty list means "the api is too old to filter", so show everything as before
        // (reading it as no permission and hiding the menu would change the screen only during the seconds old and new coexist).
        let unknown = render_as(&[]);
        assert!(unknown.contains("/t/admin/logs"), "{unknown}");
        assert!(unknown.contains("/t/admin/tenants"), "{unknown}");
    }

    /// Users redirected via SSO can only learn "where am I signing in" from the screen.
    /// Show the app name in the heading and the tenant name in the top-left label. **Fall back to defaults when
    /// lookup fails** (the form keeps showing whether the api is old or the display name is empty).
    #[test]
    fn the_login_form_names_the_application_and_the_tenant() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |client_name, tenant_name| {
            render(&LoginTemplate {
                messages: &messages,
                tenant_prefix: "/t",
                csrf: "csrf-token",
                error_key: None,
                login_hint: None,
                client_name,
                tenant_name,
                app_approval_offered: false,
            })
        };

        let html = render_with(Some("PhotoNest"), Some("Acme Corp"));
        assert!(html.contains("PhotoNest にサインイン"), "{html}");
        assert!(
            html.contains(r#"<span class="navbar-brand mb-0 h1">Acme Corp</span>"#),
            "{html}"
        );

        // Without a name, both the label and the heading revert to the previous defaults.
        let html = render_with(None, None);
        assert!(
            html.contains(r#"<span class="navbar-brand mb-0 h1">assay</span>"#),
            "{html}"
        );
        assert!(html.contains(">サインイン<"), "{html}");

        // The display name is a registered value, not an RP claim, but arbitrary strings can be entered from the admin screen.
        // Verify it goes through template escaping.
        let html = render_with(Some("<script>alert(1)</script>"), None);
        assert!(!html.contains("<script>alert(1)</script>"), "{html}");
        assert!(html.contains("&#60;script&#62;"), "{html}");
    }

    /// **Every error code that can occur on a screen has a message.** The script reads messages only
    /// from `#passkey-error` data attributes, so a code without an attribute silently falls back to the
    /// default message (the user repeats the same action without knowing what happened). Neither the response
    /// side nor the screen side alone reveals this, so pin them side by side per screen.
    #[test]
    fn every_login_screen_has_a_message_for_the_codes_its_route_returns() {
        let messages = Messages::new(Locale::Ja);
        // Two needed on every screen (browser ceremony aborted, server unreachable).
        let shared = [
            "data-msg-invalid-credential",
            "data-msg-challenge-not-found",
            "data-msg-cancelled",
            "data-msg-server",
            "data-msg-policy-denied",
        ];

        // OIDC authorization flow: consent, session expiry and rate limiting can be returned.
        let oidc = render(&LoginTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf-token",
            error_key: None,
            login_hint: None,
            client_name: None,
            tenant_name: None,
            app_approval_offered: false,
        });
        assert_attributes(
            &oidc,
            &shared,
            &["data-msg-session-expired", "data-msg-rate-limited"],
        );

        // Admin console: adds the no-admin-permission case (`forbidden`).
        let console = render(&ConsoleLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf-token",
            error_key: None,
        });
        assert_attributes(
            &console,
            &shared,
            &["data-msg-forbidden", "data-msg-rate-limited"],
        );

        // Portal: adds the email verification gate (SEC6b).
        let portal = render(&PortalLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf-token",
            error_key: None,
            external_providers: &[],
        });
        assert_attributes(
            &portal,
            &shared,
            &[
                "data-msg-email-verification-required",
                "data-msg-rate-limited",
            ],
        );
    }

    fn assert_attributes(html: &str, shared: &[&str], extra: &[&str]) {
        // The entry is rendered `hidden`, and the script removes it after confirming "WebAuthn is usable here".
        // **If the wrapper id drifts, nobody can see it**, so pin them as a pair.
        assert!(
            html.contains(r#"<div id="passkey-login" hidden>"#),
            "{html}"
        );
        for attribute in shared.iter().chain(extra) {
            assert!(html.contains(attribute), "{attribute} missing from {html}");
        }
    }

    /// Passkey screens branch off account settings, so **put "Back" at the top of the body**.
    /// The top-left label also links home, but it is not visibly a link, so do not rely on it
    /// as the way back (never create dead ends).
    #[test]
    fn the_passkey_screens_offer_a_way_back_in_the_page_body() {
        let messages = Messages::new(Locale::Ja);
        let list = render(&PasskeyListTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            credentials: &[],
            csrf_token: "test-csrf",
            saved_key: None,
            error_key: None,
        });
        let register = render(&PasskeyRegisterTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            error_key: None,
        });
        for html in [&list, &register] {
            assert!(
                html.contains(
                    r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="/t/settings""#
                ),
                "{html}"
            );
        }
        // The list goes back to account settings, registration back to the list (points one screen up).
        assert!(html_has_link(&list, "/t/settings"), "{list}");
        assert!(html_has_link(&register, "/t/account/passkey"), "{register}");
    }

    /// "Last used" uses the same format as the registration time (conversion to the user's time zone is `local-time`).
    /// Not shown for passkeys never used.
    #[test]
    fn the_passkey_list_shows_last_use_like_the_registration_time() {
        let messages = Messages::new(Locale::Ja);
        let credential = |last_used_at: Option<&str>| PasskeyCredentialInfo {
            id: "c1".into(),
            name: "ノート PC".into(),
            created_at: "2026-08-20T10:00:00Z".into(),
            last_used_at: last_used_at.map(Into::into),
            suspended: false,
        };
        let render_list = |credentials: &[PasskeyCredentialInfo]| {
            render(&PasskeyListTemplate {
                messages: &messages,
                tenant_prefix: "/t",
                credentials,
                csrf_token: "test-csrf",
                saved_key: None,
                error_key: None,
            })
        };

        let used = render_list(&[credential(Some("2026-10-16T08:00:00Z"))]);
        assert!(
            used.contains(
                r#"<time class="local-time" datetime="2026-10-16T08:00:00Z">2026-10-16 08:00 UTC</time>"#
            ),
            "{used}"
        );
        assert!(!used.contains(": 2026-10-16T08:00:00Z"), "{used}");

        let unused = render_list(&[credential(None)]);
        assert!(
            !unused.contains(&messages.get("passkey-last-used")),
            "{unused}"
        );
    }

    /// A failed registration is not a dead end (besides retrying, leave a way out to the list).
    #[test]
    fn the_passkey_register_screen_can_be_left_after_a_failure() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&PasskeyRegisterTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            error_key: None,
        });
        let error_step = html
            .split_once(r#"<div id="step-error""#)
            .expect("step-error block")
            .1;
        assert!(html_has_link(error_step, "/t/account/passkey"), "{html}");
    }

    fn html_has_link(html: &str, href: &str) -> bool {
        html.contains(&format!(r#"href="{href}""#))
    }

    /// Tables are rearranged into cards on narrow screens (ADR-0048). **All tables** are covered; leaving one out
    /// collapses that screen's columns -- in fact, two tables on the security screen were shipped without
    /// `.table-cards`, so on smartphones app names split vertically one character per line and times were
    /// cut off at the right edge. Inspect the templates directly so adding a new table cannot repeat this.
    #[test]
    fn every_table_collapses_into_cards_on_narrow_screens() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let mut offenders = Vec::new();
        let mut checked = 0usize;
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read templates dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("html") {
                    continue;
                }
                let html = std::fs::read_to_string(&path).expect("read template");
                for tag in html.match_indices("<table") {
                    checked += 1;
                    let rest = &html[tag.0..];
                    let end = rest.find('>').unwrap_or(rest.len());
                    if !rest[..end].contains("table-cards") {
                        offenders.push(format!("{}: {}", path.display(), &rest[..end]));
                    }
                }
            }
        }
        assert!(checked > 0, "no tables found — did the templates move?");
        assert!(
            offenders.is_empty(),
            "these tables would squeeze on a phone (add .table-cards and data-label to each cell): {offenders:#?}"
        );
    }

    /// The "Devices" section (task #872): registered devices with revoke, and a registration field for unregistered browsers.
    #[test]
    fn the_security_page_lists_devices_and_offers_registration() {
        let messages = Messages::new(Locale::Ja);
        let devices = vec![SecurityDeviceView {
            id: "0197aaaa-0000-7000-8000-000000000001".to_string(),
            name: "kyon-pc".to_string(),
            current: false,
            user_agent: "Mozilla/5.0".to_string(),
            last_used_at: "2026-11-04T09:00:00Z".to_string(),
            last_country: "JP".to_string(),
            expires_at: "2027-05-03T09:00:00Z".to_string(),
        }];
        let render_with = |registered: bool, identified: bool| {
            render(&UserSecurity {
                messages: &messages,
                tenant: "/t",
                csrf: "csrf",
                sessions: &[],
                connected_apps: &[],
                devices: &devices,
                current_device_registered: registered,
                current_device_identified: identified,
                passkey_fresh: false,
                resume_device_name: None,
                devices_alerts_enabled: true,
                approver_keys: &[],
                sign_ins: &[],
                sign_ins_older: None,
                sign_ins_paged: false,
                ssh_keys_enabled: false,
                ssh_keys: &[],
                ssh_keys_passkey_fresh: false,
                status: None,
                saved_key: None,
                error_key: None,
            })
        };
        let html = render_with(false, true);
        assert!(html.contains("kyon-pc"), "{html}");
        assert!(html.contains(r#"action="/t/settings/security/revoke-device""#));
        assert!(html.contains(r#"action="/t/settings/security/register-device""#));
        assert!(html.contains(r#"name="device_id" value="0197aaaa-0000-7000-8000-000000000001""#));

        let html = render_with(true, true);
        assert!(!html.contains(r#"action="/t/settings/security/register-device""#));

        let html = render_with(false, false);
        assert!(!html.contains(r#"action="/t/settings/security/register-device""#));
    }

    /// After returning from passkey verification, registration is auto-submitted with the typed name (task #916; one press).
    /// Not submitted when the verification is not fresh yet or the name was not carried over.
    #[test]
    fn returning_from_the_passkey_check_finishes_the_device_registration() {
        let messages = Messages::new(Locale::Ja);
        let render_with = |passkey_fresh: bool, resume: Option<&str>| {
            render(&UserSecurity {
                messages: &messages,
                tenant: "/t",
                csrf: "csrf",
                sessions: &[],
                connected_apps: &[],
                devices: &[],
                current_device_registered: false,
                current_device_identified: true,
                passkey_fresh,
                resume_device_name: resume,
                devices_alerts_enabled: true,
                approver_keys: &[],
                sign_ins: &[],
                sign_ins_older: None,
                sign_ins_paged: false,
                ssh_keys_enabled: false,
                ssh_keys: &[],
                ssh_keys_passkey_fresh: false,
                status: None,
                saved_key: None,
                error_key: None,
            })
        };
        let html = render_with(true, Some("自宅の Windows"));
        assert!(html.contains("data-auto-submit"), "{html}");
        assert!(html.contains(r#"value="自宅の Windows""#), "{html}");
        assert!(html.contains("/assets/auto-submit.js"));
        for (fresh, resume) in [(false, Some("自宅の Windows")), (true, None)] {
            let html = render_with(fresh, resume);
            assert!(
                !html.contains("data-auto-submit"),
                "fresh={fresh} resume={resume:?}"
            );
        }
    }

    /// The "Sign-in history" section (task #879): success and failure are distinguishable, a refresh's "sender" is
    /// written separately from the sign-in source, and the disclaimer about apps extending outside assay appears.
    #[test]
    fn the_security_page_lists_sign_ins_and_refresh_usage() {
        let messages = Messages::new(Locale::Ja);
        let sign_ins = vec![
            SignInView {
                occurred_at: "2026-11-04T09:00:00Z".to_string(),
                outcome_key: "user-security-signins-outcome-succeeded",
                succeeded: true,
                failure_key: None,
                ip_address: "203.0.113.10".to_string(),
                country: "JP".to_string(),
                browser_summary: "Windows・Chrome".to_string(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0)".to_string(),
                method_keys: vec![
                    "user-security-signins-method-password",
                    "user-security-signins-method-totp",
                ],
                attempted_app: String::new(),
                current: true,
                device_registered: Some(false),
                apps: vec![SignInAppView {
                    app_name: "photonest".to_string(),
                    last_issued_at: "2026-11-04T09:00:05Z".to_string(),
                    refresh: Some(SignInRefreshView {
                        use_count: "12".to_string(),
                        last_used_at: "2026-11-04T10:00:00Z".to_string(),
                        last_ip_address: "198.51.100.20".to_string(),
                        last_browser_summary: String::new(),
                        last_user_agent: "python-httpx/0.28".to_string(),
                        reuse_detected_at: "2026-11-04T10:05:00Z".to_string(),
                        state_key: "user-security-signins-refresh-state-revoked",
                        active: false,
                        revoked_at: "2026-11-04T10:05:00Z".to_string(),
                    }),
                }],
            },
            SignInView {
                occurred_at: "2026-11-04T08:59:00Z".to_string(),
                outcome_key: "user-security-signins-outcome-failed",
                succeeded: false,
                failure_key: Some("user-security-signins-failure-wrong-password"),
                ip_address: "192.0.2.99".to_string(),
                country: String::new(),
                browser_summary: String::new(),
                user_agent: String::new(),
                method_keys: Vec::new(),
                attempted_app: "photonest".to_string(),
                current: false,
                device_registered: None,
                apps: Vec::new(),
            },
        ];
        let html = render(&UserSecurity {
            messages: &messages,
            tenant: "/t",
            csrf: "csrf",
            sessions: &[],
            connected_apps: &[],
            devices: &[],
            current_device_registered: false,
            current_device_identified: true,
            passkey_fresh: false,
            resume_device_name: None,
            devices_alerts_enabled: true,
            approver_keys: &[],
            sign_ins: &sign_ins,
            sign_ins_older: Some(41),
            sign_ins_paged: false,
            ssh_keys_enabled: false,
            ssh_keys: &[],
            ssh_keys_passkey_fresh: false,
            status: None,
            saved_key: None,
            error_key: None,
        });
        assert!(html.contains(r#"id="sign-ins""#), "{html}");
        // Telling success from failure (AC2).
        assert!(html.contains(r#"data-outcome="succeeded""#));
        assert!(html.contains(r#"data-outcome="refused""#));
        assert!(html.contains("パスワード違い"));
        // Time, IP and country, browser and OS, sign-in method, target app (AC1).
        assert!(html.contains("203.0.113.10"));
        assert!(html.contains("JP"));
        assert!(html.contains("Windows・Chrome"));
        assert!(
            html.contains("パスワード・確認コード（認証アプリ）"),
            "{html}"
        );
        assert!(html.contains("photonest"));
        // When the country is unknown, say "unknown" rather than guessing (AC7).
        assert!(html.contains("（国は不明）"));
        // Refresh usage (AC3), written separately from the sender (AC4).
        assert!(html.contains("延長した回数: 12"), "{html}");
        assert!(html.contains("取り消し済み"));
        assert!(html.contains("使い終えたトークンがもう一度使われました"));
        assert!(html.contains("送ってきた相手: 198.51.100.20"), "{html}");
        // Disclaimer for apps that use assay only for the first sign-in (AC5).
        assert!(html.contains("ここには出ません"));
        // To older history.
        assert!(html.contains(r#"href="/t/settings/security?history_before=41#sign-ins""#));
    }

    #[test]
    fn browser_summaries_name_the_os_and_the_browser() {
        let chrome_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
        assert_eq!(browser_summary(chrome_win), "Windows・Chrome");
        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0";
        assert_eq!(browser_summary(edge), "Windows・Edge");
        let android = "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36";
        assert_eq!(browser_summary(android), "Android・Chrome");
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(browser_summary(iphone), "iOS・Safari");
        let firefox_mac =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:131.0) Gecko/20100101 Firefox/131.0";
        assert_eq!(browser_summary(firefox_mac), "macOS・Firefox");
        assert_eq!(browser_summary("python-httpx/0.28"), "");
        assert_eq!(browser_summary(""), "");
    }

    /// The "SSH keys" section (task #885): hidden if the organization does not use it. If it does, show the registration
    /// field, fingerprints and revoke, and a path to verification if passkey verification is still pending.
    #[test]
    fn the_security_page_lists_ssh_keys_only_when_enabled() {
        let messages = Messages::new(Locale::Ja);
        let keys = vec![SecuritySshKeyView {
            id: "0197aaaa-0000-7000-8000-000000000009".to_string(),
            name: "kyon-pc".to_string(),
            key_type: "sk-ssh-ed25519@openssh.com".to_string(),
            fingerprint: "SHA256:1rYiSPZV2H9QsZrfrX/5nhreVmcpuSKQQYA/CKjnPfU".to_string(),
            created_at: "2026-11-04T09:00:00Z".to_string(),
        }];
        let render_with = |enabled: bool, fresh: bool| {
            render(&UserSecurity {
                messages: &messages,
                tenant: "/t",
                csrf: "csrf",
                sessions: &[],
                connected_apps: &[],
                devices: &[],
                current_device_registered: false,
                current_device_identified: true,
                passkey_fresh: false,
                resume_device_name: None,
                devices_alerts_enabled: true,
                approver_keys: &[],
                ssh_keys_enabled: enabled,
                ssh_keys: &keys,
                ssh_keys_passkey_fresh: fresh,
                status: None,
                sign_ins: &[],
                sign_ins_older: None,
                sign_ins_paged: false,
                saved_key: None,
                error_key: None,
            })
        };
        let html = render_with(false, false);
        assert!(!html.contains(r#"id="ssh-keys""#), "{html}");
        assert!(!html.contains("register-ssh-key"));

        let html = render_with(true, false);
        assert!(html.contains(r#"id="ssh-keys""#));
        assert!(html.contains(r#"action="/t/settings/security/register-ssh-key""#));
        assert!(html.contains(r#"action="/t/settings/security/revoke-ssh-key""#));
        assert!(html.contains("SHA256:1rYiSPZV2H9QsZrfrX/5nhreVmcpuSKQQYA/CKjnPfU"));
        assert!(html.contains(r#"name="key_id" value="0197aaaa-0000-7000-8000-000000000009""#));
        assert!(html.contains("operation=manage_ssh_keys"));

        let html = render_with(true, true);
        assert!(!html.contains("operation=manage_ssh_keys"));
    }

    /// Times are output as a machine-readable value (`datetime`) and a human-readable one (element content) (ADR-0048).
    /// JavaScript replaces the content with the viewer's time zone, but it is output in a readable form even
    /// without replacement -- an RFC 3339 string with microseconds is not readable as a date as is.
    #[test]
    fn timestamps_carry_a_machine_value_and_a_readable_one() {
        let messages = Messages::new(Locale::Ja);
        let sessions = [SecuritySessionView {
            id: "s1".to_string(),
            current: false,
            multi_factor: false,
            auth_time: "2026-09-09T11:20:04.512345Z".to_string(),
            user_agent: "UA".to_string(),
            ip_address: "203.0.113.1".to_string(),
            absolute_expires_at: "2026-09-09T19:20:04.512345Z".to_string(),
            status: None,
        }];
        let html = render(&UserSecurity {
            messages: &messages,
            tenant: "/t",
            csrf: "csrf",
            sessions: &sessions,
            connected_apps: &[],
            devices: &[],
            current_device_registered: false,
            current_device_identified: true,
            passkey_fresh: false,
            resume_device_name: None,
            devices_alerts_enabled: true,
            approver_keys: &[],
            sign_ins: &[],
            sign_ins_older: None,
            sign_ins_paged: false,
            ssh_keys_enabled: false,
            ssh_keys: &[],
            ssh_keys_passkey_fresh: false,
            status: None,
            saved_key: None,
            error_key: None,
        });
        assert!(
            html.contains(r#"<time class="local-time" datetime="2026-09-09T11:20:04.512345Z">2026-09-09 11:20 UTC</time>"#),
            "{html}"
        );
        // Raw RFC 3339 does not appear in the body (if it did, the screen before replacement would be unreadable).
        assert!(!html.contains(">2026-09-09T11:20:04.512345Z<"), "{html}");
    }

    /// "Status" (task #896): bound + registered vs. neither changes how device, binding, lifetime basis,
    /// belongings, token kind and organization rules are worded. When unreadable, only guidance is shown.
    #[test]
    fn the_status_section_tells_a_bound_registered_session_from_a_plain_one() {
        let messages = Messages::new(Locale::Ja);
        let session = |bound: bool| SessionStatusView {
            id: "s1".to_string(),
            current: true,
            auth_time: "2026-11-05T01:00:00Z".to_string(),
            expires_at: "2026-12-05T01:00:00Z".to_string(),
            method_keys: vec!["user-security-signins-method-passkey"],
            multi_factor: bound,
            browser: "Windows・Chrome".to_string(),
            user_agent: "UA".to_string(),
            ip_address: "203.0.113.1".to_string(),
            country: String::new(),
            device_identified: true,
            device_name: if bound {
                "家の PC".to_string()
            } else {
                String::new()
            },
            device_registered_at: "2026-11-01T00:00:00Z".to_string(),
            device_last_used_at: "2026-11-05T01:00:00Z".to_string(),
            binding_key: if bound {
                "user-security-status-binding-device-key"
            } else {
                "user-security-status-binding-unbound"
            },
            basis_key: if bound {
                "user-security-status-basis-bound-registered"
            } else {
                "user-security-status-basis-unbound"
            },
            basis_short_key: if bound {
                "user-security-status-basis-bound-registered-short"
            } else {
                "user-security-status-basis-unbound-short"
            },
            long_lifetime: bound,
            key_algorithm: if bound {
                "ES256".to_string()
            } else {
                String::new()
            },
            key_thumbprint_head: "abcdefghijkl".to_string(),
            key_bound_at: "2026-11-05T01:00:01Z".to_string(),
            key_refreshed_at: String::new(),
            approver_device_name: String::new(),
            approver_level_key: "",
            passkey_fresh_until: String::new(),
        };
        let view = |bound: bool| SecurityStatusView {
            current: Some(session(bound)),
            browser: "Windows・Chrome".to_string(),
            user_agent: "UA".to_string(),
            ip_address: "203.0.113.1".to_string(),
            country: String::new(),
            bound_cookie_expires_at: String::new(),
            belongings: if bound {
                vec![BelongingView {
                    kind_key: "user-security-status-kind-device",
                    use_key: "user-security-status-use-device",
                    strength_key: "user-security-status-strength-marker",
                    name: "家の PC".to_string(),
                    detail: "Windows・Chrome".to_string(),
                    detail_key: "",
                    registered_at: "2026-11-01T00:00:00Z".to_string(),
                    last_used_at: "2026-11-05T01:00:00Z".to_string(),
                    last_use_invisible: false,
                    expires_at: "2027-05-04T01:00:00Z".to_string(),
                }]
            } else {
                Vec::new()
            },
            apps: vec![AppTokensView {
                app_name: "photonest".to_string(),
                scopes: "openid".to_string(),
                active_refresh_tokens: u32::from(bound),
                dpop_bound_refresh_tokens: u32::from(bound),
                token_key: if bound {
                    "user-security-status-token-dpop"
                } else {
                    "user-security-status-token-none"
                },
                last_issued_at: String::new(),
                refresh_use_count: 0,
                refresh_last_used_at: String::new(),
                refresh_last_sender: String::new(),
                refresh_reuse_detected_at: String::new(),
            }],
            policy: PolicyView {
                unregistered_device_alerts: false,
                ssh_keys_enabled: true,
                bound_ttl: duration_label(&messages, 2_592_000).unwrap_or_default(),
                absolute_ttl: duration_label(&messages, 604_800).unwrap_or_default(),
                idle_ttl: duration_label(&messages, 604_800).unwrap_or_default(),
                device_expiry_days: 180,
            },
            warnings: if bound {
                Vec::new()
            } else {
                vec![WarningView {
                    key: "user-security-status-warning-unregistered",
                    count: 2,
                    last_at: "2026-11-05T01:00:00Z".to_string(),
                }]
            },
            failure_days: Vec::new(),
            warning_window_days: 30,
        };
        let render_with = |status: Option<&SecurityStatusView>| {
            render(&UserSecurity {
                messages: &messages,
                tenant: "/t",
                csrf: "csrf",
                sessions: &[],
                connected_apps: &[],
                devices: &[],
                current_device_registered: false,
                current_device_identified: true,
                passkey_fresh: false,
                resume_device_name: None,
                devices_alerts_enabled: true,
                approver_keys: &[],
                sign_ins: &[],
                sign_ins_older: None,
                sign_ins_paged: false,
                ssh_keys_enabled: false,
                ssh_keys: &[],
                ssh_keys_passkey_fresh: false,
                status,
                saved_key: None,
                error_key: None,
            })
        };

        let bound = view(true);
        let html = render_with(Some(&bound));
        assert!(html.contains(r#"id="status""#), "{html}");
        assert!(
            html.contains("端末の鍵に結び付き、かつ登録した端末なので 30 日です。"),
            "{html}"
        );
        assert!(html.contains("結び付いています"));
        assert!(html.contains("ES256"));
        assert!(html.contains("家の PC"));
        assert!(html.contains("登録した端末"));
        assert!(html.contains("端末の鍵に結び付き（DPoP）"));
        assert!(
            html.contains("国なし"),
            "home network has no country: {html}"
        );
        assert!(!html.contains(r#"id="status-warnings""#));

        let plain = view(false);
        let html = render_with(Some(&plain));
        assert!(
            html.contains("端末の鍵に結び付いていないので 7 日です。"),
            "{html}"
        );
        assert!(html.contains("結び付いていません"));
        assert!(html.contains("登録していない端末"));
        assert!(html.contains("リフレッシュトークンは持っていません"));
        assert!(html.contains(r#"id="status-warnings""#));
        assert!(html.contains("まだ登録した持ち物はありません。"));

        let html = render_with(None);
        assert!(html.contains(r#"id="status-unavailable""#));
        assert!(!html.contains(r#"id="status""#));
    }

    /// Unparseable values are output as is rather than dropped (leave a clue rather than missing display).
    #[test]
    fn an_unparsable_timestamp_is_left_alone() {
        assert_eq!(
            utc_short("2026-09-09T11:20:04.512345Z"),
            "2026-09-09 11:20 UTC"
        );
        assert_eq!(utc_short("never"), "never");
        assert_eq!(utc_short(""), "");
        // Values with an offset are also converted to UTC (the api returns Z, but don't tie it to one source).
        assert_eq!(
            utc_short("2026-09-09T20:20:04+09:00"),
            "2026-09-09 11:20 UTC"
        );
    }

    /// Asset references always carry `?v={asset_version}` so the URL changes per deploy
    /// (prevents intermediate caches (CDN, browser) from keeping serving old CSS/JS).
    #[test]
    fn rendered_pages_reference_versioned_asset_urls() {
        let messages = Messages::new(Locale::Ja);
        let console = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            error_key: None,
            admin: None,
        });
        let auth = render(&ConsoleLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf",
            error_key: None,
        });
        let v = asset_version();
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/app.css?v={v}")));
            assert!(html.contains(&format!("/assets/vendor/bootstrap.min.css?v={v}")));
            assert!(html.contains(&format!("/assets/vendor/bootstrap.bundle.min.js?v={v}")));
            assert!(html.contains(&format!("/assets/react/app.js?v={v}")));
            assert!(!html.contains("/assets/app.css\""));
        }
        // The shared confirmation-dialog script is loaded by the admin console layout (`console/layout.html`).
        // The login screen uses `page.html` and has no forms with `data-confirm`, so it is out of scope.
        assert!(console.contains(&format!("/assets/console.js?v={v}")));
        // The submitting marker is needed by forms on every screen, so both layouts load it.
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/submit-feedback.js?v={v}")));
        }
        // Loaded after the confirmation dialog so cancelled submissions are not marked (they run in registration order).
        assert!(
            console.find("/assets/console.js") < console.find("/assets/submit-feedback.js"),
            "submit-feedback.js must load after console.js: {console}"
        );
        // The marking DOM operation is shared, so load it before the scripts that call it.
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/button-pending.js?v={v}")));
            assert!(
                html.find("/assets/button-pending.js") < html.find("/assets/submit-feedback.js"),
                "button-pending.js must load first: {html}"
            );
        }
        // The color scheme must be settled before the first paint, so load it before the stylesheets.
        for html in [&console, &auth] {
            assert!(html.contains(&format!("/assets/theme.js?v={v}")));
            assert!(
                html.find("/assets/theme.js") < html.find("/assets/vendor/bootstrap.min.css"),
                "theme.js must load before the stylesheet: {html}"
            );
            // With `defer`, a white screen is painted and then repainted black.
            let tag_start = html
                .find("/assets/theme.js")
                .expect("theme.js is referenced");
            let tag_end = tag_start + html[tag_start..].find('>').expect("tag end");
            assert!(
                !html[tag_start..tag_end].contains("defer"),
                "theme.js must not be deferred: {html}"
            );
        }
    }

    /// The three login screens render the hooks the shared script `passkey-login.js` needs
    /// (button, error area, completion endpoint).
    ///
    /// One script is shared by the three screens and receives only the completion target via `data-complete-path`.
    /// Renaming an attribute on only one side yields a screen whose button silently does nothing, so pin it on the rendering side.
    #[test]
    fn every_login_screen_renders_the_passkey_hooks() {
        let messages = Messages::new(Locale::Ja);
        let admin = render(&ConsoleLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf",
            error_key: None,
        });
        let portal = render(&PortalLogin {
            messages: &messages,
            tenant_prefix: "/t",
            csrf: "csrf",
            error_key: None,
            external_providers: &[],
        });
        let authorize = render(&LoginTemplate {
            messages: &messages,
            tenant_prefix: "/t",
            tenant_name: None,
            client_name: None,
            csrf: "csrf",
            error_key: None,
            login_hint: None,
            app_approval_offered: false,
        });
        // Direct login also points its start at a dedicated route (so it never picks up the Cookie of an abandoned
        // authorization flow; ADR-0040 decision 4). The authorization flow uses the script defaults, so it has no data attributes.
        for (screen, html, paths) in [
            (
                "admin",
                &admin,
                Some((
                    "/passkey/login/direct/begin",
                    "/passkey/login/admin/complete",
                )),
            ),
            (
                "portal",
                &portal,
                Some((
                    "/passkey/login/direct/begin",
                    "/passkey/login/portal/complete",
                )),
            ),
            ("authorize", &authorize, None),
        ] {
            assert!(
                html.contains(r#"id="btn-passkey-login""#),
                "{screen}: {html}"
            );
            assert!(html.contains(r#"id="passkey-error""#), "{screen}: {html}");
            assert!(
                html.contains(r#"id="passkey-error-msg""#),
                "{screen}: {html}"
            );
            assert!(
                html.contains("/assets/passkey-login.js"),
                "{screen}: {html}"
            );
            match paths {
                Some((begin_path, complete_path)) => {
                    assert!(
                        html.contains(&format!(r#"data-begin-path="{begin_path}""#)),
                        "{screen}: {html}"
                    );
                    assert!(
                        html.contains(&format!(r#"data-complete-path="{complete_path}""#)),
                        "{screen}: {html}"
                    );
                }
                None => {
                    assert!(!html.contains("data-begin-path"), "{screen}: {html}");
                    assert!(!html.contains("data-complete-path"), "{screen}: {html}");
                }
            }
        }
    }

    /// MT20: the admin console's shared layout has a language switcher (also on logged-out screens;
    /// if the language cannot be changed before login, users are forced to sign in in a language they cannot read).
    /// It is a GET form without `action`, so on every screen inheriting the layout it submits to the current path.
    #[test]
    fn console_layout_offers_a_language_switcher() {
        let messages = Messages::new(Locale::Ja);
        for admin in [
            Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
            None,
        ] {
            let html = render(&ConsoleHome {
                messages: &messages,
                tenant: "/t",
                error_key: None,
                admin,
            });
            assert!(
                html.contains(&messages.get("admin-language-switch")),
                "admin={admin:?}: {html}"
            );
            assert!(html.contains(r#"name="lang" value="ja""#), "{html}");
            assert!(html.contains(r#"name="lang" value="en""#), "{html}");
            // The target is the current path (no `action`).
            assert!(!html.contains(r#"<form method="get" action"#), "{html}");
        }
    }

    /// Logout in the header POSTs with a CSRF token (task #143). The token arrives via `ConsoleAdmin`,
    /// so every screen inheriting the layout gets the same field.
    #[test]
    fn console_logout_posts_the_token() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            error_key: None,
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
        });
        let form = html
            .split(r#"<form method="post" action="/t/admin/logout">"#)
            .nth(1)
            .and_then(|rest| rest.split("</form>").next())
            .unwrap_or_else(|| panic!("no logout form: {html}"));
        assert!(
            form.contains(r#"<input type="hidden" name="csrf_token" value="test-console-csrf">"#),
            "{form}"
        );
    }

    /// The tenant being operated on is visible on every admin console screen (shown in the shared layout header).
    /// It exists to prevent operating on the wrong tenant, so it lives in the layout, not just on home.
    #[test]
    fn console_layout_always_shows_the_current_tenant_for_signed_in_admins() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            error_key: None,
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: Some("Acme Inc."),
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
        });
        assert!(html.contains("Acme Inc."), "{html}");
        assert!(
            html.contains(&messages.get("admin-current-tenant")),
            "{html}"
        );
        // The tenant label in the header doubles as the link to the switch screen.
        assert!(html.contains(r#"href="/t/admin/switch-tenant""#), "{html}");

        // When the name cannot be fetched (old api), only the name is omitted; the screen does not break.
        let html = render(&ConsoleHome {
            messages: &messages,
            tenant: "/t",
            error_key: None,
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
        });
        assert!(html.contains("admin-1"), "{html}");
        assert!(!html.contains("navbar-tenant-label"), "{html}");
    }

    /// In the external IdP list, long URLs to register with the counterpart wrap to show in full (`code-wrap`),
    /// with a copy button. ⚠ Without wrapping the table overflows to the right even at 1280px.
    #[test]
    fn external_idp_list_wraps_long_urls_and_offers_a_copy_button() {
        let messages = Messages::new(Locale::Ja);
        let acs = "https://assay.example.com/019f0000-0000-7000-8000-00000000a001/federation/saml/acs/corp";
        let providers: Vec<crate::admin_dto::ExternalIdpView> = serde_json::from_value(serde_json::json!([{
            "id": "p1", "provider_code": "corp", "display_name": "Corp", "issuer": "https://idp.example.org",
            "protocol": "saml", "has_client_secret": false, "enabled": true, "allow_auto_link": false,
            "saml_sp_entity_id": "https://assay.example.com/019f0000-0000-7000-8000-00000000a001/saml/sp",
            "saml_acs_url": acs, "redirect_uri": "https://assay.example.com/unused",
            "created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z"
        }]))
        .expect("view");
        let html = render(&ExternalIdpsConsole {
            messages: &messages,
            tenant: "/t",
            admin: None,
            csrf: "csrf",
            providers: &providers,
            saved: false,
            deleted: false,
            error_key: None,
        });
        assert!(
            html.contains(&format!(r#"<code class="code-wrap">{acs}</code>"#)),
            "{html}"
        );
        assert!(
            html.contains(&format!(r#"data-copy-text="{acs}""#)),
            "{html}"
        );
        assert!(html.contains("data-copy-status"), "{html}");
        assert!(!html.contains(r#"<code class="text-break">"#), "{html}");
    }

    /// The IdP metadata download link is a web route, not a direct link to the api.
    #[test]
    fn saml_console_links_idp_metadata_on_the_web_origin() {
        let messages = Messages::new(Locale::Ja);
        let html = render(&SamlServiceProvidersConsole {
            messages: &messages,
            tenant: "/t",
            idp_metadata_url: "/t/admin/saml-clients/idp-metadata",
            admin: Some(ConsoleAdmin {
                label: "admin-1",
                tenant_name: None,
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
            csrf: "csrf",
            saved: false,
            updated: false,
            deleted: false,
            imported: false,
            error_key: None,
            providers: &[],
            values: &SamlServiceProviderFormValues::default(),
        });
        assert!(
            html.contains(r#"href="/t/admin/saml-clients/idp-metadata""#),
            "{html}"
        );
        assert!(!html.contains("api.idp.example.com"), "{html}");
    }

    /// `href` / `action` paths written directly in templates must always be **web's own routes**.
    ///
    /// Do not write api-only paths relative to the web origin. If a browser-facing link is needed, add an explicit
    /// use-case route to web (values that are entirely template expressions are excluded from static checking).
    #[test]
    fn template_link_targets_are_routes_this_service_serves() {
        let routes = crate::router::declared_route_paths();
        let mut checked = 0;
        for (template, raw) in template_link_targets() {
            let Some(path) = normalize_template_path(&raw) else {
                continue;
            };
            checked += 1;
            assert!(
                routes.contains(&path),
                "{template} links `{raw}` but web serves no route `{path}`; \
                 for an api endpoint, pass an issuer-based absolute URL from the handler"
            );
        }
        assert!(checked > 0, "expected link targets to check");
    }

    /// Enumerates templates' `href="…"` / `action="…"` / `src="…"` as (file name, value).
    ///
    /// `src` is checked too because forgetting the serving route for `<script src="/assets/…">` gives 404,
    /// and behaviour silently disappears while the screen still renders (actually happened with `client-form.js`).
    fn template_link_targets() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read templates dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("html") {
                    continue;
                }
                let name = path.display().to_string();
                let source = std::fs::read_to_string(&path).expect("read template");
                for attr in ["href=\"", "action=\"", "src=\""] {
                    for after in source.split(attr).skip(1) {
                        if let Some(len) = after.find('"') {
                            out.push((name.clone(), after[..len].to_string()));
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/templates")),
            &mut out,
        );
        out
    }

    /// Normalizes a template value into a form comparable with `router.rs` paths. `None` if undecidable.
    fn normalize_template_path(raw: &str) -> Option<String> {
        let raw = raw.trim();
        // External URLs, anchors and empty values are not routes.
        if raw.is_empty()
            || raw.starts_with("http://")
            || raw.starts_with("https://")
            || raw.starts_with('#')
            || raw.starts_with("mailto:")
        {
            return None;
        }
        // The whole value is a template expression (= a URL built by the handler; may be absolute).
        if raw.starts_with("{{") && raw.ends_with("}}") && raw.matches("{{").count() == 1 {
            return None;
        }
        let path = crate::router::collapse_params(raw);
        // Query and fragment do not matter for identifying the route.
        let path = path.split(['?', '#']).next().unwrap_or_default();
        // Drop the leading tenant prefix (`{{ tenant }}…` / `/{{ t.id }}…`).
        let path = path.strip_prefix("{}").unwrap_or(path);
        let path = path.strip_prefix("/{}").unwrap_or(path);
        path.starts_with('/').then(|| path.to_string())
    }

    /// Templates with `data-confirm` must inherit a layout that loads the shared script.
    /// Otherwise the confirmation dialog silently never appears and destructive operations are submitted.
    #[test]
    fn templates_using_data_confirm_load_the_confirm_handler() {
        // `data-confirm` is an attribute read by the handler in `assets/console.js`. Writing the attribute but
        // forgetting to load the script lets destructive operations through with no dialog (nothing changes on
        // screen, so it goes unnoticed). Via the shared layout or a direct load is fine, but one is required.
        let roots = [
            concat!(env!("CARGO_MANIFEST_DIR"), "/templates"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/templates/console"),
        ];
        let mut checked = 0;
        for dir in roots {
            for entry in std::fs::read_dir(dir).expect("read templates dir") {
                let path = entry.expect("dir entry").path();
                if path.extension().and_then(|e| e.to_str()) != Some("html") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read template");
                if !source.contains("data-confirm=") {
                    continue;
                }
                checked += 1;
                let extends_layout =
                    |src: &str| src.contains(r#"{% extends "console/layout.html" %}"#);
                // Partials (fragments inserted via `{% include %}`) are fine if every includer inherits the layout.
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let include = format!(r#"{{% include "console/{name}" %}}"#);
                let includers: Vec<String> = std::fs::read_dir(roots[1])
                    .expect("read templates dir")
                    .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
                    .filter(|src| src.contains(&include))
                    .collect();
                let loads_handler = extends_layout(&source)
                    || source.contains("/assets/console.js")
                    || (!includers.is_empty() && includers.iter().all(|src| extends_layout(src)));
                assert!(
                    loads_handler,
                    "{} uses data-confirm but never loads assets/console.js",
                    path.display()
                );
            }
        }
        assert!(checked > 0, "expected templates using data-confirm");
    }
}

/// Renders a template and returns the HTML string. Render errors (effectively only fmt errors) are not swallowed:
/// they are logged and fall back to a minimal error page (fail-soft).
pub fn render<T: Template>(template: &T) -> String {
    template.render().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render template");
        "<!DOCTYPE html><html><body><p>Internal Server Error</p></body></html>".to_string()
    })
}

/// TOTP setup screen (`GET /account/mfa/totp/setup`).
/// Shows both the QR code SVG and the raw secret (base32) (for users who cannot use QR).
#[derive(Template)]
#[template(path = "mfa_totp_setup.html")]
pub struct TotpSetupTemplate<'a> {
    pub messages: &'a Messages,
    /// Tenant prefix (`/{tenant_id}`). Used to build the back link (account settings).
    pub tenant_prefix: &'a str,
    /// QR code SVG string (embedded inline).
    pub qr_svg: &'a str,
    /// Base32-encoded raw secret (shown directly for users who cannot use QR).
    pub secret_base32: &'a str,
    pub error_key: Option<&'a str>,
    /// CSRF token of the confirmation code form (`console_csrf_token`; task #118).
    pub csrf: &'a str,
}

/// Screen for a failed TOTP setup started from account settings (already set up, session expired,
/// or the QR could not be regenerated after a wrong code; task #119).
///
/// A plain [`MessagePage`] only reported the failure and had no exit, a dead end. Like the setup screen,
/// provide a link back to account settings. The template decides the target (sign-in or settings).
#[derive(Template)]
#[template(path = "mfa_totp_account_error.html")]
pub struct TotpAccountErrorTemplate<'a> {
    pub messages: &'a Messages,
    /// Tenant prefix (`/{tenant_id}`). Used to build the back link.
    pub tenant_prefix: &'a str,
    /// Translation key of the body (`mfa-error-*`).
    pub message_key: &'a str,
    /// Must sign in again (no session or expired). Account settings cannot be opened then,
    /// so the body link points to sign-in.
    pub sign_in_required: bool,
}

/// Login-flow TOTP input page (`GET /mfa/totp`).
#[derive(Template)]
#[template(path = "mfa_totp_verify.html")]
pub struct TotpVerifyTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// Whether to show the "send a code by email" link (AP9).
    pub email_otp_available: bool,
    /// That link's target (varies per tenant, so the caller builds it).
    pub email_otp_action: &'a str,
    /// Target of the SMS OTP send form (AP13). The link is always shown; not configured/registered is explained in the send result.
    pub sms_otp_action: &'a str,
}
/// Front-channel notification page for RP-initiated logout (`GET /{tenant_id}/logout`; moved from the api in
/// ADR-0018 decision 2). Loads each RP's `frontchannel_logout_uri` in invisible iframes and, after all iframes
/// load (or time out), navigates to the post-logout redirect target.
#[derive(Template)]
#[template(path = "rp_logout.html")]
pub struct RpLogoutPage<'a> {
    pub messages: &'a Messages,
    pub frontchannel_uris: &'a [String],
    pub redirect_to: Option<&'a str>,
}

/// Confirmation screen for sign-out requests without `id_token_hint` (task #588). Executed via a CSRF-protected POST.
#[derive(Template)]
#[template(path = "rp_logout_confirm.html")]
pub struct RpLogoutConfirmPage<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix.
    pub tenant_prefix: &'a str,
    /// `console_csrf_token` (from the SSO session).
    pub csrf_token: &'a str,
    pub client_id: Option<&'a str>,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub state: Option<&'a str>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (used to build absolute paths of the Passkey JSON API; ADR-0009 §6).
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// The authorization request's `login_hint` (G12). Only a **display hint** used as the login field's initial value;
    /// it does not imply an existing account (an arbitrary string from the RP; the template escapes it).
    pub login_hint: Option<&'a str>,
    /// Display name of the client that sent the authorization request (looked up by the api from registered values).
    /// Makes the heading "Sign in to X". `None` shows the default heading.
    pub client_name: Option<&'a str>,
    /// Display name of the flow's tenant, shown as the navbar label. `None` shows `IdP`.
    pub tenant_name: Option<&'a str>,
    /// Whether to offer "Continue in the app" (the authenticator app endpoint is open; task #892). Showing it only on
    /// Android Chrome is up to the page script (cosmetic only; User-Agent is never used for decisions).
    pub app_approval_offered: bool,
}

/// End-user portal login screen (`GET /{tenant_id}/login`; direct login without an OIDC `auth_session`).
/// Entry to the IdP's own account screens; not placed in the shared layout.
#[derive(Template)]
#[template(path = "portal_login.html")]
pub struct PortalLogin<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (used to build form targets and links; ADR-0009 §6).
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// Enabled external IdPs (AP10). If empty, the whole button area is hidden.
    pub external_providers: &'a [assay_contracts::auth::ExternalIdpButton],
}

/// Portal TOTP input screen (`GET /{tenant_id}/login/mfa`). Shown while holding the `mfa_ticket` Cookie.
#[derive(Template)]
#[template(path = "portal_mfa.html")]
pub struct PortalMfa<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// Consent screen (`GET /consent`, F3).
#[derive(Template)]
#[template(path = "consent.html")]
pub struct ConsentTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub auth_session_id: &'a str,
    pub client_name: &'a str,
    pub requested_scopes: &'a [String],
}

/// SAML SSO auto-POST page (`GET /{tenant_id}/saml/continue`). Renders a form that POSTs the signed
/// `SAMLResponse` to the SP's ACS and submits it immediately with inline JS (submit button when JS is off).
/// The target is a foreign origin, so the handler adds a CSP allowing the ACS origin in `form-action`.
#[derive(Template)]
#[template(path = "saml_post.html")]
pub struct SamlPostPage<'a> {
    pub messages: &'a Messages,
    pub acs_url: &'a str,
    /// Base64-encoded SAML Response (the template escapes it into a hidden input).
    pub saml_response: &'a str,
    pub relay_state: Option<&'a str>,
}

/// Screen after pressing "Continue in the app" (task #892). Leaves a request marker in this browser and links to open the authenticator app.
///
/// ⚠ This screen only waits; it does not advance by itself even when approved (the new tab opened by the app does).
#[derive(Template)]
#[template(path = "app_approval_wait.html")]
pub struct AppApprovalWaitPage<'a> {
    pub messages: &'a Messages,
    /// App Link of the authenticator app (`/app/approve` on the issuer's host).
    pub approve_url: &'a str,
    pub tenant_prefix: &'a str,
}

/// Confirmation of registering the authenticator app's key (task #892). Opened inside the app's Auth Tab.
#[derive(Template)]
#[template(path = "app_approver_confirm.html")]
pub struct AppApproverConfirmPage<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub enrollment: &'a str,
    /// The app's self-reported device model name.
    pub device_name: &'a str,
    /// Translation key for how the key storage is shown.
    pub level_key: &'a str,
    /// When acceptance started (RFC 3339).
    pub created_at: &'a str,
}

/// Device registration screen shown when signing in correctly from an unregistered device (task #916).
#[derive(Template)]
#[template(path = "device_enrollment.html")]
pub struct DeviceEnrollmentPage<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    /// Whose sign-in this is.
    pub username: &'a str,
    /// Initial device name (from the browser's self-identification; editable).
    pub device_name: &'a str,
    /// Screen to return to after registration (paths of this tenant only).
    pub next: &'a str,
    /// Whether "Continue in the app" is available here (only for showing guidance).
    pub app_approval_offered: bool,
}

/// Minimal page with only a title and body (screens outside the shared layout, such as login errors or missing permissions).
#[derive(Template)]
#[template(path = "message_page.html")]
pub struct MessagePage {
    /// Display language tag (`ja` / `en`; `Messages::lang()`). Output as `<html lang>` (ADR-0048).
    pub lang: &'static str,
    pub title: String,
    pub message: String,
}

/// Screen for "use of the app is not permitted" (ADR-0054 decision 2).
///
/// ⚠ **Do not hide the reason.** The check happens after authentication, so hiding it gives no brute-force clue.
/// Silently rejecting is indistinguishable from an outage for users, who then doubt their credentials and retry.
/// So show three things: "sign-in succeeded", "which app refused", "whom to ask next".
#[derive(Template)]
#[template(path = "application_not_permitted.html")]
pub struct ApplicationNotPermittedPage {
    /// Display language tag (`ja` / `en`; `Messages::lang()`). Output as `<html lang>` (ADR-0048).
    pub lang: &'static str,
    pub title: String,
    /// "You signed in, but you are not permitted to use X".
    pub signed_in: String,
    /// "Ask an administrator to use it".
    pub next_step: String,
    /// Return target. **An empty string shows no link** (routes where the tenant cannot be identified).
    pub back_href: String,
    pub back_label: String,
}

/// HTTP error page (any status code: 403 / 404 / 500 etc.). Shows the status code large, with a
/// title and description. Takes only translated strings and the display language (no dependency on
/// `Messages`) so it can render even on unmatched routes (fallback) without tenant context.
/// Rendering entry points are consolidated in `crate::error_pages` (`page()` called directly by handlers, and
/// the middleware that unifies all error responses).
#[derive(Template)]
#[template(path = "error_page.html")]
pub struct ErrorPage {
    /// Display language tag (`ja` / `en`; `Messages::lang()`). Output as `<html lang>` (ADR-0048).
    pub lang: &'static str,
    /// Status code to display (e.g. `"404"`).
    pub code: String,
    pub title: String,
    pub message: String,
    /// Return URL. **An empty string shows no link** (routes where the tenant cannot be identified, or when the
    /// target equals the current location). Without an exit on an error screen, users have only the browser's back.
    pub back_href: String,
    /// Heading of the return target (translated). Unused when `back_href` is empty.
    pub back_label: String,
}

/// Version information page (`GET /{tenant_id}/admin/version`).
///
/// **It lives inside the admin console** (ADR-0034). Knowing the running commit lets outsiders judge which known
/// bugs are still open, so it is never on an unauthenticated surface.
#[derive(Template)]
#[template(path = "console/version.html")]
pub struct VersionTemplate<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub info: VersionInfo,
    /// Applied state of the DB schema (migrations). `None` if it cannot be fetched from the api (the screen
    /// shows "unavailable"). web has no DB, so it receives this via the api.
    pub schema: Option<SchemaVersionInfo>,
}

/// Forced password change screen (`GET /{tenant_id}/password-change`, ADR-0009 §5). Shown during the login
/// flow (password verified, SSO not yet issued). Not placed in the shared layout.
#[derive(Template)]
#[template(path = "password_change.html")]
pub struct PasswordChangeTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// Forced password change screen (on first login; ADR-0009 §5). Shared by the admin console login
/// (`POST /{tenant_id}/admin/password-change`) and the portal (general) login
/// (`POST /{tenant_id}/login/password-change`). Neither keeps temporary state, so
/// `username` (login identifier) is kept in a hidden field and the form target is switched via `action`.
/// The forced change in OIDC login ([`PasswordChangeTemplate`]) identifies the user by `auth_session_id`, so it is a separate screen.
#[derive(Template)]
#[template(path = "password_change_forced.html")]
pub struct ForcedPasswordChange<'a> {
    pub messages: &'a Messages,
    /// Absolute path of the form target (e.g. `/{tenant_id}/admin/password-change`).
    pub action: &'a str,
    pub csrf: &'a str,
    pub username: &'a str,
    pub error_key: Option<&'a str>,
}

/// Admin session context shown in the header of the admin console's shared layout.
///
/// "Who I am acting as and which tenant I am operating on" must always be visible on every console screen
/// (prevents operating on the wrong tenant). Both come at once from the api's whoami response, so
/// nothing extra is fetched per screen.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleAdmin<'a> {
    /// Admin's display label (display name -> login identifier -> internal ID).
    pub label: &'a str,
    /// Display name of the tenant being operated on. `None` only when the api did not return it (only the name is omitted).
    pub tenant_name: Option<&'a str>,
    /// Permission codes this admin can exercise (implications expanded by the api). Used to decide which menus to show.
    pub permissions: &'a [String],
    /// CSRF token for post-login state-changing forms (`console_csrf_token`). The header language
    /// dropdown posts to `POST /{tenant_id}/settings/display` (task #79). It lives here because every logged-in
    /// console screen passes this struct to the shared layout, so it reaches all screens without adding a field
    /// to each screen's template struct.
    pub csrf_token: &'a str,
}

impl ConsoleAdmin<'_> {
    /// Whether to show a link to a screen requiring the given permission (decides whether to show the menu).
    ///
    /// **Returns `true` when the list is empty.** It is empty when the api is too old to return this field
    /// (the few seconds of a rolling deploy); reading that as "no permission" would wipe out the menu.
    /// Anyone who got into the admin console holds at least `idp.tenant.admin`, so empty means
    /// "cannot filter". The api still returns 403 at the destination as before.
    pub fn can(&self, permission_code: &str) -> bool {
        self.permissions.is_empty() || self.permissions.iter().any(|code| code == permission_code)
    }
}

/// One admin console menu item.
///
/// The sidebar (`console/layout.html`) and home cards (`console/home.html`) **show the same thing
/// in different shapes**. ⚠ **Writing both by hand always drifts** -- in fact, the sidebar had only "External IdP"
/// and home only "Authentication policies" for a while. Neither was a subset of the other, so users could not
/// read it as "abbreviated" and were just left confused. Keeping the definition in this one place and
/// rendering both from it makes drift **impossible to write**.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleNavItem {
    /// Path following `{{ tenant }}` (including the leading `/`).
    pub path: &'static str,
    /// Font Awesome class name (without `fa-solid`).
    pub icon: &'static str,
    /// Translation key of the display name.
    pub label: &'static str,
    /// Translation key of the one-line description. ⚠ **Shown only on home** -- the sidebar is for choosing a
    /// destination; listing descriptions there would make it tall and harder to pick from.
    pub description: &'static str,
    /// Permission code required to show this screen. `None` = shown to everyone who can enter the admin console.
    pub requires: Option<&'static str>,
}

/// A menu group (a sidebar heading = one card on home).
#[derive(Debug, Clone, Copy)]
pub struct ConsoleNavGroup {
    pub label: &'static str,
    /// Translation key of the group description. ⚠ **Shown on home as the heading's subtitle** -- placing it inside
    /// the item list gives it the same indent and width as items, so it looks like an "unclickable first row".
    pub description: &'static str,
    pub icon: &'static str,
    pub items: &'static [ConsoleNavItem],
}

impl ConsoleNavGroup {
    /// Returns only the items visible to this admin. Groups that become empty are omitted entirely on home.
    pub fn visible_items(&self, admin: &ConsoleAdmin<'_>) -> Vec<ConsoleNavItem> {
        self.items
            .iter()
            .filter(|item| item.requires.is_none_or(|code| admin.can(code)))
            .copied()
            .collect()
    }
}

impl ConsoleNavItem {
    /// Whether the currently open screen belongs to this item (the sidebar's `aria-current`).
    pub fn is_current(&self) -> bool {
        current_console_nav_item().is_some_and(|current| current.path == self.path)
    }
}

/// For screens not in the menu, which item they are opened from (path prefix -> item path).
///
/// Creating users, member details, service accounts and invitations open from "Accounts"; restart and
/// saving system settings are posted from "Settings". ⚠ Paths not listed here look up the item by their own path,
/// so merely adding a screen under an item needs no entry (`/admin/clients/new` -> `/admin/clients`).
const CONSOLE_NAV_PARENTS: &[(&str, &str)] = &[
    ("/admin/users", "/admin/accounts"),
    ("/admin/members", "/admin/accounts"),
    ("/admin/service-accounts", "/admin/accounts"),
    ("/admin/invitations", "/admin/accounts"),
    ("/admin/system-settings", "/admin/settings"),
    ("/admin/restart", "/admin/settings"),
];

/// Whether `path` is `prefix` itself or below it (`prefix/…`).
///
/// Compares by segment -- a plain string prefix match would let `/admin/logs` capture `/admin/login`.
fn path_is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Looks up the menu item a screen belongs to from its tenant-relative path (e.g. `/admin/users/new`).
/// Screens belonging to no item, such as home, login and tenant switch, give `None`.
pub fn console_nav_item_for(path: &str) -> Option<&'static ConsoleNavItem> {
    let mut section = path;
    for (prefix, parent) in CONSOLE_NAV_PARENTS {
        if path_is_under(path, prefix) {
            section = *parent;
        }
    }
    CONSOLE_NAV
        .iter()
        .flat_map(|group| group.items)
        .find(|item| path_is_under(section, item.path))
}

/// The menu item the currently open screen belongs to. The shared layout uses it for the sidebar marker and tab title.
pub fn current_console_nav_item() -> Option<&'static ConsoleNavItem> {
    crate::tenant::current_relative_path().and_then(|path| console_nav_item_for(&path))
}

/// Whether the currently open screen is the admin console home.
pub fn console_home_is_current() -> bool {
    crate::tenant::current_relative_path().is_some_and(|path| path == "/admin")
}

/// Upper limit of admin notes on accounts (people and service accounts) (the input's `maxlength`; the contract crate
/// is the single source of the value; ADR-0063 / ADR-0065).
pub const ACCOUNT_NOTE_MAX_LEN: usize = assay_contracts::admin::ACCOUNT_NOTE_MAX_LEN;

/// Admin console menu definition (the single source for the sidebar and home).
///
/// ⚠ **When adding a screen, add it here.** `console_menu_covers_every_admin_screen` is a test that checks it
/// against `/admin/*` in `crates/web/src/router.rs`.
pub const CONSOLE_NAV: &[ConsoleNavGroup] = &[
    // ⚠ **Order: "what you manage" first, "what happened" last.** When operations/audit were at the top,
    //    people coming to manage something skipped over them every time.
    ConsoleNavGroup {
        label: "admin-home-group-access",
        description: "admin-home-group-access-desc",
        icon: "fa-users",
        items: &[
            // ⚠ **People and service accounts share one entry** (ADR-0065). When they were separate items,
            //    things added on the people side (notes, usable apps) did not reach the service account side.
            ConsoleNavItem {
                path: "/admin/accounts",
                icon: "fa-address-book",
                label: "admin-nav-accounts",
                description: "admin-nav-accounts-desc",
                requires: None,
            },
            // ⚠ **External IdPs and authentication policies are the "incoming" side.** When they shared a box with
            //    connected apps (to which assay passes identities), opposite directions were mixed and could not be found.
            //    Authentication policies are "who may sign in with which factors", which is about accounts.
            ConsoleNavItem {
                path: "/admin/external-idps",
                icon: "fa-right-to-bracket",
                label: "admin-nav-external-idps",
                description: "admin-nav-external-idps-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/authentication-policies",
                icon: "fa-shield-halved",
                label: "admin-nav-auth-policies",
                description: "admin-nav-auth-policies-desc",
                requires: None,
            },
        ],
    },
    // The "outgoing" side -- parties assay passes identities to, and the keys they use to verify them.
    ConsoleNavGroup {
        label: "admin-home-group-integration",
        description: "admin-home-group-integration-desc",
        icon: "fa-cubes",
        items: &[
            // ⚠ **Apps come first.** "Connections" (OIDC / SAML) are merely **how** an app connects
            //    (ADR-0054). People coming to decide who may use something land here first.
            ConsoleNavItem {
                path: "/admin/applications",
                icon: "fa-layer-group",
                label: "admin-nav-applications",
                description: "admin-nav-applications-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/clients",
                icon: "fa-cubes",
                label: "admin-nav-clients",
                description: "admin-nav-clients-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/saml-clients",
                icon: "fa-cube",
                label: "admin-nav-saml-clients",
                description: "admin-nav-saml-clients-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/resources",
                icon: "fa-bullseye",
                label: "admin-nav-resources",
                description: "admin-nav-resources-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/signing-keys",
                icon: "fa-key",
                label: "admin-nav-signing-keys",
                description: "admin-nav-signing-keys-desc",
                // Signing keys are shared by all tenants and the endpoints are root-only (the api's `require_root_tenant`).
                // In child tenants the api drops this code from the exercisable list, so the item disappears too.
                requires: Some("idp.keys:read"),
            },
        ],
    },
    ConsoleNavGroup {
        label: "admin-home-group-operations",
        description: "admin-home-group-operations-desc",
        icon: "fa-heart-pulse",
        items: &[
            ConsoleNavItem {
                path: "/admin/status",
                icon: "fa-heart-pulse",
                label: "admin-nav-status",
                description: "admin-nav-status-desc",
                requires: None,
            },
            ConsoleNavItem {
                path: "/admin/audit-logs",
                icon: "fa-file-lines",
                label: "admin-nav-audit",
                description: "admin-nav-audit-desc",
                requires: None,
            },
            // Error/warning logs require `idp.system.admin` (`api::handlers::admin_application_logs`).
            // Shown to admins without it, the link leads to a 403 dead end.
            ConsoleNavItem {
                path: "/admin/logs",
                icon: "fa-triangle-exclamation",
                label: "admin-nav-applog",
                description: "admin-nav-applog-desc",
                requires: Some("idp.system.admin"),
            },
        ],
    },
    ConsoleNavGroup {
        label: "admin-home-group-settings",
        description: "admin-home-group-settings-desc",
        icon: "fa-gear",
        items: &[
            ConsoleNavItem {
                path: "/admin/settings",
                icon: "fa-gear",
                label: "admin-nav-settings",
                description: "admin-nav-settings-desc",
                requires: None,
            },
            // Tenant management also requires `idp.system.admin` (`api::handlers::admin_tenants`).
            ConsoleNavItem {
                path: "/admin/tenants",
                icon: "fa-building",
                label: "admin-nav-tenants",
                description: "admin-nav-tenants-desc",
                requires: Some("idp.system.admin"),
            },
        ],
    },
];

/// Header context of the shared layout (`None` when unauthenticated).
/// Held by each console screen template and referenced from `console/layout.html`.
pub type Admin<'a> = Option<ConsoleAdmin<'a>>;

/// Admin console home (`GET /{tenant_id}/admin`).
#[derive(Template)]
#[template(path = "console/home.html")]
pub struct ConsoleHome<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (ADR-0009 §6).
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Banner for `?error=csrf` (returned from a logout with a mismatching token; task #143).
    pub error_key: Option<&'a str>,
}

/// Admin console login screen (`GET /{tenant_id}/admin/login`). Not placed in the shared layout.
#[derive(Template)]
#[template(path = "console/login.html")]
pub struct ConsoleLogin<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix. Used to build the forgotten-password link (`/forgot-password`).
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// Notice on the shared layout (error banner, 404, message with a back link). Reused by each console screen's
/// error responses. `is_error` toggles the error banner with `role="alert"`.
#[derive(Template)]
#[template(path = "console/notice.html")]
pub struct ConsoleNotice<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: Option<&'a str>,
    pub message: &'a str,
    pub is_error: bool,
    pub back_href: Option<&'a str>,
    pub back_label: &'a str,
}

/// Audit log list (`GET /{tenant_id}/admin/audit-logs`). Filter values are passed as expanded strings for re-entry.
/// Pager prev/next links (with query strings already built) are `None` when not applicable.
#[derive(Template)]
#[template(path = "console/audit_logs.html")]
pub struct AuditLogs<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub date_error: bool,
    pub event_type: &'a str,
    pub result: &'a str,
    pub client_id: &'a str,
    pub correlation_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub entries: &'a [AuditLogView],
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// Error/warning log list (`GET /{tenant_id}/admin/logs`). Filter values are passed as expanded strings for re-entry.
/// Pager prev/next links (with query strings already built) are `None` when not applicable.
#[derive(Template)]
#[template(path = "console/application_logs.html")]
pub struct ApplicationLogs<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub date_error: bool,
    pub level: &'a str,
    pub service: &'a str,
    pub target: &'a str,
    pub correlation_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub entries: &'a [ApplicationLogEntryResponse],
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// Client status list (`GET /{tenant_id}/admin/status`).
#[derive(Template)]
#[template(path = "console/client_status.html")]
pub struct ClientStatus<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub views: &'a [ClientStatusResponse],
}

/// User permissions screen (`GET /{tenant_id}/admin/users/{id}/permissions`).
#[derive(Template)]
#[template(path = "console/users_permissions.html")]
pub struct UsersPermissions<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub user: &'a UserSummaryResponse,
    /// Permission codes this user currently holds.
    pub codes: &'a [String],
    /// Permission codes grantable now (grantable codes minus those held). Shown as choices.
    pub grantable: &'a [String],
    /// Whether the list of grantable codes could not be fetched from the api. When `true` no choices can be shown,
    /// so say it is a fetch failure rather than letting it be mistaken for "no candidates".
    pub available_load_failed: bool,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// Profile save completion notice (shows a success banner when returning via Post/Redirect/Get; MT25).
    pub saved: bool,
}

/// User creation form (`GET/POST /{tenant_id}/admin/users/new`, ADR-0009 §5, §6).
#[derive(Template)]
#[template(path = "console/user_form.html")]
pub struct UserForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub email: &'a str,
    pub preferred_username: &'a str,
    pub name: &'a str,
    /// Admin note (ADR-0063).
    pub note: &'a str,
}

/// User creation result (on success of `POST /{tenant_id}/admin/users/new`). Shows the setup link only once.
#[derive(Template)]
#[template(path = "console/user_created.html")]
pub struct UserCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub email: &'a str,
    /// One-time link to hand to the person (ADR-0062). Shown only on this screen.
    pub setup_url: &'a str,
    /// When the link expires (RFC3339; redrawn in the viewer's time on screen).
    pub setup_expires_at: &'a str,
}

/// Account list (`GET /{tenant_id}/admin/accounts`; people and service accounts; ADR-0065).
#[derive(Template)]
#[template(path = "console/accounts_list.html")]
pub struct AccountsList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Accounts on the current page (not all of them).
    pub accounts: &'a [crate::admin_dto::AccountView],
    /// Total count after filtering (before paging).
    pub total: i64,
    /// Current filter term (to redisplay in the search box; empty means unfiltered).
    pub query: &'a str,
    /// Current kind (`user` / `service_account`; empty means "all"). Carried by the search form.
    pub kind: &'a str,
    /// Kind filter (shown only when two or more kinds are readable).
    pub kind_tabs: Vec<AccountKindTab>,
    /// Where to go when the search term is cleared (keeps the kind).
    pub clear_href: String,
    /// Whether people are readable (shows "Create user" and "Invite guest").
    pub can_read_users: bool,
    /// Whether service accounts are readable (shows "Add service account").
    pub can_read_service_accounts: bool,
    pub error_key: Option<&'a str>,
    pub notice_key: Option<&'a str>,
    /// Pager prev/next links (with query strings already built). `None` when not applicable.
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// One kind filter.
#[derive(Debug, Clone)]
pub struct AccountKindTab {
    /// Translation key.
    pub label: &'static str,
    pub href: String,
    pub active: bool,
}

/// Screen for one service account (`GET /{tenant_id}/admin/service-accounts/{client_id}`; ADR-0065).
///
/// Same skeleton as the person screen ([`MemberDetail`]) (basics -> note -> usable apps -> admin permissions -> edit -> danger).
#[derive(Template)]
#[template(path = "console/service_account_detail.html")]
pub struct ServiceAccountDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Facts as an account (status, identity, note).
    pub account: &'a crate::admin_dto::ServiceAccountView,
    /// Connection settings (authentication method, kind).
    pub client: &'a ClientView,
    /// Usable apps. Admins without `idp.applications:read` cannot look them up, so `None` (section hidden).
    pub applications: Option<&'a crate::admin_dto::AccountApplicationListView>,
    /// Admin permission codes held (ADR-0037).
    pub permission_codes: &'a [String],
    /// Permission codes grantable now (excluding held ones).
    pub grantable_permissions: &'a [String],
    /// Whether grantable codes could not be fetched from the api (so it is not mistaken for "no candidates").
    pub permissions_load_failed: bool,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    pub notice_key: Option<&'a str>,
}

impl ServiceAccountDetail<'_> {
    /// Translation key of the note field's example text (shows an example matching the kind).
    pub fn note_placeholder_key(&self) -> &'static str {
        "admin-service-account-note-placeholder"
    }

    /// URL of this service account's screen. Targets of the shared note/app sections (`account_*_card.html`) are built from it.
    pub fn account_href(&self) -> String {
        format!(
            "{}/admin/service-accounts/{}",
            self.tenant, self.account.client_id
        )
    }

    /// Target of the admin note.
    pub fn note_action(&self) -> String {
        format!("{}/note", self.account_href())
    }

    /// Target for assigning/unassigning apps (`verb` is `assign` / `unassign`).
    pub fn assignment_action(&self, application_id: &str, verb: &str) -> String {
        format!(
            "{}/applications/{application_id}/{verb}",
            self.account_href()
        )
    }
}

/// Screen for one member (`GET /{tenant_id}/admin/members/{user_id}`).
///
/// ⚠ **The list is only for "finding and viewing state"; operations are gathered here.** When one list cell
/// held 7 buttons, they stacked 7 high in the 168px action column and wide ones were cut off at the right
/// (row height 282px). **The very premise of fitting 7 into one cell was impossible.**
///
/// Here operations are split into 3 tiers by weight -- view (just navigates) / edit (can be redone) /
/// ⚠ **irreversible** (delete, remove). In the list everything was the same size, and
/// "View permissions" looked as weighty as "Delete".
#[derive(Template)]
#[template(path = "console/member_detail.html")]
pub struct MemberDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub member: &'a crate::admin_dto::MemberView,
    /// Apps this member can use (ADR-0063). Admins without `idp.applications:read` cannot
    /// look them up, so `None` (section hidden).
    pub applications: Option<&'a crate::admin_dto::AccountApplicationListView>,
    /// Number of currently valid refresh tokens (task #83). `None` for guests and when not fetched (hidden).
    pub active_tokens: Option<&'a crate::admin_dto::UserActiveTokensView>,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    pub notice_key: Option<&'a str>,
}

impl MemberDetail<'_> {
    /// Translation key of the note field's example text (shows an example matching the kind).
    pub fn note_placeholder_key(&self) -> &'static str {
        "admin-member-note-placeholder"
    }

    /// URL of this person's screen. Targets of the shared note/app sections (`account_*_card.html`) are built from it.
    pub fn account_href(&self) -> String {
        format!("{}/admin/members/{}", self.tenant, self.member.user_id)
    }

    /// Target of the admin note.
    pub fn note_action(&self) -> String {
        format!("{}/note", self.account_href())
    }

    /// Target for assigning/unassigning apps (`verb` is `assign` / `unassign`).
    pub fn assignment_action(&self, application_id: &str, verb: &str) -> String {
        format!(
            "{}/applications/{application_id}/{verb}",
            self.account_href()
        )
    }
}

/// Result screen of an admin password reissue (shows the one-time generated password; ADR-0009 §5).
/// Used from both the member list (HOME users) and tenant management (child tenant admins).
#[derive(Template)]
#[template(path = "console/password_reset_result.html")]
pub struct PasswordResetResult<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Display of the target (email address etc.).
    pub subject: &'a str,
    /// One-time link to hand to the person (ADR-0062).
    pub setup_url: &'a str,
    pub setup_expires_at: &'a str,
    pub back_href: &'a str,
    /// Message key of the back link.
    pub back_label_key: &'a str,
}

/// Guest invitation form (`GET/POST /{tenant_id}/admin/invitations`, ADR-0009 §3).
#[derive(Template)]
#[template(path = "console/invitation_form.html")]
pub struct InvitationForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    /// The entered invitee (email address or internal ID). Returned on failure so it need not be retyped.
    pub invitee: &'a str,
}

/// Guest invitation result (on success of `POST /{tenant_id}/admin/invitations`). Shows the invitation token only once.
#[derive(Template)]
#[template(path = "console/invitation_created.html")]
pub struct InvitationCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub token: &'a str,
    pub expires_at: &'a str,
    /// Whether the invitation email (accept link) could be sent (MT17). If false, prompts manual delivery of the token.
    pub email_sent: bool,
    /// Only when invited by email address (not shown when invited by internal ID; task #591).
    pub invitee_email: Option<&'a str>,
}

/// Password reset request screen (`GET/POST /{tenant_id}/forgot-password`; MT18). Logged-out route.
/// After accepting a request, the same completion text is shown whether or not the account exists (prevents enumeration).
#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPassword<'a> {
    pub messages: &'a Messages,
    /// Completion display after the request is accepted.
    pub accepted: bool,
    pub error_key: Option<&'a str>,
}

/// Password reset screen (`GET/POST /{tenant_id}/password-reset?token=...`; MT18).
/// Opened from the link in the reset email.
#[derive(Template)]
#[template(path = "password_reset.html")]
pub struct PasswordReset<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub show_form: bool,
    pub token: &'a str,
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// Invitation acceptance screen (`GET/POST /{tenant_id}/invitations/accept`; MT17). Opened by the invitee from
/// the link in the invitation email. Not placed in the shared (admin console) layout.
#[derive(Template)]
#[template(path = "invitation_accept.html")]
pub struct InvitationAccept<'a> {
    pub messages: &'a Messages,
    /// Whether to show the acceptance form (true only when signed in via SSO).
    pub show_form: bool,
    pub token: &'a str,
    pub csrf: &'a str,
    /// Whether acceptance succeeded (shows the success screen).
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// Email verification screen (`GET/POST /{tenant_id}/verify-email?token=...`; SEC6b). Opened from the link in
/// the self-registration confirmation email. GET shows a confirm button (POST consumes the token) so that
/// link prefetching does not consume the token. Logged-out route (no SSO needed).
#[derive(Template)]
#[template(path = "verify_email.html")]
pub struct VerifyEmail<'a> {
    pub messages: &'a Messages,
    /// Whether to show the confirmation form (POST button) (true when there is a token).
    pub show_form: bool,
    pub token: &'a str,
    /// Whether verification succeeded (shows the success screen).
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// Input values of the client registration/edit form (used for both new and redisplay). Fed as is into the
/// template's re-entry fields. `redirect_uris` is one URI per line; `scopes` is a raw space-separated string.
pub struct ClientFormValues {
    pub app_name: String,
    pub client_type: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub client_status: String,
    /// The client's usage (one of `client_usage`). The screen asks for this first and switches the following
    /// fields. The api has no such value; it expresses the same thing with two values: whether there are
    /// `redirect_uris` and whether `client_credentials` is allowed (ADR-0032).
    pub usage: String,
    /// Client authentication method (G3). Selectable only for confidential; public is always `none`.
    pub token_endpoint_auth_method: String,
    /// Verification keys for `private_key_jwt` (JWK Set JSON; ADR-0030). Contains only public keys, so
    /// showing the current value in the edit form is fine (needed to check during rotation).
    pub jwks: String,
    /// Admin note (ADR-0065). Rendered **only when registering a new service account**. Connected apps are not
    /// accounts and have no note; notes after registration are written on the single-item screen.
    pub note: String,
}

/// The client's usage. A console input unit, not part of the api's model (ADR-0032).
///
/// "Has a redirect_uri" and "allows `client_credentials`" are two independent values, but what admins actually
/// want to decide is one thing: "what is this client for". Exposing the two values yields clients with both
/// empty that can do nothing, or registrations with fabricated URIs that are never used from a browser.
pub mod client_usage {
    /// Signs users in via a browser (authorization_code).
    pub const USER_LOGIN: &str = "user_login";
    /// A system calls the API (client_credentials). No user is present, so no redirect_uri.
    pub const SYSTEM: &str = "system";
}

impl ClientFormValues {
    /// Whether this scope is selected (the template's checked state).
    ///
    /// Matches against the split space-separated stored form. No substring match, because `profile`
    /// would match a future value like `profile_extended`, making an unselected field
    /// appear selected.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split_whitespace().any(|s| s == scope)
    }

    /// Initial values of the new registration form (confidential, PKCE required, openid scope).
    ///
    /// The default authentication method is `private_key_jwt`. A shared secret is stored on the IdP side, placed in
    /// the client's config file, and travels over the network on every request (ADR-0030). **The default is
    /// the value set when the chooser did not think about it**, so keep it on the safe side.
    pub fn default_new() -> Self {
        Self {
            app_name: String::new(),
            client_type: "confidential".to_string(),
            redirect_uris: String::new(),
            scopes: "openid".to_string(),
            client_status: "ACTIVE".to_string(),
            usage: client_usage::USER_LOGIN.to_string(),
            token_endpoint_auth_method: "private_key_jwt".to_string(),
            jwks: String::new(),
            note: String::new(),
        }
    }

    /// Builds the edit form's initial values from an existing client (URIs newline-separated, scopes space-separated).
    pub fn from_client(c: &ClientView) -> Self {
        Self {
            app_name: c.app_name.clone(),
            client_type: c.client_type.clone(),
            redirect_uris: c.redirect_uris.join("\n"),
            scopes: c.scopes.join(" "),
            client_status: c.client_status.clone(),
            // The true source of the usage is the registration returned by the api (G4). The form shows a copy of it.
            usage: usage_from_registration(&c.grant_types, &c.redirect_uris),
            token_endpoint_auth_method: c.token_endpoint_auth_method.clone(),
            jwks: c.jwks.clone().unwrap_or_default(),
            note: String::new(),
        }
    }
}

/// Decides the on-screen usage from the registered content.
///
/// System means "has `client_credentials` and has no redirect_uri".
/// Not deciding by `client_credentials` alone **leans registrations not expressible as a usage toward keeping URIs**.
/// The "both" shape (`authorization_code` + `client_credentials` + redirect_uri) cannot be created because the api
/// rejects it on both create and update (ADR-0032 Revised), but if it existed (e.g. via direct DB edits),
/// reading it as system would let it be saved with the redirect_uri field hidden, silently erasing all
/// registered redirect targets not even shown (= running logins stop with `unauthorized_client`).
/// With this reading, saving merely gets refused by the api with `api-client-usage-conflict`.
fn usage_from_registration(grant_types: &[String], redirect_uris: &[String]) -> String {
    if grant_types.iter().any(|g| g == "client_credentials") && redirect_uris.is_empty() {
        client_usage::SYSTEM
    } else {
        client_usage::USER_LOGIN
    }
    .to_string()
}

/// External IdP list (`GET /{tenant_id}/admin/external-idps`; AP16; the API is AP10).
///
/// **The registration form is not on this screen.** The fields required differ completely by protocol (OIDC / SAML),
/// and putting both in one form makes "what am I registering now" unreadable. The entry point asks for the
/// protocol, and from then on only that protocol's screen is shown (same shape as ADR-0038 splitting registration by usage).
#[derive(Template)]
#[template(path = "console/external_idps.html")]
pub struct ExternalIdpsConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub providers: &'a [crate::admin_dto::ExternalIdpView],
    pub saved: bool,
    pub deleted: bool,
    pub error_key: Option<&'a str>,
}

/// Choosing the protocol to register (`GET /{tenant_id}/admin/external-idps/new`).
///
/// This is the registration entry point. OIDC and SAML are not "different settings of the same thing": what is
/// received from the counterpart and how authenticity is checked differ, so this is decided first.
#[derive(Template)]
#[template(path = "console/external_idp_choose.html")]
pub struct ExternalIdpProtocolChoice<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
}

/// External IdP registration/edit form (`GET /{tenant_id}/admin/external-idps/new/{protocol}` and
/// `GET /{tenant_id}/admin/external-idps/{id}/edit`).
///
/// **The protocol is decided before entering the screen.** For new ones the URL decides, for edits the registered
/// value, so there is no choice in the form (the api also rejects changing the protocol after registration).
#[derive(Template)]
#[template(path = "console/external_idp_form.html")]
pub struct ExternalIdpFormPage<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    /// id of the edit target (`None` means new registration).
    pub editing: Option<&'a str>,
    /// Initial form values (the target's current values when editing, defaults when new).
    pub values: &'a ExternalIdpFormValues,
    /// Whether initial values were just filled in by metadata import (AP12).
    pub imported: bool,
    pub error_key: Option<&'a str>,
}

/// Values of the external IdP settings form (round-tripped). Variable-length values (`scopes`, SAML certificates)
/// are held as one string (scopes space-separated, certificates separated by blank lines).
///
/// **Fields used vary by protocol, but there is one struct.** Splitting into OIDC and SAML structs would not
/// change the shape of the values the screen carries (the protocol is fixed before the screen, so no mix-up
/// occurs). The api (`ExternalIdpConfig`) is the single source for judging valid combinations.
#[derive(Debug, Clone)]
pub struct ExternalIdpFormValues {
    pub provider_code: String,
    pub display_name: String,
    /// `oidc` / `saml`. Cannot be changed after registration (the api rejects it, because existing links would
    /// keep pointing at identifiers of another protocol).
    pub protocol: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// The api does not return secrets, so no value is held. Only **whether it is set** is passed to the screen;
    /// a blank field on edit means "unchanged" (interpreting blank as delete would break the link merely
    /// by fixing another field).
    pub has_client_secret: bool,
    pub scopes: String,
    /// SAML: the IdP's `SingleSignOnService` URL.
    pub saml_sso_url: String,
    /// SAML: certificates for signature verification. Several can be written separated by blank lines (during rotation old and new are both valid).
    pub saml_certificates: String,
    pub saml_name_id_format: String,
    pub enabled: bool,
    pub allow_auto_link: bool,
}

/// Scopes chosen via checkboxes. `openid` is always required to get an ID Token (cannot be removed), so it is
/// not included -- listing an unchoosable item as a choice makes it look removable.
///
/// **Adding here alone does not add a choice.** The checkbox `name` (`scope_*`) is written directly in
/// `console/external_idp_form.html`, and building the submitted value in
/// `handlers::admin_external_idps_console::selected_scopes`. Adding to only one
/// removes the scope from the free-text field without a checkbox, so it is **silently dropped on every
/// save**. When adding, align all 3 places.
pub const EXTERNAL_IDP_OPTIONAL_SCOPES: [&str; 2] = ["profile", "email"];

impl ExternalIdpFormValues {
    pub fn is_saml(&self) -> bool {
        self.protocol == "saml"
    }

    /// Whether this scope is selected (the template's checked state). Matches against the split
    /// space-separated stored form. No substring match, because `email` would match the counterpart's
    /// values like `email_verified`, making an unselected field appear selected.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split_whitespace().any(|s| s == scope)
    }

    /// Scopes not in the checkboxes (space-separated).
    ///
    /// **Scopes requested from an external IdP are defined by the counterpart**, so choices must not be closed to fixed
    /// values (there are counterpart-specific values like `groups`, `User.Read`). The two common ones are
    /// checkboxes; the rest go in this field. `openid` is always added, so it is not shown here.
    pub fn extra_scopes(&self) -> String {
        self.scopes
            .split_whitespace()
            .filter(|s| *s != "openid" && !EXTERNAL_IDP_OPTIONAL_SCOPES.contains(s))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Default for ExternalIdpFormValues {
    fn default() -> Self {
        Self {
            provider_code: String::new(),
            display_name: String::new(),
            protocol: "oidc".to_string(),
            issuer: String::new(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            client_id: String::new(),
            has_client_secret: false,
            // Minimal OIDC configuration. Same as the api defaults.
            scopes: "openid profile email".to_string(),
            saml_sso_url: String::new(),
            saml_certificates: String::new(),
            saml_name_id_format: String::new(),
            enabled: true,
            // Auto-linking is OFF by default (it lets a verified-email match alone enter an existing account).
            allow_auto_link: false,
        }
    }
}

/// Login identifier management screen (`GET /{tenant_id}/admin/users/{user_id}/login-identifiers`; AP16; the API is AP8).
#[derive(Template)]
#[template(path = "console/login_identifiers.html")]
pub struct LoginIdentifiersConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub user_id: &'a str,
    pub identifiers: &'a [LoginIdentifierRow<'a>],
    pub type_options: &'a [LoginIdentifierTypeOption<'a>],
    pub error_key: Option<&'a str>,
    pub notice_key: Option<&'a str>,
}

/// One list row. The kind's translated label is resolved by the handler (templates do not build translation keys).
pub struct LoginIdentifierRow<'a> {
    /// Registry row id. `None` is the primary identifier (synthetic row), which has no per-identifier operations.
    pub id: Option<&'a str>,
    /// Kind code (`email` etc.). Held separately from the label so the promote-to-primary-email button is shown
    /// **only on email-type rows**. Deciding by the label would make the button vanish when the language changes.
    pub identifier_type: &'a str,
    pub type_label: String,
    pub display_value: &'a str,
    pub normalized_value: &'a str,
    pub is_active: bool,
    pub is_primary: bool,
    /// Whether this is the primary email address row (ADR-0050). Like the primary identifier, not subject to individual operations.
    pub is_primary_email: bool,
}

/// Choices of the kind dropdown in the add form.
pub struct LoginIdentifierTypeOption<'a> {
    pub code: &'a str,
    pub label: String,
}

/// Authorization response page for `response_mode=form_post` (G12). Passes the authorization code to the RP in the
/// form body instead of the URL. Rendering decisions are consolidated in [`crate::authorization_response`].
#[derive(Template)]
#[template(path = "authorization_post.html")]
pub struct AuthorizationPost<'a> {
    pub messages: &'a Messages,
    /// Form target (`redirect_uri`; it carries no authorization response parameters).
    pub action: &'a str,
    /// Hidden fields (`code` / `state`, or an error). Values are auto-escaped by the template.
    pub fields: &'a [(String, String)],
}

/// Client list (`GET /{tenant_id}/admin/clients`).
#[derive(Template)]
#[template(path = "console/clients_list.html")]
pub struct ClientsList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// List heading. The same template serves connected apps (OIDC) and service accounts (ADR-0038).
    pub title: String,
    /// Text and target of the "New" button. The usage is decided at this entry.
    pub new_label: String,
    pub new_href: String,
    /// Text when there are none. "Nothing registered yet" means different things per family.
    pub none_label: String,
    /// Clients on the current page (paging introduced in G7; not all of them).
    pub clients: &'a [ClientView],
    /// Total count before paging. Used for the "N total" display.
    pub total: i64,
    /// Pager prev/next links (with query strings already built). `None` when not applicable.
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// Client registration/edit form (`is_new` switches new/edit).
#[derive(Template)]
#[template(path = "console/client_form.html")]
pub struct ClientForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub heading: &'a str,
    pub action: &'a str,
    pub is_new: bool,
    pub values: &'a ClientFormValues,
    /// The list to return to (since ADR-0038 split the client list per family, it cannot be fixed).
    pub list_href: String,
}

/// Client detail (`GET /{tenant_id}/admin/clients/{id}`).
#[derive(Template)]
#[template(path = "console/client_detail.html")]
pub struct ClientDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub client: &'a ClientView,
    pub csrf: &'a str,
    /// Admin permission codes this client currently holds (ADR-0037).
    pub permission_codes: &'a [String],
    /// Permission codes grantable now (codes grantable to clients minus those held).
    pub grantable_permissions: &'a [String],
    /// Whether grantable codes could not be fetched from the api. When `true` no choices can be shown,
    /// so say it is a fetch failure rather than letting it be mistaken for "no candidates".
    pub permissions_load_failed: bool,
    /// Whether to show the admin permissions section. Shown **only for system clients (able to use `client_credentials`)
    /// or when permissions are already held**. Granting to a browser-login client is useless since it has
    /// no way to obtain an admin token, so it would show operations that have no effect (ADR-0037).
    pub shows_permissions: bool,
    /// Whether to show the grant form. true **only for system clients**. Separated from revocation (`shows_permissions`)
    /// to prevent newly adding ineffective permissions to a browser-login client that merely has
    /// leftover permissions (ADR-0037).
    pub shows_grant_form: bool,
    pub error_key: Option<&'a str>,
    /// The list to return to (ADR-0038). Returns to the family's list determined by the registration.
    pub list_href: String,
    /// Whether to show audience (`aud`) guidance. **Only for system clients.** Which audience's tokens may be
    /// taken is decided by the "users" of the app claiming that audience (ADR-0059 decision 6).
    pub shows_resources: bool,
}

/// Secret display screen (right after creation/reissue; if `secret` is `None`, it is public with no secret).
#[derive(Template)]
#[template(path = "console/client_secret.html")]
pub struct ClientSecret<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: &'a str,
    pub client_id: &'a str,
    pub secret: Option<&'a str>,
    /// The list to return to (ADR-0038).
    pub list_href: String,
}

/// App list and registration screen (`GET /{tenant_id}/admin/applications`; ADR-0054).
#[derive(Template)]
#[template(path = "console/applications.html")]
pub struct ApplicationsList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub applications: &'a [ApplicationView],
    /// Whether the check is still "record only". ⚠ **If true, assignments are not refusing anyone yet.**
    /// Without showing this, whoever curated the roster assumes "it is already in effect".
    pub record_only: bool,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// Screen for one app (`GET /{tenant_id}/admin/applications/{id}`; ADR-0054).
#[derive(Template)]
#[template(path = "console/application_detail.html")]
pub struct ApplicationDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub application: &'a ApplicationView,
    pub assigned: &'a [ApplicationAssignmentView],
    /// Assigned service accounts (ADR-0059). Listed with their kind in the same list as people.
    pub assigned_service_accounts: &'a [ApplicationServiceAccountAssignmentView],
    /// For "everyone": **the people currently signing in** (can be copied into the roster as is).
    /// Empty for "individual".
    pub current_users: &'a [ApplicationCurrentUserView],
    /// Whether "people currently signing in" was cut off at the limit. ⚠ If true, the screen says so.
    pub current_users_truncated: bool,
    pub current_users_total: i64,
    /// Identity candidates grouped by kind (ADR-0067). Counterparts are chosen from here rather than typing IDs.
    pub candidate_groups: &'a [BindingCandidateGroup],
    /// Whether candidates could not be read (the screen still renders and says so instead of the binding field).
    pub candidates_unavailable: bool,
    /// Confirmation when the chosen counterpart is another app's identity ("move from X").
    pub pending_move: Option<&'a ApplicationBindingCandidateView>,
    /// Summary of what "Delete this app" detaches (counts of identities and users; same as the api's delete
    /// behaviour -- detach both, then delete).
    pub delete_summary: &'a str,
    pub record_only: bool,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// Protected resources (audiences in `aud`) list/management screen (`GET /{tenant_id}/admin/resources`; ADR-0042).
#[derive(Template)]
#[template(path = "console/resources.html")]
pub struct ResourcesList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub resources: &'a [ResourceView],
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// Signing key list/management screen (`GET /{tenant_id}/admin/signing-keys`, K1).
#[derive(Template)]
#[template(path = "console/signing_keys.html")]
pub struct SigningKeysList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub keys: &'a [SigningKeyView],
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// Tenant list/registration screen for root admins (`GET /{tenant_id}/admin/tenants`).
#[derive(Template)]
#[template(path = "console/tenants.html")]
pub struct TenantsConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Child tenants on the current page (paging introduced in G7; not all of them).
    pub tenants: &'a [TenantView],
    /// Total count before paging. Used for the "N total" display.
    pub total: i64,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
    /// Update completion notice (shows a success banner when returning via Post/Redirect/Get; MT23).
    pub saved: bool,
    /// Pager prev/next links (with query strings already built). `None` when not applicable.
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// Tenant switch screen (`GET /{tenant_id}/admin/switch-tenant`). Lists tenants where the logged-in user has an
/// `ACTIVE` membership and navigates to the target tenant's admin console. SSO is shared per host,
/// so no re-login is needed (ADR-0009 §8).
#[derive(Template)]
#[template(path = "console/switch_tenant.html")]
pub struct SwitchTenant<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// Switchable tenants.
    pub tenants: &'a [assay_contracts::auth::AccountTenantSummary],
    /// Internal ID of the currently open tenant (used to highlight the current location).
    pub current_tenant_id: &'a str,
    /// Whether fetching the list from the api failed (a caution is shown on failure).
    pub load_failed: bool,
}

/// Tenant creation result (on success of `POST /{tenant_id}/admin/tenants`).
#[derive(Template)]
#[template(path = "console/tenant_created.html")]
pub struct TenantCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub created: &'a TenantCreatedView,
}

/// Admin console settings screen (`GET /{tenant_id}/admin/settings`; MT14). A tenant settings section (own tenant's
/// display name) and a system settings section (SMTP) shown only to root (idp.system.admin). When `system` is `None`
/// the system settings section is not rendered.
#[derive(Template)]
#[template(path = "console/admin_settings.html")]
pub struct AdminSettings<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub tenant_id: &'a str,
    pub tenant_name: &'a str,
    pub tenant_status: &'a str,
    /// Toggle allowing self-registration (/auth/register) (SEC6).
    pub tenant_self_registration: bool,
    /// State of the email-address login toggle (ADR-0050).
    pub tenant_email_login: bool,
    pub csrf: &'a str,
    /// Shows the save-success banner.
    pub saved: bool,
    pub error_key: Option<&'a str>,
    /// Tenant setting values (ADR-0058). `None` without `idp.tenant-settings:read` (section hidden).
    pub tenant_settings: Option<&'a crate::admin_dto::TenantSettingsListView>,
    /// The tenant's own mail route (ADR-0058 §8). `None` without `idp.smtp:read` (section hidden).
    pub tenant_smtp: Option<&'a crate::admin_dto::TenantSmtpView>,
    /// `Some` only for root. Renders the SMTP settings section.
    pub system: Option<&'a crate::admin_dto::SystemSettingsView>,
    /// Key names saved but not yet applied to the api (MT27). Empty means none pending.
    pub pending_api_keys: &'a [String],
    /// Shared key names applied in the api but stale in web (MT27). Remains when only the api was restarted.
    pub stale_web_keys: &'a [String],
    /// Filter conditions (written back to the form). The handler filters the list before passing it.
    pub filter: &'a crate::settings_filter::SettingsFilter,
    /// Count of tenant settings before filtering ("M of N").
    pub tenant_values_total: usize,
    /// Count of global runtime settings before filtering.
    pub runtime_total: usize,
}

impl AdminSettings<'_> {
    /// "Shown / before filtering" for tenant settings. Inserted into the count text as one value.
    pub fn tenant_values_count(&self) -> String {
        let shown = self.tenant_settings.map_or(0, |l| l.settings.len());
        format!("{shown} / {}", self.tenant_values_total)
    }

    /// "Shown / before filtering" for global runtime settings.
    pub fn runtime_count(&self) -> String {
        let shown = self.system.map_or(0, |s| s.runtime_settings.len());
        format!("{shown} / {}", self.runtime_total)
    }

    /// Display name of a setting key. Keys without a translation (just added to the definition) show the key itself
    /// -- items are listed from the api's definitions, so a forgotten translation must not make an item vanish.
    pub fn setting_label(&self, key: &str) -> String {
        setting_label(self.messages, key)
    }

    /// Value display. Booleans as "enabled / disabled"; second values (`*_SECS`) with a duration, like
    /// "604800 (7 days)" (others as stored).
    pub fn value_label(&self, item: &crate::admin_dto::TenantSettingView, value: &str) -> String {
        if item.kind == "BOOLEAN" {
            match value {
                "true" => return self.messages.get("admin-tenant-values-true"),
                "false" => return self.messages.get("admin-tenant-values-false"),
                _ => {}
            }
        }
        if is_seconds_setting(&item.key) {
            if let Some(duration) = value
                .trim()
                .parse::<u64>()
                .ok()
                .and_then(|secs| duration_label(self.messages, secs))
            {
                return self.messages.get_args(
                    "admin-tenant-values-seconds-with-duration",
                    &[("value", value), ("duration", &duration)],
                );
            }
        }
        value.to_string()
    }

    /// Whether the setting is entered in seconds (a quick reference is shown under the input).
    pub fn is_seconds(&self, item: &crate::admin_dto::TenantSettingView) -> bool {
        item.kind == "UNSIGNED_INTEGER" && is_seconds_setting(&item.key)
    }
}

/// Whether the value is a seconds setting (key name ends in `_SECS`).
pub fn is_seconds_setting(key: &str) -> bool {
    key.ends_with("_SECS")
}

/// Turns seconds into a duration like "7 days", "8 hours", "1 day 2 hours 30 minutes". 0 gives `None` (some settings
/// use it to mean "none", so it is not read as a duration).
pub fn duration_label(messages: &Messages, secs: u64) -> Option<String> {
    if secs == 0 {
        return None;
    }
    let units = [
        (86_400, "duration-days"),
        (3_600, "duration-hours"),
        (60, "duration-minutes"),
        (1, "duration-seconds"),
    ];
    let mut rest = secs;
    let mut parts = Vec::new();
    for (size, key) in units {
        let n = rest / size;
        rest %= size;
        if n > 0 {
            let id = if n == 1 {
                format!("{key}-one")
            } else {
                format!("{key}-other")
            };
            parts.push(messages.get_arg(&id, "n", &n.to_string()));
        }
    }
    Some(parts.join(" "))
}

/// Display name of a setting key (`admin-tenant-setting-<KEY>`). The key itself if untranslated.
pub fn setting_label(messages: &Messages, key: &str) -> String {
    let id = format!("admin-tenant-setting-{key}");
    let label = messages.get(&id);
    if label == id {
        key.to_string()
    } else {
        label
    }
}

/// Confirmation screen before changing to a value that could lock people out (when the api returns 409 for
/// `POST /{tenant_id}/admin/settings/tenant/keys`; ADR-0058).
#[derive(Template)]
#[template(path = "console/admin_tenant_setting_confirm.html")]
pub struct AdminTenantSettingConfirm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub key: &'a str,
    pub label: &'a str,
    pub description: &'a str,
    /// The value currently in effect for this tenant (`None` when the list could not be fetched).
    pub current_value: Option<&'a str>,
    /// The new value.
    pub value: &'a str,
}

/// Restart wait screen (response of `POST /{tenant_id}/admin/restart`; ADR-0017).
///
/// web itself stops right after returning this, so it does not inherit the shared layout (navigation).
#[derive(Template)]
#[template(path = "console/restarting.html")]
pub struct Restarting<'a> {
    pub messages: &'a Messages,
    /// Reload target (the settings screen).
    pub settings_href: &'a str,
    /// Seconds until auto reload. A bit longer than both services need to restart.
    pub retry_after_seconds: u64,
}

/// User self-service settings screen (`GET /{tenant_id}/settings`; MT15). Links to password change, language
/// settings and MFA. A user-facing screen separate from the admin console, so not in the shared layout.
#[derive(Template)]
#[template(path = "user_settings.html")]
pub struct UserSettings<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (used to build form targets and MFA links; ADR-0009 §6).
    pub tenant: &'a str,
    /// Current display language (`ja` / `en`). Initial selection of the language selector.
    pub current_lang: &'a str,
    /// Current color scheme (`light` / `dark` / `system`). Initial selection of the scheme selector.
    pub current_theme: &'a str,
    /// Current display name (for prefill; empty string if unset).
    pub current_name: &'a str,
    /// Login identifier (display only, not editable; empty string if unset).
    pub preferred_username: &'a str,
    /// Key of the save-success message (`None` hides it).
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
    /// Whether opened from the admin console (`?from=admin`). Shows a back link at the top left and keeps it across form posts.
    pub from_admin: bool,
    /// CSRF token of the state-changing forms (display name, password, language, color scheme) (`console_csrf_token`;
    /// task #79, #118).
    pub csrf: &'a str,
}

/// One row of the authenticator list (AP9). Kind and status arrive already mapped to translation keys.
pub struct AuthenticatorView {
    pub id: String,
    /// Translation key of the kind.
    pub type_key: &'static str,
    /// Translation key of the status.
    pub status_key: &'static str,
    pub label: String,
    pub created_at: String,
    /// Most recent use time (empty string if never used).
    pub last_used_at: String,
    /// Whether to show the suspend button (only when `active`).
    pub suspendable: bool,
    /// Whether to show the resume button (only when `suspended`).
    pub resumable: bool,
}

/// Authenticator management screen (`GET /{tenant_id}/settings/authenticators`; AP9).
#[derive(Template)]
#[template(path = "user_authenticators.html")]
pub struct UserAuthenticators<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub csrf: &'a str,
    pub authenticators: &'a [AuthenticatorView],
    /// Number of unused recovery codes left.
    pub recovery_codes_remaining: usize,
    /// Whether an SMS gateway is configured (AP13). If not, the registration entry is hidden entirely.
    pub sms_available: bool,
    /// Whether a verified phone number is registered (the number itself is not passed to web).
    pub phone_registered: bool,
    /// Whether awaiting confirmation code input (right after starting registration).
    pub awaiting_phone_code: bool,
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
}

/// Result of issuing recovery codes (AP9). The plaintext is shown only on this screen.
#[derive(Template)]
#[template(path = "recovery_codes.html")]
pub struct RecoveryCodes<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub codes: &'a [String],
}

/// Step-up authentication verification screen (`GET /{tenant_id}/settings/verify`; AP5).
#[derive(Template)]
#[template(path = "step_up_challenge.html")]
pub struct StepUpChallenge<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix.
    pub tenant: &'a str,
    /// Synchronizer token for post-login forms (`console_csrf_token`).
    pub csrf: &'a str,
    /// Target operation (put into the POST as is; the api re-decides the requirements).
    pub operation: &'a str,
    /// Where to return after verification (already restricted by web to paths of the same tenant).
    pub next: &'a str,
    /// Whether to show the TOTP field (when the requirement is multi-factor).
    pub second_factor_required: bool,
    /// Whether to offer passkey verification (has a passkey **usable now**; T38). Showing the button to users
    /// without one makes them fail after the browser dialog appears.
    pub passkey_available: bool,
    /// Whether the operation can only be verified by passkey (device registration; task #872). No password field.
    pub passkey_only: bool,
    pub error_key: Option<&'a str>,
}

/// One session row of the security screen (G10). Times are output as the RFC 3339 strings the api returned.
pub struct SecuritySessionView {
    /// Display ID put in the revoke form (an irreversible derivation of `session_hash`).
    pub id: String,
    pub current: bool,
    pub multi_factor: bool,
    pub auth_time: String,
    /// User-Agent (empty string if not recorded; avoids `Option` to keep the template simple).
    pub user_agent: String,
    pub ip_address: String,
    pub absolute_expires_at: String,
    /// Device, binding, sign-in method and lifetime basis of this sign-in state, taken from "Status" (task #896).
    /// `None` when "Status" could not be read (only the existing columns are shown).
    pub status: Option<SessionStatusView>,
}

/// Status of one sign-in state (task #896; ADR-0078). Text is held as keys and translated by the template.
#[derive(Clone)]
pub struct SessionStatusView {
    pub id: String,
    pub current: bool,
    pub auth_time: String,
    /// Expiry time (RFC 3339).
    pub expires_at: String,
    /// Sign-in method (`user-security-signins-method-*`).
    pub method_keys: Vec<&'static str>,
    pub multi_factor: bool,
    /// "OS / browser" summary and the original self-identification.
    pub browser: String,
    pub user_agent: String,
    pub ip_address: String,
    pub country: String,
    pub device_identified: bool,
    /// Name of the registered device (empty if unregistered).
    pub device_name: String,
    pub device_registered_at: String,
    pub device_last_used_at: String,
    /// `user-security-status-binding-*`.
    pub binding_key: &'static str,
    /// `user-security-status-basis-*`.
    pub basis_key: &'static str,
    /// Short wording of the basis (one row of the "sign-in state" table; `user-security-status-basis-*-short`).
    pub basis_short_key: &'static str,
    /// Whether the long lifetime is used (colors the basis row).
    pub long_lifetime: bool,
    pub key_algorithm: String,
    /// Head of the public key fingerprint (12 chars).
    pub key_thumbprint_head: String,
    pub key_bound_at: String,
    pub key_refreshed_at: String,
    pub approver_device_name: String,
    /// `app-approver-level-*` (empty if not signed in via approval).
    pub approver_level_key: &'static str,
    pub passkey_fresh_until: String,
}

/// One trusted belonging (task #896).
pub struct BelongingView {
    /// `user-security-status-kind-*`.
    pub kind_key: &'static str,
    /// What it is used for (`user-security-status-use-*`).
    pub use_key: &'static str,
    /// Strength (`user-security-status-strength-*`).
    pub strength_key: &'static str,
    pub name: String,
    /// Supplement (device self-identification, SSH key type).
    pub detail: String,
    /// Key to translate the supplement (the authenticator app's key storage; empty if none).
    pub detail_key: &'static str,
    pub registered_at: String,
    pub last_used_at: String,
    /// The last-used time is not visible to assay (SSH keys).
    pub last_use_invisible: bool,
    pub expires_at: String,
}

/// Token kind of one app (task #896).
pub struct AppTokensView {
    pub app_name: String,
    pub scopes: String,
    pub active_refresh_tokens: u32,
    pub dpop_bound_refresh_tokens: u32,
    /// `user-security-status-token-*` (one row for the refresh token kind).
    pub token_key: &'static str,
    pub last_issued_at: String,
    pub refresh_use_count: u32,
    pub refresh_last_used_at: String,
    pub refresh_last_sender: String,
    pub refresh_reuse_detected_at: String,
}

/// Organization rules in effect for me (task #896).
pub struct PolicyView {
    pub unregistered_device_alerts: bool,
    pub ssh_keys_enabled: bool,
    /// Duration (in a readable form like "30 days", "8 hours").
    pub bound_ttl: String,
    pub absolute_ttl: String,
    pub idle_ttl: String,
    pub device_expiry_days: i64,
}

/// One caution row (task #896).
pub struct WarningView {
    /// `user-security-status-warning-*`.
    pub key: &'static str,
    pub count: u32,
    pub last_at: String,
}

/// The "Status" section (task #896; ADR-0078).
pub struct SecurityStatusView {
    /// The sign-in state being viewed now (if none, the "this browser" section is hidden).
    pub current: Option<SessionStatusView>,
    /// What was read from this browser's current request (now, not at sign-in).
    pub browser: String,
    pub user_agent: String,
    pub ip_address: String,
    /// Country (empty when untrustworthy or from inside the home network).
    pub country: String,
    /// Expiry of the short Cookie (re-obtained every 10 minutes with the device key) (RFC 3339; empty if none).
    pub bound_cookie_expires_at: String,
    pub belongings: Vec<BelongingView>,
    pub apps: Vec<AppTokensView>,
    pub policy: PolicyView,
    pub warnings: Vec<WarningView>,
    /// Days (`YYYY-MM-DD`) with many refused sign-ins and the counts.
    pub failure_days: Vec<(String, u32)>,
    pub warning_window_days: i64,
}

impl SecurityStatusView {
    /// Whether there is at least one caution.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty() || !self.failure_days.is_empty()
    }
}

/// One connected-app row of the security screen (G10).
pub struct ConnectedAppView {
    pub client_id: String,
    pub app_name: String,
    /// Consented scopes (space-separated display string).
    pub scopes: String,
    pub granted_at: String,
}

/// Self-service security screen (`GET /{tenant_id}/settings/security`; G10).
#[derive(Template)]
#[template(path = "user_security.html")]
pub struct UserSecurity<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (used to build form targets).
    pub tenant: &'a str,
    /// Synchronizer token for post-login forms (`console_csrf_token`).
    pub csrf: &'a str,
    pub sessions: &'a [SecuritySessionView],
    pub connected_apps: &'a [ConnectedAppView],
    /// Registered devices (task #872).
    pub devices: &'a [SecurityDeviceView],
    /// Whether the browser being used is registered.
    pub current_device_registered: bool,
    /// Whether the browser being used has a device marker (if not, guidance is shown instead of the registration field).
    pub current_device_identified: bool,
    /// Whether passkey verification is still valid (if so, registration goes through as is).
    pub passkey_fresh: bool,
    /// Device name when returning from passkey verification (task #916). If the verification is fresh and this browser
    /// is not yet registered, the registration form is auto-submitted with this name (one press).
    pub resume_device_name: Option<&'a str>,
    /// Whether this organization's "unregistered device" notice is enabled.
    pub devices_alerts_enabled: bool,
    /// Registered authenticator app keys (task #892; listed as "Authenticator app" in the "Devices" section).
    pub approver_keys: &'a [SecurityApproverKeyView],
    /// Sign-in history (task #879). Newest first.
    pub sign_ins: &'a [SignInView],
    /// Link to older history (the `?history_before=` value). None on the last page.
    pub sign_ins_older: Option<i64>,
    /// Whether viewing older history (shows a link back to the top).
    pub sign_ins_paged: bool,
    /// Whether this organization uses SSH keys (task #885; the section is hidden if disabled).
    pub ssh_keys_enabled: bool,
    /// Registered SSH keys.
    pub ssh_keys: &'a [SecuritySshKeyView],
    /// Whether passkey verification is still valid (condition for registering/revoking SSH keys).
    pub ssh_keys_passkey_fresh: bool,
    /// "Status" (task #896). `None` if unreadable, in which case guidance replaces the section.
    pub status: Option<&'a SecurityStatusView>,
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
}

/// One sign-in history row (task #879). Text is held as keys and translated by the template.
pub struct SignInView {
    pub occurred_at: String,
    /// `user-security-signins-outcome-*`.
    pub outcome_key: &'static str,
    /// Whether it succeeded (changes the badge color).
    pub succeeded: bool,
    /// Reason for refusal (`user-security-signins-failure-*`). `None` on success.
    pub failure_key: Option<&'static str>,
    pub ip_address: String,
    /// Country code (empty when unknown or untrustworthy).
    pub country: String,
    /// Short summary like "Windows・Chrome" (empty if unknown).
    pub browser_summary: String,
    pub user_agent: String,
    /// Sign-in method (`user-security-signins-method-*`).
    pub method_keys: Vec<&'static str>,
    /// The app that started the refused sign-in (if known).
    pub attempted_app: String,
    pub current: bool,
    /// Whether it was a registered device (`None` means unknown).
    pub device_registered: Option<bool>,
    pub apps: Vec<SignInAppView>,
}

/// The app signed in to and how its refresh token was used (task #879).
pub struct SignInAppView {
    pub app_name: String,
    pub last_issued_at: String,
    pub refresh: Option<SignInRefreshView>,
}

/// How the refresh token was used. Source and self-identification are those of **whoever sent the refresh**.
pub struct SignInRefreshView {
    pub use_count: String,
    /// Empty if never refreshed.
    pub last_used_at: String,
    pub last_ip_address: String,
    pub last_browser_summary: String,
    pub last_user_agent: String,
    pub reuse_detected_at: String,
    /// `user-security-signins-refresh-state-*`.
    pub state_key: &'static str,
    pub active: bool,
    pub revoked_at: String,
}

/// Extracts a short "OS / browser" from the browser's self-identification (User-Agent) (for display; never for decisions).
///
/// The self-identification is self-reported and can be forged. The screen also shows the original string below the summary.
pub fn browser_summary(user_agent: &str) -> String {
    let ua = user_agent;
    let os = if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iOS") {
        Some("iOS")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    // Order matters: Edge, Opera and Samsung also include "Chrome", and Chrome also includes "Safari".
    let browser = if ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/") {
        Some("Edge")
    } else if ua.contains("OPR/") {
        Some("Opera")
    } else if ua.contains("SamsungBrowser/") {
        Some("Samsung Internet")
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        Some("Firefox")
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        Some("Chrome")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    match (os, browser) {
        (Some(o), Some(b)) => format!("{o}・{b}"),
        (Some(o), None) => o.to_string(),
        (None, Some(b)) => b.to_string(),
        (None, None) => String::new(),
    }
}

/// One row of the "SSH keys" section (task #885). Times stay as the RFC 3339 strings the api returned.
pub struct SecuritySshKeyView {
    pub id: String,
    pub name: String,
    pub key_type: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    pub created_at: String,
}

/// One row of the "Devices" section (task #872). Times stay as the RFC 3339 strings the api returned.
/// One "Authenticator app" row of the "Devices" section (task #892).
pub struct SecurityApproverKeyView {
    pub id: String,
    /// The app's self-reported device model name.
    pub device_name: String,
    /// Display of the key storage (`app-approver-level-*`).
    pub level_key: &'static str,
    pub registered_at: String,
    /// Last time used for approval (empty if none).
    pub last_used_at: String,
}

pub struct SecurityDeviceView {
    pub id: String,
    pub name: String,
    pub current: bool,
    pub user_agent: String,
    pub last_used_at: String,
    /// Country code (empty if unknown).
    pub last_country: String,
    pub expires_at: String,
}

/// Passkey list screen (`GET /account/passkey`). List of registered credentials with delete buttons.
#[derive(Template)]
#[template(path = "passkey_list.html")]
pub struct PasskeyListTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (ADR-0009 §6).
    pub tenant_prefix: &'a str,
    pub credentials: &'a [PasskeyCredentialInfo],
    /// CSRF synchronizer token of the delete form (`console_csrf_token`; task #587).
    pub csrf_token: &'a str,
    /// Banner when returning from the delete PRG (success/failure).
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
}

/// Passkey registration screen (`GET /account/passkey/register`). Starts the WebAuthn JS flow.
#[derive(Template)]
#[template(path = "passkey_register.html")]
pub struct PasskeyRegisterTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` prefix (ADR-0009 §6).
    pub tenant_prefix: &'a str,
    pub error_key: Option<&'a str>,
}

/// SAML SP (client) list/add screen (`GET /{tenant_id}/admin/saml-clients`).
#[derive(Template)]
#[template(path = "console/saml_service_providers.html")]
pub struct SamlServiceProvidersConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    /// IdP metadata download URL on the same web origin as the admin screen.
    pub idp_metadata_url: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub saved: bool,
    /// Whether right after an update (used to show the success banner).
    pub updated: bool,
    /// Whether right after a deletion (used to show the success banner).
    pub deleted: bool,
    /// Whether initial values were just applied from metadata import (used for the info banner and expanding the add panel).
    pub imported: bool,
    pub error_key: Option<&'a str>,
    pub providers: &'a [SamlServiceProviderView],
    pub values: &'a SamlServiceProviderFormValues,
}

/// Input values of the SAML SP (client) add form.
#[derive(Default)]
pub struct SamlServiceProviderFormValues {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: String,
    pub enabled: bool,
}

/// Authentication policy list/create/edit screen (`GET /{tenant_id}/admin/authentication-policies`, AP1).
///
/// The list and the create/edit form are on one screen (`?edit={id}` turns the same form into edit mode).
/// Updates **replace all fields**, so editing must show every current value in the form -- any field that
/// cannot be shown loses its condition the moment it is saved. That is why variable-length conditions
/// round-trip as text; the format lives in [`crate::authentication_policy_form`].
#[derive(Template)]
#[template(path = "console/authentication_policies.html")]
pub struct AuthenticationPoliciesConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    /// Default behaviour when no policy matches (`AUTH_POLICY_DEFAULT_EFFECT`). A policy's meaning is determined
    /// only in combination with this default, so always show it above the list.
    ///
    /// ⚠ **Render the tenant's value carried in the api's list response** (ADR-0058 §10). web holds no value --
    /// showing it from the startup snapshot would display the global value for all tenants. When the list could not
    /// be fetched (redisplay after input error, api failure) it is `None`, and no guessed value is shown.
    pub default_effect: Option<&'a str>,
    pub saved: bool,
    pub updated: bool,
    pub deleted: bool,
    pub error_key: Option<&'a str>,
    /// Policy ID being edited (`None` = create new).
    pub editing: Option<&'a str>,
    /// Whether to open the form section from the start (edit, redisplay after input error).
    pub form_open: bool,
    pub effect_options: &'a [&'a str],
    pub method_options: &'a [&'a str],
    pub values: &'a AuthenticationPolicyFormValues,
    pub policies: &'a [AuthenticationPolicyResponse],
}

impl AuthenticationPoliciesConsole<'_> {
    /// Translation key of the effect code. Unknown values show the code itself rather than passing through (when
    /// the api adds a new effect, it shows on screen in a way that makes the missing translation obvious).
    pub fn effect_label(&self, effect: &str) -> &'static str {
        match effect {
            "allow" => "admin-auth-policy-effect-allow",
            "deny" => "admin-auth-policy-effect-deny",
            "require_mfa" => "admin-auth-policy-effect-require-mfa",
            "require_specific_method" => "admin-auth-policy-effect-require-method",
            _ => "admin-auth-policy-effect-unknown",
        }
    }

    /// One-line description of what `require_specific_method` requires (empty string if none).
    pub fn required_methods_summary(&self, policy: &AuthenticationPolicyResponse) -> String {
        match &policy.effect_params {
            Some(params) => {
                let methods = params.methods.join(", ");
                if params.user_verification {
                    format!("{methods} +uv")
                } else {
                    methods
                }
            }
            None => String::new(),
        }
    }

    /// Summary of the conditions shown in the list. **No conditions = applies to everyone and every client**, so
    /// show wording that makes that obvious at a glance (a blank would read as "no condition configured").
    pub fn condition_summary(&self, policy: &AuthenticationPolicyResponse) -> String {
        let mut parts = Vec::new();
        if !policy.application_ids.is_empty() {
            parts.push(format!("app×{}", policy.application_ids.len()));
        }
        if !policy.user_ids.is_empty() {
            parts.push(format!("user×{}", policy.user_ids.len()));
        }
        if !policy.ip_cidrs.is_empty() {
            parts.push(format!("network×{}", policy.ip_cidrs.len()));
        }
        if !policy.time_windows.is_empty() {
            parts.push(format!("time×{}", policy.time_windows.len()));
        }
        if !policy.requested_acr.is_empty() {
            parts.push(format!("acr×{}", policy.requested_acr.len()));
        }
        if parts.is_empty() {
            self.messages.get("admin-auth-policy-condition-any")
        } else {
            parts.join(" / ")
        }
    }
}

/// Authentication policy form values (initial values when creating, current values when editing, redisplay on input error).
pub struct AuthenticationPolicyFormValues {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: String,
    pub enabled: bool,
    pub effect: String,
    pub methods: Vec<String>,
    pub user_verification: bool,
    /// Internal IDs of target apps (newline-separated).
    pub application_ids: String,
    pub user_ids: String,
    pub ip_cidrs: String,
    pub time_windows: String,
    pub requested_acr: String,
}

impl Default for AuthenticationPolicyFormValues {
    fn default() -> Self {
        Self {
            policy_code: String::new(),
            policy_name: String::new(),
            // Default is near the end (start from a value that does not disturb existing policies' evaluation order).
            priority: "100".to_string(),
            enabled: true,
            effect: "deny".to_string(),
            methods: Vec::new(),
            user_verification: false,
            application_ids: String::new(),
            user_ids: String::new(),
            ip_cidrs: String::new(),
            time_windows: String::new(),
            requested_acr: String::new(),
        }
    }
}

impl AuthenticationPolicyFormValues {
    pub fn is_effect(&self, effect: &str) -> bool {
        self.effect == effect
    }

    pub fn has_method(&self, code: &str) -> bool {
        self.methods.iter().any(|m| m == code)
    }
}

/// Account setup link screen (`GET /{tenant_id}/account-setup`; ADR-0062).
///
/// Opened while logged out. `token` is passed only to carry it in the form (not shown on screen).
#[derive(Template)]
#[template(path = "account_setup.html")]
pub struct AccountSetup<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub token: &'a str,
    /// Whose link this is (only when readable).
    pub email: Option<&'a str>,
    /// Whether the link allows registering a passkey.
    pub allows_passkey: bool,
    /// Shows that setup is finished.
    pub done: bool,
    /// Message key when the link is dead (reasons are not distinguished).
    pub fatal_key: Option<&'static str>,
    /// Message key shown when input must be redone.
    pub error_key: Option<&'static str>,
}
