//! Serving of screen-specific scripts (SEC12).
//!
//! What used to be inline `<script>` in templates was split out into same-origin assets so that
//! `script-src 'unsafe-inline'` could be removed from the CSP. While inline is allowed, a single
//! reflected XSS would make the CSP useless as a defense.
//!
//! External assets were chosen over nonces because nonces would have to be threaded through every template
//! struct and handler, and `?v={asset_version}` allows long-term caching. Values the templates used to
//! embed (tenant prefix, translated wording) are passed via `data-*` attributes.
//!
//! The contents are `crates/web/assets/*.js` embedded with `include_str!` (same policy as `console.js`
//! and `submit-feedback.js`).

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const PASSKEY_LOGIN_JS: &str = include_str!("../../assets/passkey-login.js");
/// Shows "Continue in the app" only in Android browsers (task #892; appearance only).
pub(crate) const APP_APPROVAL_LOGIN_JS: &str = include_str!("../../assets/app-approval-login.js");
pub(crate) const PASSKEY_REGISTER_JS: &str = include_str!("../../assets/passkey-register.js");
pub(crate) const ACCOUNT_SETUP_JS: &str = include_str!("../../assets/account-setup.js");
pub(crate) const SHARE_LINK_JS: &str = include_str!("../../assets/share-link.js");
pub(crate) const PASSWORD_VISIBILITY_JS: &str = include_str!("../../assets/password-visibility.js");
pub(crate) const RP_LOGOUT_JS: &str = include_str!("../../assets/rp-logout.js");
pub(crate) const AUTO_SUBMIT_JS: &str = include_str!("../../assets/auto-submit.js");
pub(crate) const CLIENT_FORM_JS: &str = include_str!("../../assets/client-form.js");
pub(crate) const LOCAL_TIME_JS: &str = include_str!("../../assets/local-time.js");
/// Filters a list in place (a member's "available apps", etc.).
pub(crate) const LIST_FILTER_JS: &str = include_str!("../../assets/list-filter.js");
/// Filters the server-side list just by typing in the search box (account list; continuation of ADR-0065).
pub(crate) const LIVE_SEARCH_JS: &str = include_str!("../../assets/live-search.js");

/// The reference URL carries `?v={asset_version}`, which changes per deploy, so long-term caching is fine.
fn javascript(body: &'static str) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
}

pub async fn passkey_login_js() -> impl IntoResponse {
    javascript(PASSKEY_LOGIN_JS)
}

pub async fn app_approval_login_js() -> impl IntoResponse {
    javascript(APP_APPROVAL_LOGIN_JS)
}

pub async fn passkey_register_js() -> impl IntoResponse {
    javascript(PASSKEY_REGISTER_JS)
}

pub async fn account_setup_js() -> impl IntoResponse {
    javascript(ACCOUNT_SETUP_JS)
}

pub async fn share_link_js() -> impl IntoResponse {
    javascript(SHARE_LINK_JS)
}

pub async fn password_visibility_js() -> impl IntoResponse {
    javascript(PASSWORD_VISIBILITY_JS)
}

pub async fn rp_logout_js() -> impl IntoResponse {
    javascript(RP_LOGOUT_JS)
}

pub async fn auto_submit_js() -> impl IntoResponse {
    javascript(AUTO_SUBMIT_JS)
}

pub async fn client_form_js() -> impl IntoResponse {
    javascript(CLIENT_FORM_JS)
}

pub async fn local_time_js() -> impl IntoResponse {
    javascript(LOCAL_TIME_JS)
}

pub async fn list_filter_js() -> impl IntoResponse {
    javascript(LIST_FILTER_JS)
}

pub async fn live_search_js() -> impl IntoResponse {
    javascript(LIVE_SEARCH_JS)
}
