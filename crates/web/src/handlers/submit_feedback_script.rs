//! Serving of the in-progress feedback scripts.
//!
//! `assets/button-pending.js` (DOM work marking a button), `assets/submit-feedback.js`
//! (catches form submission and calls the former) and `assets/theme.js` (applies the color scheme) are
//! embedded into the web binary with `include_str!` and served from our own origin
//! (no dependency on an external CDN while keeping CSP `script-src 'self'`; same policy as `assets/app.css`
//! and `assets/console.js`).
//!
//! All they do is "show a spinner on the pressed button and disable it until processing ends" (ADR-0021).
//! Unlike `console.js`, which is admin-console only, both the auth screens (`page.html`) and the admin console
//! (`console/layout.html`) load them. **`button-pending.js` comes first** (`submit-feedback.js` and
//! the screen script that talks to the server via fetch (`assets/passkey-register.js`) call it).

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const BUTTON_PENDING_JS: &str = include_str!("../../assets/button-pending.js");
pub(crate) const THEME_JS: &str = include_str!("../../assets/theme.js");
pub(crate) const SUBMIT_FEEDBACK_JS: &str = include_str!("../../assets/submit-feedback.js");

fn javascript(body: &'static str) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // The reference URL carries `?v={asset_version}`, which changes per deploy, so long-term caching is fine
            // (same reason as `stylesheet::app_css`).
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
}

pub async fn button_pending_js() -> impl IntoResponse {
    javascript(BUTTON_PENDING_JS)
}

/// Script that sets the color scheme before the first paint (`assets/theme.js`). The choice is carried by
/// the `theme` cookie, so the response itself is the same for every user and can be cached long-term.
pub async fn theme_js() -> impl IntoResponse {
    javascript(THEME_JS)
}

pub async fn submit_feedback_js() -> impl IntoResponse {
    javascript(SUBMIT_FEEDBACK_JS)
}
