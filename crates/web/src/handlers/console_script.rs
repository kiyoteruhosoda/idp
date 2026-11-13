//! Serving of the admin console's shared script.
//!
//! `assets/console.js` is embedded into the web binary with `include_str!` and served from our own origin
//! as `/assets/console.js` (no dependency on an external CDN while keeping CSP `script-src 'self'`;
//! same policy as `assets/app.css`). Loaded by the shared layout (`console/layout.html`).
//!
//! Its only content is the confirm dialog for destructive operations. Instead of embedding the wording in
//! inline JS string literals, it provides a shared handler that reads `data-confirm` (see the script's comments for why).
//! It is separate from the bundle for React screens (`/assets/react/app.js`); this one applies to the whole
//! server-rendered admin console.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const CONSOLE_JS: &str = include_str!("../../assets/console.js");

pub async fn console_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // The reference URL carries `?v={asset_version}`, which changes per deploy, so long-term caching is fine
            // (same reason as `stylesheet::app_css`).
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        CONSOLE_JS,
    )
}
