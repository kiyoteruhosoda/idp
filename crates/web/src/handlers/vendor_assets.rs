//! Serving of vendored UI assets (Bootstrap, Font Awesome).
//!
//! To provide the same screen format as photonest (Bootstrap 5 + Font Awesome) while keeping CSP
//! `default-src 'self'`, files under `assets/vendor/` are embedded into the web binary with
//! `include_str!` / `include_bytes!` and served from our own origin as `/assets/vendor/...`
//! (same policy as `stylesheet.rs` / `react_assets.rs`).
//!
//! Font Awesome's CSS references fonts via the relative path `../webfonts/`, so
//! the CSS is served at `/assets/vendor/fontawesome/css/all.min.css` and the fonts at
//! `/assets/vendor/fontawesome/webfonts/{name}` so that the relative references resolve.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const BOOTSTRAP_CSS: &str = include_str!("../../assets/vendor/bootstrap.min.css");
pub(crate) const BOOTSTRAP_JS: &str = include_str!("../../assets/vendor/bootstrap.bundle.min.js");
pub(crate) const FONTAWESOME_CSS: &str =
    include_str!("../../assets/vendor/fontawesome/css/all.min.css");
const FA_SOLID_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-solid-900.woff2");
const FA_REGULAR_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-regular-400.woff2");
const FA_BRANDS_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-brands-400.woff2");
const FA_V4COMPAT_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-v4compatibility.woff2");

/// CSS/JS referenced from templates by URLs carrying `?v={asset_version}`. The URL changes on every deploy
/// (cache busting), so long-term caching is fine.
const VERSIONED_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// Webfonts referenced by relative path from Font Awesome's CSS cannot carry a version query
/// (stable URLs), so the update delay is capped at one day.
const WEBFONT_CACHE_CONTROL: &str = "public, max-age=86400";

pub async fn bootstrap_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, VERSIONED_CACHE_CONTROL),
        ],
        BOOTSTRAP_CSS,
    )
}

pub async fn bootstrap_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, VERSIONED_CACHE_CONTROL),
        ],
        BOOTSTRAP_JS,
    )
}

pub async fn fontawesome_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, VERSIONED_CACHE_CONTROL),
        ],
        FONTAWESOME_CSS,
    )
}

fn woff2(body: &'static [u8]) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "font/woff2"),
            (CACHE_CONTROL, WEBFONT_CACHE_CONTROL),
        ],
        body,
    )
}

pub async fn fa_solid_woff2() -> impl IntoResponse {
    woff2(FA_SOLID_WOFF2)
}

pub async fn fa_regular_woff2() -> impl IntoResponse {
    woff2(FA_REGULAR_WOFF2)
}

pub async fn fa_brands_woff2() -> impl IntoResponse {
    woff2(FA_BRANDS_WOFF2)
}

pub async fn fa_v4compatibility_woff2() -> impl IntoResponse {
    woff2(FA_V4COMPAT_WOFF2)
}
