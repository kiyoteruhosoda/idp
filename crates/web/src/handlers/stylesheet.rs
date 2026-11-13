//! Serving of web's shared stylesheet and the assay mark.
//!
//! `assets/app.css` is embedded into the web binary with `include_str!` and served from our own origin
//! as `/assets/app.css`. This applies a shared design to every screen without depending on an external
//! CDN while keeping CSP `style-src 'self'`. Each template loads it from its <head> via
//! <link rel="stylesheet" href="/assets/app.css">.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const APP_CSS: &str = include_str!("../../assets/app.css");
pub(crate) const ASSAY_SVG: &str = include_str!("../../assets/assay.svg");
const ASSAY_192_PNG: &[u8] = include_bytes!("../../assets/icons/assay-192.png");
const ASSAY_512_PNG: &[u8] = include_bytes!("../../assets/icons/assay-512.png");
const ASSAY_MASKABLE_512_PNG: &[u8] = include_bytes!("../../assets/icons/assay-maskable-512.png");

pub async fn app_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            // Templates reference it by URL with `?v={asset_version}`, so the URL itself changes on every
            // deploy (cache busting). Long-term caching is therefore fine.
            // Revalidation does not work because the intermediate CDN (Cloudflare) overrides max-age.
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        APP_CSS,
    )
}

/// The tab and app icon mark (`<link rel="icon">`). A single SVG covers all sizes, so
/// no per-size PNGs are provided. Served from our own origin under CSP `img-src 'self'`.
pub async fn assay_svg() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            // Referenced with `?v={asset_version}` like app.css, so long-term caching is fine.
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        ASSAY_SVG,
    )
}

/// Home screen icon (pointed to by the admin console manifest; `handlers::web_app_manifest`).
///
/// A single SVG suffices for the tab mark, but ⚠ **Chrome's install criteria require 192px and 512px PNGs**,
/// and with SVG only it says "this app cannot be installed". The picture is the same as `assets/assay.svg`
/// (rendered with headless Chrome). The maskable one fills the whole background and shrinks the mark into the safe zone.
pub async fn assay_192_png() -> impl IntoResponse {
    png(ASSAY_192_PNG)
}

pub async fn assay_512_png() -> impl IntoResponse {
    png(ASSAY_512_PNG)
}

pub async fn assay_maskable_512_png() -> impl IntoResponse {
    png(ASSAY_MASKABLE_512_PNG)
}

fn png(bytes: &'static [u8]) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/png"),
            // The manifest points to it with `?v={asset_version}`, so long-term caching is fine.
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
}
