//! ベンダリングした UI アセット（Bootstrap・Font Awesome）の配信。
//!
//! photonest と同じ画面フォーマット（Bootstrap 5 + Font Awesome）を、CSP の
//! `default-src 'self'` を維持したまま提供するため、`assets/vendor/` 配下のファイルを
//! `include_str!` / `include_bytes!` で web バイナリへ同梱し `/assets/vendor/...` として
//! 自オリジン配信する（`stylesheet.rs` / `react_assets.rs` と同方針）。
//!
//! Font Awesome の CSS はフォントを相対パス `../webfonts/` で参照するため、
//! CSS を `/assets/vendor/fontawesome/css/all.min.css`、フォントを
//! `/assets/vendor/fontawesome/webfonts/{name}` で配信して相対参照を成立させる。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

const BOOTSTRAP_CSS: &str = include_str!("../../assets/vendor/bootstrap.min.css");
const BOOTSTRAP_JS: &str = include_str!("../../assets/vendor/bootstrap.bundle.min.js");
const FONTAWESOME_CSS: &str = include_str!("../../assets/vendor/fontawesome/css/all.min.css");
const FA_SOLID_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-solid-900.woff2");
const FA_REGULAR_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-regular-400.woff2");
const FA_BRANDS_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-brands-400.woff2");
const FA_V4COMPAT_WOFF2: &[u8] =
    include_bytes!("../../assets/vendor/fontawesome/webfonts/fa-v4compatibility.woff2");

/// バイナリ同梱のベンダアセットはデプロイ単位でしか変わらないため 1 日キャッシュさせる。
const VENDOR_CACHE_CONTROL: &str = "public, max-age=86400";

pub async fn bootstrap_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, VENDOR_CACHE_CONTROL),
        ],
        BOOTSTRAP_CSS,
    )
}

pub async fn bootstrap_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, VENDOR_CACHE_CONTROL),
        ],
        BOOTSTRAP_JS,
    )
}

pub async fn fontawesome_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (CACHE_CONTROL, VENDOR_CACHE_CONTROL),
        ],
        FONTAWESOME_CSS,
    )
}

fn woff2(body: &'static [u8]) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "font/woff2"),
            (CACHE_CONTROL, VENDOR_CACHE_CONTROL),
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
