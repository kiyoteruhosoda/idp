//! React islands のビルド済みアセット配信。
//!
//! npm/Vite で生成した本物の React バンドルを `include_str!` で web バイナリへ同梱する。
//! これにより CSP の `script-src 'self'` を維持したまま、外部 CDN に依存せず全画面を hydrate できる。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

const APP_JS: &str = include_str!("../../assets/react/app.js");
const APP_JS_MAP: &str = include_str!("../../assets/react/app.js.map");

pub async fn app_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        APP_JS,
    )
}

pub async fn app_js_map() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "application/json; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        APP_JS_MAP,
    )
}
