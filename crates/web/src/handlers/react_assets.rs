//! React islands のビルド済みアセット配信。
//!
//! npm/Vite で生成した本物の React バンドルを `include_str!` で web バイナリへ同梱する。
//! これにより CSP の `script-src 'self'` を維持したまま、外部 CDN に依存せず全画面を hydrate できる。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

const APP_JS: &str = include_str!("../../assets/react/app.js");
const APP_JS_MAP: &str = include_str!("../../assets/react/app.js.map");

#[derive(Clone, Copy)]
enum ReactAssetKind {
    JavaScript,
    SourceMap,
}

impl ReactAssetKind {
    fn content_type(self) -> &'static str {
        match self {
            Self::JavaScript => "text/javascript; charset=utf-8",
            Self::SourceMap => "application/json; charset=utf-8",
        }
    }

    fn cache_control(self) -> &'static str {
        match self {
            // `react_bootstrap.html` references the bundle with a `?v={asset_version}`
            // query, so the URL changes on every deploy (cache busting) and the body
            // can be cached long-term.
            Self::JavaScript => "public, max-age=31536000, immutable",
            // The source map is referenced from inside the bundle without a version
            // query (stable URL), so keep its staleness bounded.
            Self::SourceMap => "public, max-age=86400",
        }
    }

    fn body(self) -> &'static str {
        match self {
            Self::JavaScript => APP_JS,
            Self::SourceMap => APP_JS_MAP,
        }
    }

    fn response(self) -> impl IntoResponse {
        (
            [
                (CONTENT_TYPE, self.content_type()),
                (CACHE_CONTROL, self.cache_control()),
            ],
            self.body(),
        )
    }
}

pub async fn app_js() -> impl IntoResponse {
    ReactAssetKind::JavaScript.response()
}

pub async fn app_js_map() -> impl IntoResponse {
    ReactAssetKind::SourceMap.response()
}
