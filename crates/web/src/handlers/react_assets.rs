//! React islands のビルド済みアセット配信。
//!
//! npm/Vite で生成した本物の React バンドルを `include_str!` で web バイナリへ同梱する。
//! これにより CSP の `script-src 'self'` を維持したまま、外部 CDN に依存せず全画面を hydrate できる。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const APP_JS: &str = include_str!("../../assets/react/app.js");
// ⚠ ソースマップ（`app.js.map`）は配らない（task #593）。本番で画面の元のソースを丸ごと渡す理由が無い。
//   バンドルの末尾の `sourceMappingURL` は残るが、開発者ツールが取りに来ても 404 になるだけ。

#[derive(Clone, Copy)]
enum ReactAssetKind {
    JavaScript,
}

impl ReactAssetKind {
    fn content_type(self) -> &'static str {
        match self {
            Self::JavaScript => "text/javascript; charset=utf-8",
        }
    }

    fn cache_control(self) -> &'static str {
        match self {
            // `react_bootstrap.html` references the bundle with a `?v={asset_version}`
            // query, so the URL changes on every deploy (cache busting) and the body
            // can be cached long-term.
            Self::JavaScript => "public, max-age=31536000, immutable",
        }
    }

    fn body(self) -> &'static str {
        match self {
            Self::JavaScript => APP_JS,
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
