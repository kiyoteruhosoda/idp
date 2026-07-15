//! web 共通スタイルシートの配信。
//!
//! `assets/app.css` を `include_str!` で web バイナリへ同梱し、`/assets/app.css` として
//! 自オリジン配信する。これにより CSP の `style-src 'self'` を維持したまま、外部 CDN に
//! 依存せず全画面へ共通デザインを適用できる。各テンプレートの <head> から
//! <link rel="stylesheet" href="/assets/app.css"> で読み込む。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

const APP_CSS: &str = include_str!("../../assets/app.css");

pub async fn app_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            // テンプレートが安定 URL を直接参照する。デプロイ後に更新を拾えるよう revalidate させる。
            (CACHE_CONTROL, "public, max-age=0, must-revalidate"),
        ],
        APP_CSS,
    )
}
