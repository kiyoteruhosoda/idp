//! web 共通スタイルシートと、assay の印の配信。
//!
//! `assets/app.css` を `include_str!` で web バイナリへ同梱し、`/assets/app.css` として
//! 自オリジン配信する。これにより CSP の `style-src 'self'` を維持したまま、外部 CDN に
//! 依存せず全画面へ共通デザインを適用できる。各テンプレートの <head> から
//! <link rel="stylesheet" href="/assets/app.css"> で読み込む。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const APP_CSS: &str = include_str!("../../assets/app.css");
pub(crate) const ASSAY_SVG: &str = include_str!("../../assets/assay.svg");

pub async fn app_css() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            // テンプレートは `?v={asset_version}` 付き URL で参照し、デプロイごとに URL 自体が
            // 変わる（キャッシュバスティング）。そのため長期キャッシュしてよい。
            // revalidate 方式は中間 CDN（Cloudflare）が max-age を上書きするため機能しない。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        APP_CSS,
    )
}

/// タブとアプリアイコンの印（`<link rel="icon">`）。SVG 1 枚で全サイズを賄うので、
/// サイズ別の PNG は置かない。CSP の `img-src 'self'` のまま自オリジンから配る。
pub async fn assay_svg() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            // app.css と同じく `?v={asset_version}` 付きで参照するため長期キャッシュしてよい。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        ASSAY_SVG,
    )
}
