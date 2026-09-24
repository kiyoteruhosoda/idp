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
const ASSAY_192_PNG: &[u8] = include_bytes!("../../assets/icons/assay-192.png");
const ASSAY_512_PNG: &[u8] = include_bytes!("../../assets/icons/assay-512.png");
const ASSAY_MASKABLE_512_PNG: &[u8] = include_bytes!("../../assets/icons/assay-maskable-512.png");

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

/// ホーム画面のアイコン（管理コンソールのマニフェストが指す。`handlers::web_app_manifest`）。
///
/// タブの印は SVG 1 枚で足りるが、⚠ **Chrome のインストール条件は 192px と 512px の PNG**
/// で、SVG だけでは「このアプリはインストールできません」になる。絵は `assets/assay.svg` と
/// 同じ（Chrome の headless で描き出した）。maskable は地を全面に塗り、印を安全領域へ縮めたもの。
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
            // マニフェストが `?v={asset_version}` 付きで指すので長期キャッシュしてよい。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
}
