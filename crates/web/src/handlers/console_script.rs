//! 管理コンソール共通スクリプトの配信。
//!
//! `assets/console.js` を `include_str!` で web バイナリへ同梱し、`/assets/console.js` として
//! 自オリジン配信する（CSP の `script-src 'self'` を維持したまま外部 CDN に依存しない。
//! `assets/app.css` と同じ方針）。共通レイアウト（`console/layout.html`）が読み込む。
//!
//! 中身は破壊的操作の確認ダイアログのみ。文言をインライン JS の文字列リテラルへ埋め込むのを
//! やめ、`data-confirm` 属性から読むための共通ハンドラを置く（理由はスクリプト側のコメント）。
//! React 画面用のバンドル（`/assets/react/app.js`）とは別物で、こちらはサーバレンダリングの
//! 管理コンソール全体に効く。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const CONSOLE_JS: &str = include_str!("../../assets/console.js");

pub async fn console_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // 参照 URL に `?v={asset_version}` が付きデプロイごとに変わるため長期キャッシュしてよい
            // （`stylesheet::app_css` と同じ理由）。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        CONSOLE_JS,
    )
}
