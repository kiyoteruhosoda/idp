//! 送信中フィードバック用スクリプトの配信。
//!
//! `assets/submit-feedback.js` を `include_str!` で web バイナリへ同梱し、
//! `/assets/submit-feedback.js` として自オリジン配信する（CSP の `script-src 'self'` を維持したまま
//! 外部 CDN に依存しない。`assets/app.css`・`assets/console.js` と同じ方針）。
//!
//! 中身は「押したボタンにスピナーを出し、送信が終わるまで押せなくする」だけ（ADR-0021）。
//! 管理コンソール限定の `console.js` と違い、認証系画面（`page.html`）と管理コンソール
//! （`console/layout.html`）の両方が読み込む。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const SUBMIT_FEEDBACK_JS: &str = include_str!("../../assets/submit-feedback.js");

pub async fn submit_feedback_js() -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // 参照 URL に `?v={asset_version}` が付きデプロイごとに変わるため長期キャッシュしてよい
            // （`stylesheet::app_css` と同じ理由）。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        SUBMIT_FEEDBACK_JS,
    )
}
