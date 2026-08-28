//! 処理中フィードバック用スクリプトの配信。
//!
//! `assets/button-pending.js`（ボタンへ印を付ける DOM 操作）・`assets/submit-feedback.js`
//! （フォーム送信を捕まえて前者を呼ぶ）・`assets/theme.js`（配色の適用）を `include_str!` で
//! web バイナリへ同梱し、自オリジン配信する
//! （CSP の `script-src 'self'` を維持したまま外部 CDN に依存しない。`assets/app.css`・
//! `assets/console.js` と同じ方針）。
//!
//! 中身は「押したボタンにスピナーを出し、処理が終わるまで押せなくする」だけ（ADR-0021）。
//! 管理コンソール限定の `console.js` と違い、認証系画面（`page.html`）と管理コンソール
//! （`console/layout.html`）の両方が読み込む。**`button-pending.js` が先**（`submit-feedback.js` と、
//! fetch でサーバと話す画面スクリプト（`assets/passkey-register.js`）がこれを呼ぶ）。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const BUTTON_PENDING_JS: &str = include_str!("../../assets/button-pending.js");
pub(crate) const THEME_JS: &str = include_str!("../../assets/theme.js");
pub(crate) const SUBMIT_FEEDBACK_JS: &str = include_str!("../../assets/submit-feedback.js");

fn javascript(body: &'static str) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            // 参照 URL に `?v={asset_version}` が付きデプロイごとに変わるため長期キャッシュしてよい
            // （`stylesheet::app_css` と同じ理由）。
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
}

pub async fn button_pending_js() -> impl IntoResponse {
    javascript(BUTTON_PENDING_JS)
}

/// 配色を最初の描画より前に立てるスクリプト（`assets/theme.js`）。選択は `theme` Cookie が
/// 運ぶため、応答そのものは利用者によらず同じで、長期キャッシュしてよい。
pub async fn theme_js() -> impl IntoResponse {
    javascript(THEME_JS)
}

pub async fn submit_feedback_js() -> impl IntoResponse {
    javascript(SUBMIT_FEEDBACK_JS)
}
