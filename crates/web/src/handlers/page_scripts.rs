//! 画面固有スクリプトの配信（SEC12）。
//!
//! もとはテンプレートのインライン `<script>` だったものを自オリジンのアセットへ切り出し、
//! CSP から `script-src 'unsafe-inline'` を外せるようにした。インライン許容を残したままでは、
//! 反射型 XSS が 1 か所でもあれば CSP が防御にならない。
//!
//! nonce 方式ではなく外部アセット化を選んだのは、テンプレート構造体・ハンドラすべてに nonce を
//! 通す必要が無く、`?v={asset_version}` で長期キャッシュも効くため。テンプレート側が持っていた
//! 埋め込み値（テナントプレフィクス・翻訳済み文言）は `data-*` 属性で渡す。
//!
//! 中身は `crates/web/assets/*.js` を `include_str!` で同梱する（`console.js`・
//! `submit-feedback.js` と同じ方針）。

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::IntoResponse;

pub(crate) const PASSKEY_LOGIN_JS: &str = include_str!("../../assets/passkey-login.js");
pub(crate) const PASSKEY_REGISTER_JS: &str = include_str!("../../assets/passkey-register.js");
pub(crate) const PASSWORD_VISIBILITY_JS: &str = include_str!("../../assets/password-visibility.js");
pub(crate) const RP_LOGOUT_JS: &str = include_str!("../../assets/rp-logout.js");
pub(crate) const AUTO_SUBMIT_JS: &str = include_str!("../../assets/auto-submit.js");
pub(crate) const CLIENT_FORM_JS: &str = include_str!("../../assets/client-form.js");

/// 参照 URL に `?v={asset_version}` が付きデプロイごとに変わるため長期キャッシュしてよい。
fn javascript(body: &'static str) -> impl IntoResponse {
    (
        [
            (CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
}

pub async fn passkey_login_js() -> impl IntoResponse {
    javascript(PASSKEY_LOGIN_JS)
}

pub async fn passkey_register_js() -> impl IntoResponse {
    javascript(PASSKEY_REGISTER_JS)
}

pub async fn password_visibility_js() -> impl IntoResponse {
    javascript(PASSWORD_VISIBILITY_JS)
}

pub async fn rp_logout_js() -> impl IntoResponse {
    javascript(RP_LOGOUT_JS)
}

pub async fn auto_submit_js() -> impl IntoResponse {
    javascript(AUTO_SUBMIT_JS)
}

pub async fn client_form_js() -> impl IntoResponse {
    javascript(CLIENT_FORM_JS)
}
