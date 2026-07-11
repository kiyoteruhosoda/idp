//! web が受け取るフォーム DTO。

use serde::Deserialize;

/// ログインフォーム（`POST /login`）。
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// TOTP 確認フォーム（`POST /account/mfa/totp/setup`）。
#[derive(Debug, Deserialize)]
pub struct TotpConfirmForm {
    /// 認証アプリから入力した 6 桁コード。
    pub code: String,
}

/// 同意フォーム（`POST /consent`、F3）。
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub auth_session_id: String,
    pub csrf_token: String,
    /// `approve` または `deny`。
    pub action: String,
}

/// 強制パスワード変更フォーム（`POST /password-change`、ADR-0009 §5）。ログインフロー中
/// （パスワード検証済み・SSO 未発行）の `auth_session_id` を前提とする。
#[derive(Debug, Deserialize)]
pub struct PasswordChangeForm {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}

/// 管理コンソールの強制パスワード変更フォーム（`POST /admin/password-change`、ADR-0009 §5）。
/// 管理ログインは一時状態を持たないため `username` を含めフルに再送する。
#[derive(Debug, Deserialize)]
pub struct AdminPasswordChangeForm {
    pub username: String,
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}
