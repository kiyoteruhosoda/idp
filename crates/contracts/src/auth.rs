//! 内部認証 API（`/internal/authenticate*`、ADR-0007 §3）の DTO 契約。
//!
//! web（ログイン画面）→api の内部認証呼び出しで共有する。web が [`InternalAuthenticateRequest`] /
//! [`InternalAdminAuthenticateRequest`] を送信（serialize）し、api が受信（deserialize）する。応答は
//! `result` タグで判別し、成功時のみ SSO/redirect 情報を含む。Cookie 組み立て（Secure/HttpOnly/
//! SameSite/TTL）とエラー文言のローカライズは呼び出し側（web）が担う。
//!
//! `/internal/*` は外部公開しない内部 I/F のため OpenAPI（`utoipa::ToSchema`）には含めない。

use serde::{Deserialize, Serialize};

/// 内部認証 API（`POST /internal/authenticate`）のリクエスト。
///
/// web が資格情報・`auth_session_id` 参照・接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を
/// api へ転送する。CSRF は `csrf_token`（`auth_session_id` 由来）を api の LoginService が検証する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAuthenticateRequest {
    #[serde(default)]
    pub auth_session_id: Option<String>,
    pub username: String,
    pub password: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 内部認証 API のレスポンス。`result` タグで判別する。成功時のみ SSO/redirect 情報を返す。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAuthenticateResponse {
    /// 認証成功。`redirect_to`（code 付き RP URL）へ 302 し、`sso_session_id` を Cookie 化する。
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// AuthSession が無い・期限切れ（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// api 内部エラー。
    Internal,
}

/// 管理コンソール内部認証 API（`POST /internal/authenticate/admin`、ADR-0007 §3・§4）のリクエスト。
///
/// 管理ログインの CSRF は web 側で検証済み（ADR-0007 §4）のため本 API には含めない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalAdminAuthenticateRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 内部ログアウト API（`POST /internal/logout`、ADR-0007）のリクエスト。
///
/// web が管理コンソールのログアウトで、失効させたい SSO セッション id（Cookie 値）と接続元情報を転送する。
/// Cookie の失効は web が行い、api は DB のセッション削除と監査記録を担う。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalLogoutRequest {
    pub sso_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 管理コンソール内部認証 API のレスポンス。成功時は SSO セッション id を返す（code/redirect は無い）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalAdminAuthenticateResponse {
    /// 認証成功かつ `idp.admin` 保有。`sso_session_id` を Cookie 化して管理コンソールへ 302 する。
    Success {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// 資格情報は正しいが `idp.admin` 権限を保有しない。
    Forbidden,
    /// api 内部エラー。
    Internal,
}
