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
    /// 認証成功かつ同意済み。`redirect_to`（code 付き RP URL）へ 302 し、`sso_session_id` を Cookie 化する。
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// 認証成功だが同意が必要。`auth_session_id` Cookie を発行して `/consent` へ 302 する。
    /// `sso_session_id` も発行する（SSO Cookie をセットするため）。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// パスワード認証成功だが MFA（TOTP）が設定済み。TOTP 入力画面 `/mfa/totp` へ誘導する。
    /// `auth_session_id` Cookie はそのまま維持する（MFA 検証で使う）。
    MfaRequired {
        auth_session_id: String,
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

/// TOTP セットアップ開始 API（`POST /internal/mfa/totp/setup`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpSetupRequest {
    /// SSO セッション Cookie の生値（web が転送）。
    pub sso_session_id: String,
    /// 認証アプリに表示するアカウント名（通常はメールアドレスまたはユーザー名）。
    pub account_name: String,
}

/// TOTP セットアップ開始 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpSetupResponse {
    /// セットアップ開始成功。QR URI と生シークレット（base32）を返す。
    Ok {
        /// `otpauth://totp/...` URI。QR コード生成に使う。
        totp_uri: String,
        /// base32 エンコードされたシークレット。QR が使えないユーザーへ直接表示する。
        secret_base32: String,
    },
    /// すでに有効な TOTP が設定済み（再セットアップ不可。先に削除が必要）。
    AlreadyConfigured,
    /// SSO セッションが無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// TOTP 確認 API（`POST /internal/mfa/totp/confirm`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpConfirmRequest {
    pub sso_session_id: String,
    /// ユーザーが認証アプリから入力した 6 桁コード。
    pub code: String,
}

/// TOTP 確認 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpConfirmResponse {
    Ok,
    InvalidCode,
    NotFound,
    AlreadyConfigured,
    SessionExpired,
    Internal,
}

/// TOTP 削除 API（`POST /internal/mfa/totp/delete`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalTotpDeleteRequest {
    pub sso_session_id: String,
}

/// TOTP 削除 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalTotpDeleteResponse {
    Ok,
    SessionExpired,
    Internal,
}

/// ログイン TOTP 検証 API（`POST /internal/mfa/totp/verify`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalVerifyTotpRequest {
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// ログイン TOTP 検証 API のレスポンス。成功系は `InternalAuthenticateResponse` と同等。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalVerifyTotpResponse {
    Success {
        redirect_to: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    SessionExpired,
    CsrfMismatch,
    InvalidCode,
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

/// 同意画面情報 API（`GET /internal/consent-info`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentInfoRequest {
    pub auth_session_id: String,
}

/// 同意画面情報 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentInfoResponse {
    /// セッションが有効。同意画面に必要な情報を返す。
    Ok {
        auth_session_id: String,
        client_name: String,
        client_id: String,
        /// 同意を求めるスコープ（`openid` は除く）。
        requested_scopes: Vec<String>,
    },
    /// AuthSession が無い・期限切れ・認証済みユーザー未設定（`/authorize` からやり直し）。
    SessionExpired,
}

/// 同意承認 API（`POST /internal/consent/approve`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentApproveRequest {
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 同意承認 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentApproveResponse {
    /// 同意付与・code 発行成功。`redirect_to`（code 付き RP URL）へ 302 する。
    Success { redirect_to: String },
    /// AuthSession が無い・期限切れ。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}

/// 同意拒否 API（`POST /internal/consent/deny`）のリクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalConsentDenyRequest {
    pub auth_session_id: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 同意拒否 API のレスポンス。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum InternalConsentDenyResponse {
    /// 拒否処理完了。`redirect_to`（`access_denied` エラー付き RP URL）へ 302 する。
    Ok { redirect_to: String },
    /// AuthSession が無い・期限切れ（RP へのリダイレクトができない）。
    SessionExpired,
    /// api 内部エラー。
    Internal,
}
