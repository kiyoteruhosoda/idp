//! presentation 全体で使う共通 DTO（`〇〇Request` / `〇〇Response`）。
//! OpenAPI スキーマは `utoipa::ToSchema` から自動生成する（手書きしない）。

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub sub: String,
    pub status: String,
}

/// `GET /authorize` のクエリパラメータ（設計仕様 §4.2）。
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// `POST /login` のフォームパラメータ（設計仕様 §4.3）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// 内部認証 API（`POST /internal/authenticate`、ADR-0007 §3）のリクエスト。
///
/// web（ログイン画面）が資格情報・`auth_session_id` 参照・接続元情報（`X-Forwarded-For` 由来 IP・
/// User-Agent）を api へ転送する。`/internal/*` は外部公開しない内部 I/F のため OpenAPI（`ToSchema`）
/// には含めない。CSRF は `csrf_token`（`auth_session_id` 由来）を LoginService が検証する。
#[derive(Debug, Deserialize)]
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
/// Cookie 組み立て（Secure/HttpOnly/SameSite/TTL）とエラー文言のローカライズは呼び出し側（web）が
/// 担う（ADR-0007 §3）。
#[derive(Debug, Serialize)]
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
#[derive(Debug, Deserialize)]
pub struct InternalAdminAuthenticateRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// 管理コンソール内部認証 API のレスポンス。成功時は SSO セッション id を返す（code/redirect は無い）。
#[derive(Debug, Serialize)]
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

/// `POST /token` のフォームパラメータ（設計仕様 §4.4）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
}

/// OAuth 2.0 のエラーレスポンス（RFC 6749 §5.2）。
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// クライアント（RP）登録リクエスト（管理 API、設計仕様 §9.3）。
/// `client_id` は自動採番、`client_secret` は confidential のとき発行される（リクエストには含めない）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientRegisterRequest {
    pub app_name: String,
    /// `public` または `confidential`。
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    /// 省略時は既定（true）。public は常に PKCE 必須。
    #[serde(default)]
    pub require_pkce: Option<bool>,
}

/// クライアント部分更新リクエスト。指定した項目のみ更新する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientUpdateRequest {
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// `ACTIVE` または `DISABLED`。
    #[serde(default)]
    pub client_status: Option<String>,
}

/// 監査ログ検索のクエリパラメータ（管理 API、A3・設計仕様 §7）。
/// `from` / `to` は RFC3339（例 `2026-07-06T00:00:00Z`）。未指定の項目は絞り込まない。
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuditLogQueryParams {
    #[serde(default)]
    pub event_type: Option<String>,
    /// `success` または `failure`。
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// 監査ログ 1 行のレスポンス（設計仕様 §7 のログ項目）。
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogEntryResponse {
    pub id: i64,
    pub event_type: String,
    pub occurred_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// 利用者への権限付与リクエスト（管理 API、A2・ADR-0006）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantPermissionRequest {
    /// 付与する権限コード（例 `idp.admin`）。`permissions` マスタに存在すること。
    pub permission_code: String,
}

/// 利用者が保有する権限コードの一覧レスポンス（A2・ADR-0006）。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserPermissionsResponse {
    /// 対象利用者の内部 ID（UUID）。
    pub user_id: String,
    /// 保有する権限コード（順序は不定）。
    pub permission_codes: Vec<String>,
}

/// クライアントの公開表現（`client_secret_hash` は返さない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientResponse {
    pub id: String,
    pub client_id: String,
    pub client_type: String,
    pub client_status: String,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// 登録レスポンス。`client_secret` は confidential のときのみ、**この応答でのみ**平文で返る。
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientCreatedResponse {
    #[serde(flatten)]
    pub client: ClientResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// シークレット再発行レスポンス。平文はこの応答でのみ返る。
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSecretResponse {
    pub client_id: String,
    pub client_secret: String,
}

/// `GET /userinfo` のレスポンス（scope に応じてクレームを増減する、設計仕様 §4.7）。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
