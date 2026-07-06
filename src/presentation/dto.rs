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
