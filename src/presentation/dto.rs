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
