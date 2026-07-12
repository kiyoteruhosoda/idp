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
    /// `prompt` パラメータ（OIDC Core §3.1.2.1）: `none` / `login` / `consent` / `select_account`。
    pub prompt: Option<String>,
    /// `max_age` パラメータ（OIDC Core §3.1.2.1）: SSO セッションの auth_time からの最大経過秒数。
    pub max_age: Option<u64>,
}

/// `POST /login` のフォームパラメータ（設計仕様 §4.3）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

// 内部認証 API（`/internal/authenticate*`）の DTO は api サーバと web クライアントで共有するため
// `idp-contracts` crate に定義する（ADR-0007 §6）。handler は `idp_contracts::auth::*` を用いる。

/// `POST /token` のフォームパラメータ（設計仕様 §4.4・§9.1）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    /// `refresh_token` grant 専用。
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: String,
    /// `offline_access` scope を要求した場合のみ返却する。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
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
    /// RP-initiated logout のリダイレクト先（登録済みのもののみ許可）。
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// front-channel logout URI（OIDC front-channel logout 1.0）。
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    /// back-channel logout URI（OIDC back-channel logout 1.0）。
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
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
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
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
    /// 付与する権限コード（例 `idp.tenant.admin`）。`permissions` マスタに存在すること。
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
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

/// 署名鍵の公開表現（秘密鍵・暗号化鍵は含めない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct SigningKeyResponse {
    pub kid: String,
    /// `RS256` または `ES256`。
    pub algorithm: String,
    /// `ACTIVE` または `RETIRED`。
    pub status: String,
    /// RFC3339 文字列。
    pub not_before: String,
    /// RFC3339 文字列。
    pub not_after: String,
    /// RFC3339 文字列。
    pub created_at: String,
}

/// 新規署名鍵の生成リクエスト（`POST /admin/signing-keys`）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct GenerateSigningKeyRequest {
    /// `RS256` または `ES256`。
    pub algorithm: String,
}

// --- テナント管理（ADR-0009 §5・§6。`idp.system.admin` 必須） --------------------------------

/// 子テナント作成リクエスト（`POST /{tenant_id}/admin/tenants`）。`id`（UUID）はシステムが自動採番する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// テナント表示名。一意制約なし・URL には使わない。
    pub name: String,
    /// 初期管理者のメールアドレス。新テナントを所属元とし新テナント scope の `idp.tenant.admin` を
    /// 付与した管理者ユーザーを生成する。パスワードは自動生成し `generated_password` で一度だけ返す。
    pub admin_email: String,
}

/// 子テナント部分更新リクエスト（`PATCH /{tenant_id}/admin/tenants/{child_id}`）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// `ACTIVE` または `DISABLED`。
    #[serde(default)]
    pub status: Option<String>,
}

/// テナントの公開表現。
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantResponse {
    pub id: String,
    /// 作成元テナント。root のみ `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_tenant_id: Option<String>,
    pub name: String,
    /// `ACTIVE` または `DISABLED`。
    pub status: String,
    /// 自己登録（`/auth/register`）を許可するか（SEC6。既定は無効）。
    pub self_registration_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// テナント作成レスポンス。`generated_password` は初期管理者の自動生成パスワードで、**この応答でのみ**
/// 平文で返る（ログ・監査には出さない。ADR-0009 §5）。
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantCreatedResponse {
    #[serde(flatten)]
    pub tenant: TenantResponse,
    /// 生成された初期管理者ユーザーの内部 ID（UUID）。
    pub admin_user_id: String,
    /// 初期管理者の自動生成パスワード（平文。一度限り）。
    pub generated_password: String,
}

/// 設定画面の自テナント表示名更新リクエスト（`PATCH /{tenant_id}/admin/settings/tenant`。MT14）。
/// `idp.tenant.admin` が自テナントの表示名だけを変更する（`status`・`parent_tenant_id` は不変）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantSettingsRequest {
    pub name: String,
    /// 自己登録トグル（SEC6）。省略時は現状維持。
    #[serde(default)]
    pub self_registration_enabled: Option<bool>,
}

// --- システム設定（SMTP 等。root/idp.system.admin のみ。MT14） -----------------------------

/// システム設定の公開表現（`GET/PUT /{tenant_id}/admin/system-settings`）。SMTP パスワードは
/// 平文を返さず、設定済みか否か（`smtp_password_set`）のみを返す。
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemSettingsResponse {
    pub smtp_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_port: Option<u16>,
    pub smtp_username: String,
    /// SMTP パスワードが設定済みか（平文は返さない）。
    pub smtp_password_set: bool,
    pub smtp_from_address: String,
    pub smtp_use_tls: bool,
}

/// システム設定の更新リクエスト（`PUT /{tenant_id}/admin/system-settings`）。`smtp_password` は
/// `None`（未指定）= 現行維持、`Some("")` = 消去、`Some(x)` = 設定（暗号化して保存する）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSystemSettingsRequest {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
}

// --- 利用者作成（ADR-0009 §5・§6。`idp.tenant.admin` 必須） -----------------------------------

/// 管理者による利用者作成リクエスト（`POST /{tenant_id}/admin/users`）。パスワードは自動生成する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// 利用者作成レスポンス。`generated_password` は**この応答でのみ**平文で返る（ログ・監査には出さない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserCreatedResponse {
    pub user_id: String,
    pub sub: String,
    /// 自動生成パスワード（平文。一度限り）。
    pub generated_password: String,
}

// --- メンバー・招待（ADR-0009 §3・§6） --------------------------------------------------------

/// メンバー一覧の 1 件（`GET /{tenant_id}/admin/members`）。HOME / GUEST を問わない。
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberResponse {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `HOME` または `GUEST`。
    pub membership_type: String,
    /// `INVITED` または `ACTIVE`。
    pub status: String,
}

/// ゲスト招待作成リクエスト（`POST /{tenant_id}/admin/invitations`）。被招待者は所属元が他テナントの
/// 既存利用者で、内部 ID で指定する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// 被招待利用者の内部 ID（UUID）。
    pub user_id: String,
}

/// 招待作成レスポンス。`token` は平文の招待トークンで、**この応答でのみ**返る（メール未達時に管理者が
/// 被招待者へ別途通知する。ログ・監査には出さない。ADR-0009 §3）。
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationCreatedResponse {
    pub token: String,
    /// 招待の失効時刻（RFC3339）。
    pub expires_at: String,
    /// 招待メール（承諾リンク）を被招待者へ送信できたか（MT17）。SMTP 未設定・送信失敗は false
    /// （招待は成立しており、管理者が token を手動で伝達する）。
    pub email_sent: bool,
    /// 被招待者のメールアドレス（送信先の確認表示用）。
    pub invitee_email: String,
}

/// 招待承諾リクエスト（`POST /{tenant_id}/invitations/accept`）。ログイン済み利用者がトークンを提示する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptInvitationRequest {
    pub token: String,
}
