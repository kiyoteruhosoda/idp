//! web が api の JSON 管理 API（`/admin/*`）から受け取るビューモデル（ADR-0007 §4）。
//!
//! これらは api の OpenAPI DTO（`ClientResponse` 等）と同じ JSON 形状を web 側で受けるための
//! 読み取り用構造体。api の管理 API は OpenAPI で公開される契約であり、web はその一消費者として
//! 自前のビューモデルで受ける（内部認証の真の契約は `idp-contracts` に置く）。整合は E2E で検証する。

use serde::Deserialize;

/// クライアント（RP）の公開表現（`GET /admin/clients`・`/admin/clients/{id}` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientView {
    pub id: String,
    pub client_id: String,
    pub client_type: String,
    pub client_status: String,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    #[allow(dead_code)]
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// 作成応答（`POST /admin/clients`）。`client_secret` は confidential のときのみ含まれる。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientCreatedView {
    #[serde(flatten)]
    pub client: ClientView,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// secret 再発行応答（`POST /admin/clients/{id}/secret`）。
#[derive(Debug, Clone, Deserialize)]
pub struct ClientSecretView {
    #[allow(dead_code)]
    pub client_id: String,
    pub client_secret: String,
}

/// 監査ログ 1 行（`GET /admin/audit-logs` の応答要素。設計仕様 §7）。
#[derive(Debug, Clone, Deserialize)]
pub struct AuditLogView {
    #[allow(dead_code)]
    pub id: i64,
    pub event_type: String,
    pub occurred_at: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub user_agent: Option<String>,
    pub result: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// api のエラー応答本文（`{ "error": code, "message": msg }`）。
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorBody {
    #[allow(dead_code)]
    pub error: String,
    pub message: String,
}

/// 署名鍵の公開表現（`GET /admin/signing-keys` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeyView {
    pub kid: String,
    pub algorithm: String,
    pub status: String,
    pub not_before: String,
    pub not_after: String,
    pub created_at: String,
}

/// SAML 連携アプリ（外部 IdP）の公開表現（`GET /admin/saml-providers` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct SamlProviderView {
    pub display_name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub enabled: bool,
}

/// SAML SP（クライアント）の公開表現（`GET /admin/saml-service-providers` の応答要素）。
#[derive(Debug, Clone, Deserialize)]
pub struct SamlServiceProviderView {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub enabled: bool,
}

/// 利用者作成応答（`POST /admin/users`）。`generated_password` は一度限り平文で返る（ADR-0009 §5）。
#[derive(Debug, Clone, Deserialize)]
pub struct UserCreatedView {
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub sub: String,
    pub generated_password: String,
}

/// メンバー一覧の 1 件（`GET /admin/members`。HOME / GUEST を問わない。ADR-0009 §3）。
#[derive(Debug, Clone, Deserialize)]
pub struct MemberView {
    pub user_id: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// `HOME` または `GUEST`。
    pub membership_type: String,
    /// `INVITED` または `ACTIVE`。
    pub status: String,
    /// 利用者アカウント自体の状態（`ACTIVE` / `DISABLED` / `LOCKED`）。不存在ユーザーは `None`。
    #[serde(default)]
    pub user_status: Option<String>,
}

/// 管理者によるパスワード再発行応答（`POST /admin/users/{id}/password-reset` ほか）。
/// `generated_password` は一度限り平文で返る（ADR-0009 §5）。
#[derive(Debug, Clone, Deserialize)]
pub struct UserPasswordResetView {
    #[allow(dead_code)]
    pub user_id: String,
    pub generated_password: String,
}

/// 招待作成応答（`POST /admin/invitations`）。`token` は一度限り平文で返る（ADR-0009 §3）。
#[derive(Debug, Clone, Deserialize)]
pub struct InvitationCreatedView {
    pub token: String,
    pub expires_at: String,
    /// 招待メール（承諾リンク）を送信できたか（MT17）。false なら手動でトークンを伝達する。
    pub email_sent: bool,
    /// 被招待者のメールアドレス（送信先の確認表示用）。
    pub invitee_email: String,
}

/// テナントの公開表現（`GET/PATCH /admin/settings/tenant` の応答。MT14）。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantView {
    pub id: String,
    pub name: String,
    /// 自己登録（`/auth/register`）を許可するか（SEC6。既定は無効）。
    #[serde(default)]
    pub self_registration_enabled: bool,
    /// `ACTIVE` または `DISABLED`。
    pub status: String,
}

/// テナント作成応答（`POST /admin/tenants`）。初期管理者パスワードは一度だけ表示する。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantCreatedView {
    pub id: String,
    #[serde(default)]
    pub parent_tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub self_registration_enabled: bool,
    pub status: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    pub admin_user_id: String,
    pub generated_password: String,
}

/// システム設定の公開表現（`GET/PUT /admin/system-settings` の応答。MT14）。
/// SMTP パスワードは平文を含まず、設定済みか否か（`smtp_password_set`）のみ。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuntimeSettingView {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub restart_required: bool,
    #[serde(default)]
    pub default_risk: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    /// 起動時に解決された有効値（非 secret のみ）。DB 更新後も再起動までは変わらない。
    #[serde(default)]
    pub value: Option<String>,
    /// 組み込み既定値（非 secret のみ）。
    #[serde(default)]
    pub default_value: Option<String>,
    /// 現在 DB に保存されている上書き値（非 secret のみ）。
    #[serde(default)]
    pub db_value: Option<String>,
    /// この画面（DB）から上書きできるか（`DB_MANAGED` かつ非 secret）。
    #[serde(default)]
    pub editable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemSettingsView {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password_set: bool,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
    #[serde(default)]
    pub runtime_settings: Vec<RuntimeSettingView>,
}
