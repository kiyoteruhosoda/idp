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
    /// 検証メールを送出したか（SEC6b）。`true` の場合、確認リンクを踏むまでログインできない。
    /// SMTP 未設定時は `false`（アカウントは作成済みだが検証は後追い）。
    pub email_verification_required: bool,
}

/// メール検証リンクの消費（SEC6b）。平文トークンを受け取り `email_verified` を立てる。
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
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
    /// `acr_values` パラメータ（OIDC Core §3.1.2.1）: RP が要求する認証コンテキストクラス
    /// （空白区切り。G12）。**要求は保証ではない** —— 認証ポリシーの `requested_acr` 条件（AP3）が
    /// 参照するだけで、満たせない要求でエラーにはしない（同 §3.1.2.1 の voluntary な扱い）。
    pub acr_values: Option<String>,
    /// `login_hint` パラメータ（OIDC Core §3.1.2.1）: ログイン画面へ事前入力する識別子（G12）。
    pub login_hint: Option<String>,
    /// `ui_locales` パラメータ（OIDC Core §3.1.2.1）: RP が要求する表示言語（空白区切りの
    /// BCP47 タグ。G12）。
    pub ui_locales: Option<String>,
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
    /// `client_secret_post` のクライアント secret（RFC 6749 §2.3.1。G3）。`Authorization: Basic`
    /// との併用は `invalid_request`。
    pub client_secret: Option<String>,
    /// `refresh_token` grant 専用。
    pub refresh_token: Option<String>,
    /// `client_credentials` grant で要求する scope（空白区切り。G4）。
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// 利用者を認証した grant でのみ返却する（`client_credentials` は利用者が居ないため省略。G4）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
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
    /// サーバ間（M2M）連携で `client_credentials` grant を許可するか（G4。既定 false）。
    /// confidential クライアントのみ有効。
    #[serde(default)]
    pub allow_client_credentials: Option<bool>,
    /// クライアント認証方式（G3）。`client_secret_basic`（既定）または `client_secret_post`。
    /// confidential クライアントのみ指定できる。
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
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
    /// `client_credentials` grant の許可（G4）。confidential クライアントのみ有効。
    #[serde(default)]
    pub allow_client_credentials: Option<bool>,
    /// クライアント認証方式（G3）。`client_secret_basic` または `client_secret_post`。
    /// confidential クライアントのみ変更できる。
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
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

/// エラー・警告ログ検索のクエリパラメータ（管理 API。`log` テーブル）。
/// `from` / `to` は RFC3339（例 `2026-07-06T00:00:00Z`）。未指定の項目は絞り込まない。
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ApplicationLogQueryString {
    /// `ERROR` または `WARN`。
    #[serde(default)]
    pub level: Option<String>,
    /// `api` または `web`。
    #[serde(default)]
    pub service: Option<String>,
    /// 出力元モジュールパスの前方一致（例 `idp_api::presentation`）。
    #[serde(default)]
    pub target: Option<String>,
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
/// 作成者自身が新テナントのブートストラップ管理者（ACTIVE GUEST + `idp.tenant.admin`）になるため、
/// 初期管理者メールは受け取らない（ADR-0009 §4）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// テナント表示名。一意制約なし・URL には使わない。
    pub name: String,
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

/// ランタイム設定の解決結果。出所・安全属性に加え、非 secret キーは表示用に**起動時に解決された
/// 有効値**（`value`）・組み込み既定値（`default_value`）・DB 上書き値（`db_value`）を返す。
/// secret キーはいずれも `None`（平文を外へ出さない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct RuntimeSettingResponse {
    pub key: String,
    pub owner: String,
    pub source: String,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: String,
    /// `SAFE` または `NEEDS_ACTION`。secret の平文・fingerprint は含まない。
    pub status: String,
    /// 判定理由。secret の平文・fingerprint は含まない。
    pub reason: String,
    /// この設定が何に使われるかの説明（運用者向け）。
    pub description: String,
    /// 起動時に解決された有効値（非 secret のみ）。DB 更新後も再起動までは変わらない。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// 組み込み既定値（非 secret のみ）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// 現在 DB に保存されている上書き値（非 secret のみ。未設定は `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_value: Option<String>,
    /// この画面（DB）から上書きできるか（`owner == DB_MANAGED` かつ非 secret）。
    pub editable: bool,
    /// **保存済みだが実行中の api へ未反映**か（MT27）。DB に保存された値と、api が起動時に
    /// 解決した有効値がずれている状態を指す。上書きの**解除**が未反映の場合も `true`。
    pub pending_restart: bool,
    /// web も消費するキーか（ADR-0013）。`true` のキーは反映に **api と web の両方**の再起動が要る。
    pub shared_with_web: bool,
}

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
    #[serde(default)]
    pub runtime_settings: Vec<RuntimeSettingResponse>,
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

/// ランタイム設定の DB 上書き更新リクエスト（`PUT /{tenant_id}/admin/system-settings/runtime`）。
/// `value` が `None` または空文字列のときは上書きを解除する（既定値・環境変数へ戻る）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuntimeSettingRequest {
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
}

/// 再起動要求の受理応答（`POST /{tenant_id}/admin/restart`。ADR-0017）。
///
/// 応答を返した**あと**に停止するため、これは「受理した」であって「再起動が終わった」ではない。
#[derive(Debug, Serialize, ToSchema)]
pub struct RestartServiceResponse {
    /// 停止するサービス名（現状は常に `api`）。
    pub service: String,
    pub restarting: bool,
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

/// 利用者の状態更新リクエスト（`PATCH /{tenant_id}/admin/users/{user_id}`）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserStatusRequest {
    /// `ACTIVE` または `DISABLED`（`LOCKED` は管理操作では設定できない）。
    pub status: String,
}

/// 管理者による利用者プロフィール更新リクエスト（`PATCH /{tenant_id}/admin/users/{user_id}/profile`。
/// MT25）。省略したフィールドは変更しない（部分更新）。`preferred_username` はログイン識別子であり、
/// 変更するとその利用者のログイン名が変わる（空文字での解除は 400）。`name` に空文字を渡すと
/// 表示名を解除する。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserProfileRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// 管理者によるパスワード再発行レスポンス。`generated_password` は**この応答でのみ**平文で返る
/// （`must_change_password` が設定され、本人が次回ログインで変更する。ログ・監査には出さない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserPasswordResetResponse {
    pub user_id: String,
    /// 自動生成パスワード（平文。一度限り）。
    pub generated_password: String,
}

/// ゲストメンバーシップの状態更新リクエスト（`PATCH /{tenant_id}/admin/members/{user_id}`。MT24）。
/// 受け付けるのは `SUSPENDED`（一時停止）と `ACTIVE`（再開）のみ。`INVITED` は招待フローが管理する
/// 状態のため、ここからは設定できない。
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMemberStatusRequest {
    /// `SUSPENDED` = 一時停止 / `ACTIVE` = 再開。
    pub status: String,
}

/// 管理者による MFA 解除レスポンス（MT21）。何を外したかだけを返し、シークレット・
/// クレデンシャルの内容は含めない。未設定でも成功（すべて `false` / `0`）になる。
#[derive(Debug, Serialize, ToSchema)]
pub struct UserMfaResetResponse {
    pub user_id: String,
    /// TOTP 設定が存在して削除されたか。
    pub totp_removed: bool,
    /// 削除した Passkey（WebAuthn クレデンシャル）の件数。
    pub passkeys_removed: u64,
}

/// 子テナント管理者のパスワード再発行リクエスト
/// （`POST /{tenant_id}/admin/tenants/{child_id}/admin-password-reset`）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct TenantAdminPasswordResetRequest {
    /// 対象利用者（子テナント所属）のメールアドレス。
    pub email: String,
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
    /// 利用者アカウント自体の状態（`ACTIVE` / `DISABLED` / `LOCKED`）。不存在ユーザーは `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_status: Option<String>,
}

/// 一覧のページングクエリ（`GET /{tenant_id}/admin/clients`・`.../tenants`。G7）。
///
/// 絞り込み条件を持たない一覧で共有する。絞り込みのある一覧（members）は固有の型を持つ。
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct PageQueryParams {
    /// 1 ページの件数。未指定は 50、上限 200（超過分は上限へ丸める）。
    #[serde(default)]
    pub limit: Option<i64>,
    /// 読み飛ばす件数。未指定は 0。
    #[serde(default)]
    pub offset: Option<i64>,
}

/// クライアント一覧のレスポンス（`GET /{tenant_id}/admin/clients`。G7）。
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientListResponse {
    pub clients: Vec<ClientResponse>,
    /// `limit` / `offset` を無視した該当総数。画面が「全 N 件」と次ページの有無を確定できる。
    pub total: i64,
    /// 実際に適用された値（クランプ後）。要求値をそのまま返さないのは、上限で丸めた結果を
    /// 呼び出し側がページ送りの計算にそのまま使えるようにするため。
    pub limit: i64,
    pub offset: i64,
}

/// 子テナント一覧のレスポンス（`GET /{tenant_id}/admin/tenants`。G7）。
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantListResponse {
    pub tenants: Vec<TenantResponse>,
    /// `limit` / `offset` を無視した該当総数。
    pub total: i64,
    /// 実際に適用された値（クランプ後）。
    pub limit: i64,
    pub offset: i64,
}

/// メンバー一覧のクエリパラメータ（`GET /{tenant_id}/admin/members`。MT22）。
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct MemberListQueryParams {
    /// 絞り込み語。メールアドレス・氏名の**部分一致**（大文字小文字を無視）。未指定・空は絞り込まない。
    #[serde(default)]
    pub q: Option<String>,
    /// 1 ページの件数。未指定は 50、上限 200（超過分は上限へ丸める）。
    #[serde(default)]
    pub limit: Option<i64>,
    /// 読み飛ばす件数。未指定は 0。
    #[serde(default)]
    pub offset: Option<i64>,
}

/// メンバー一覧のレスポンス（`GET /{tenant_id}/admin/members`。MT22）。
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberListResponse {
    pub members: Vec<MemberResponse>,
    /// `limit` / `offset` を無視した該当総数。画面が「全 N 件」と次ページの有無を確定できる。
    pub total: i64,
    /// 実際に適用された値（クランプ後）。要求値をそのまま返さないのは、上限で丸めた結果を
    /// 呼び出し側がページ送りの計算にそのまま使えるようにするため。
    pub limit: i64,
    pub offset: i64,
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

/// 認証ポリシー 1 件（ユーザー認証・認証ポリシー仕様書 §7）。
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationPolicyResponse {
    pub id: String,
    pub policy_code: String,
    pub policy_name: String,
    /// 評価順（昇順 = 小さいほど優先）。
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`。
    pub effect: String,
    /// `require_specific_method` の要求内容（他の効果では `null`。AP3）。
    pub effect_params: Option<RequiredMethodsDto>,
    /// 対象クライアント（空 = 全クライアント）。
    pub client_ids: Vec<String>,
    /// 対象ユーザーの内部 ID（空 = 全ユーザー）。
    pub user_ids: Vec<String>,
    /// 対象ネットワークゾーン（CIDR 表記。空 = 全ネットワーク。AP3）。
    pub ip_cidrs: Vec<String>,
    /// 適用時間帯（空 = 常時。AP3）。
    pub time_windows: Vec<TimeWindowDto>,
    /// 認可要求の `acr_values` 条件（空 = 要求内容を問わない。AP3）。
    pub requested_acr: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// `require_specific_method` の要求内容（AP3。仕様 §12.2）。
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RequiredMethodsDto {
    /// 許可する認証方式（`password` / `totp` / `webauthn` / `recovery_code` / `email_otp` /
    /// `sms_otp` / `external_idp`）。**いずれか 1 つ**を使っていれば満たす。
    #[serde(default)]
    pub methods: Vec<String>,
    /// WebAuthn の User Verification（生体・PIN）を必須とするか。
    #[serde(default)]
    pub user_verification: bool,
}

/// 適用時間帯（AP3）。タイムゾーンは固定 UTC オフセット（分）で表す。
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TimeWindowDto {
    /// 対象曜日（0 = 日曜 … 6 = 土曜。空 = 全曜日）。
    #[serde(default)]
    pub days: Vec<u8>,
    /// 開始時刻（0 時からの分。0〜1439）。
    pub start_minute: u16,
    /// 終了時刻（同上。開始より小さい場合は日をまたぐ帯）。
    pub end_minute: u16,
    /// UTC オフセット（分。例: JST = 540）。
    #[serde(default)]
    pub utc_offset_minutes: i16,
}

/// 認証ポリシー一覧（priority 昇順）。
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationPoliciesResponse {
    pub policies: Vec<AuthenticationPolicyResponse>,
}

/// 認証ポリシーの作成・更新（全項目置換）リクエスト。
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthenticationPolicyUpsertRequest {
    /// テナント内一意の識別コード（英数字と `-` `_` `.`、1〜100 文字）。
    pub policy_code: String,
    pub policy_name: String,
    /// 評価順（昇順 = 小さいほど優先）。
    pub priority: i32,
    /// 省略時は有効（`true`）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`。
    pub effect: String,
    /// `require_specific_method` の要求内容（他の効果で指定するとエラー。AP3）。
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsDto>,
    /// 対象クライアント（省略・空 = 全クライアント）。
    #[serde(default)]
    pub client_ids: Vec<String>,
    /// 対象ユーザーの内部 ID（UUID。省略・空 = 全ユーザー）。
    #[serde(default)]
    pub user_ids: Vec<String>,
    /// 対象ネットワークゾーン（CIDR 表記。省略・空 = 全ネットワーク。AP3）。
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    /// 適用時間帯（省略・空 = 常時。AP3）。
    #[serde(default)]
    pub time_windows: Vec<TimeWindowDto>,
    /// 認可要求の `acr_values` 条件（省略・空 = 要求内容を問わない。AP3）。
    #[serde(default)]
    pub requested_acr: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod authentication_policy_contract_tests {
    use super::*;

    /// 管理コンソール（web）が使う `idp_contracts::admin` 側の DTO と、ここ（OpenAPI に載せる
    /// api 側の DTO）は**同じ JSON でなければならない**。食い違うと管理画面から保存できなくなる
    /// （web が送った形を api が復号できない）。両方を JSON で往復させて形の一致を固定する。
    #[test]
    fn authentication_policy_contract_matches_the_api_dto() {
        let shared = idp_contracts::admin::AuthenticationPolicyUpsertRequest {
            policy_code: "office-hours".to_string(),
            policy_name: "Office hours".to_string(),
            priority: 10,
            enabled: true,
            effect: "require_specific_method".to_string(),
            effect_params: Some(idp_contracts::admin::RequiredMethodsPayload {
                methods: vec!["webauthn".to_string()],
                user_verification: true,
            }),
            client_ids: vec!["app-a".to_string()],
            user_ids: vec!["019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string()],
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            time_windows: vec![idp_contracts::admin::TimeWindowPayload {
                days: vec![1, 2, 3, 4, 5],
                start_minute: 540,
                end_minute: 1080,
                utc_offset_minutes: 540,
            }],
            requested_acr: vec!["urn:example:high".to_string()],
        };
        let json = serde_json::to_value(&shared).expect("serialize the shared contract");
        let api: AuthenticationPolicyUpsertRequest =
            serde_json::from_value(json).expect("the api must accept what web sends");

        assert_eq!(api.policy_code, shared.policy_code);
        assert_eq!(api.priority, shared.priority);
        assert_eq!(api.enabled, shared.enabled);
        assert_eq!(api.effect, shared.effect);
        let params = api.effect_params.expect("effect_params must survive");
        assert_eq!(params.methods, vec!["webauthn".to_string()]);
        assert!(params.user_verification);
        assert_eq!(api.client_ids, shared.client_ids);
        assert_eq!(api.user_ids, shared.user_ids);
        assert_eq!(api.ip_cidrs, shared.ip_cidrs);
        assert_eq!(api.requested_acr, shared.requested_acr);
        assert_eq!(api.time_windows.len(), 1);
        assert_eq!(api.time_windows[0].days, vec![1, 2, 3, 4, 5]);
        assert_eq!(api.time_windows[0].start_minute, 540);
        assert_eq!(api.time_windows[0].end_minute, 1080);
        assert_eq!(api.time_windows[0].utc_offset_minutes, 540);
    }

    /// 管理コンソールが描く方式のチェックボックスは、api の `AuthenticationMethod` の
    /// **保存値そのもの**でなければならない（選んだ方式が api に弾かれる形にしない）。
    #[test]
    fn authentication_method_codes_match_the_contract() {
        use crate::domain::values::AuthenticationMethod;

        let expected = [
            AuthenticationMethod::Password,
            AuthenticationMethod::Totp,
            AuthenticationMethod::WebAuthn,
            AuthenticationMethod::RecoveryCode,
            AuthenticationMethod::EmailOtp,
            AuthenticationMethod::SmsOtp,
            AuthenticationMethod::ExternalIdp,
        ]
        .map(|m| m.as_str())
        .to_vec();
        assert_eq!(
            idp_contracts::admin::AUTHENTICATION_METHOD_CODES.to_vec(),
            expected
        );
        // 一覧に載せた各コードが実際に解釈できること（綴り間違いの検出）。
        for code in idp_contracts::admin::AUTHENTICATION_METHOD_CODES {
            assert!(
                AuthenticationMethod::parse(code).is_ok(),
                "unknown method code in the contract: {code}"
            );
        }
    }
}
