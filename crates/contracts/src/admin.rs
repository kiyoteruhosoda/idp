//! 管理コンソール（web）が api の JSON 管理 API（`/admin/*`）を呼ぶときに共有する DTO 契約。
//!
//! これらは api の `RequirePerms<IdpAdmin>` で保護される内部認可 API のレスポンス型で、web は
//! 管理者の SSO Cookie を転送して呼ぶ（ADR-0007 §4）。OpenAPI（外部公開 API）とは別系統のため
//! `utoipa` は付けない。

use serde::{Deserialize, Serialize};

/// `GET /admin/whoami` のレスポンス。アクセスできること自体が「有効な SSO ＋ `idp.tenant.admin` 保有」を意味する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    /// 認可済み管理利用者の内部 ID（UUID 文字列）。
    pub user_id: String,
    /// 表示名（未設定なら `None`）。管理コンソールのヘッダ表示に使う。
    #[serde(default)]
    pub name: Option<String>,
    /// ログイン識別子（未設定なら `None`）。表示名が無いときのヘッダ表示の代替に使う。
    #[serde(default)]
    pub preferred_username: Option<String>,
}

/// 利用者の要約（`GET /admin/users?q=` 検索・`GET /admin/users/{id}` の応答）。管理コンソールの
/// 権限画面が対象利用者を特定・表示するために用いる。パスワードハッシュ等の機微情報は含めない。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummaryResponse {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// `ACTIVE` / `DISABLED` 等。
    pub status: String,
}

/// クライアント状況（`GET /admin/clients/status`）。状態・scope・最終利用時刻。
/// 最終利用時刻は監査ログ由来（成功した token/code 発行の最新時刻）。未使用は `None`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStatusResponse {
    pub client_id: String,
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`。
    pub status: String,
    pub scopes: Vec<String>,
    /// RFC3339 文字列。未使用なら `None`。
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// 付与可能な権限コード（`GET /admin/permissions`。`permissions` マスタ由来）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailablePermissionsResponse {
    pub codes: Vec<String>,
}

/// 利用者の保有権限コード一覧（`GET/POST /admin/users/{id}/permissions`・剥奪の応答）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissionsResponse {
    pub user_id: String,
    pub permission_codes: Vec<String>,
}

/// 署名鍵の公開表現（`GET /admin/signing-keys`・`POST /admin/signing-keys` 等のレスポンス要素）。
/// 秘密鍵は含めない。
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSigningKeyRequest {
    /// `RS256` または `ES256`。
    pub algorithm: String,
}

/// SAML メタデータ取り込みリクエスト（SP メタデータ XML を貼り付けて登録候補値を得る）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlMetadataImportRequest {
    /// SAML メタデータ XML（`EntityDescriptor`）。
    pub metadata_xml: String,
}

/// SAML SP（クライアント）登録リクエスト（`POST /admin/saml-service-providers`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderRegisterRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID フォーマット（空なら既定の persistent）。
    #[serde(default)]
    pub name_id_format: String,
    /// 署名/暗号証明書（任意）。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP（クライアント）更新リクエスト（`PUT /admin/saml-service-providers/{id}`）。
/// 登録と同じ項目を受け取り、指定 SP の内容を置き換える（テナントは変更しない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderUpdateRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID フォーマット（空なら既定の persistent）。
    #[serde(default)]
    pub name_id_format: String,
    /// 署名/暗号証明書（任意）。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP（クライアント）の管理 API 表現。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderResponse {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// 署名/暗号証明書（任意。設定されていなければ `None`）。編集フォームの初期値に使う。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// SAML SP メタデータ取り込みの応答（登録フォームの初期値）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSpMetadataImportResponse {
    #[serde(default)]
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub name_id_format: String,
    #[serde(default)]
    pub x509_certificate: String,
}

// ── 認証ポリシー（AP1。管理コンソールが `/admin/authentication-policies` を呼ぶための契約）──
//
// api 側は同じ形の DTO を `presentation::dto` に持つ（そちらは `utoipa` を付けて OpenAPI に載せる
// ため）。**2 つが食い違うと管理画面から保存できなくなる**ので、api のテスト
// （`authentication_policy_contract_matches_the_api_dto`）が JSON を往復させて形の一致を固定する。

/// 認証ポリシーの管理 API 表現（`GET /admin/authentication-policies` の要素）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicyResponse {
    pub id: String,
    pub policy_code: String,
    pub policy_name: String,
    /// 評価順（昇順 = 小さいほど優先）。
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`。
    pub effect: String,
    /// `require_specific_method` の要求内容（他の効果では `None`）。
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsPayload>,
    /// 対象クライアント（空 = 全クライアント）。
    #[serde(default)]
    pub client_ids: Vec<String>,
    /// 対象ユーザーの内部 ID（空 = 全ユーザー）。
    #[serde(default)]
    pub user_ids: Vec<String>,
    /// 対象ネットワークゾーン（CIDR 表記。空 = 全ネットワーク）。
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    /// 適用時間帯（空 = 常時）。
    #[serde(default)]
    pub time_windows: Vec<TimeWindowPayload>,
    /// 認可要求の `acr_values` 条件（空 = 要求内容を問わない）。
    #[serde(default)]
    pub requested_acr: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 認証ポリシー一覧（priority 昇順）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPoliciesResponse {
    pub policies: Vec<AuthenticationPolicyResponse>,
}

/// 認証ポリシーの作成・更新（全項目置換）リクエスト。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicyUpsertRequest {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: i32,
    pub enabled: bool,
    pub effect: String,
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsPayload>,
    #[serde(default)]
    pub client_ids: Vec<String>,
    #[serde(default)]
    pub user_ids: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    #[serde(default)]
    pub time_windows: Vec<TimeWindowPayload>,
    #[serde(default)]
    pub requested_acr: Vec<String>,
}

/// `require_specific_method` で指定できる認証方式のコード（表示順）。
///
/// 実体は api 側の `AuthenticationMethod`（保存値の文字列）で、ここはその**語彙の写し**である。
/// web は DB にも core にも触れないため、選択肢を描くにはこの一覧が要る。食い違うと管理画面で
/// 選んだ方式が api に弾かれるので、api のテスト（`authentication_method_codes_match_the_contract`）
/// が enum との一致を固定する。
pub const AUTHENTICATION_METHOD_CODES: &[&str] = &[
    "password",
    "totp",
    "webauthn",
    "recovery_code",
    "email_otp",
    "sms_otp",
    "external_idp",
];

/// ログイン識別子の種別コード（表示順。AP8 / AP16）。
///
/// 実体は api 側の `LoginIdentifierType`（保存値の文字列）で、ここはその**語彙の写し**である。
/// web は DB にも core にも触れないため、管理画面の種別プルダウンを描くにはこの一覧が要る。
/// 食い違うと画面で選んだ種別が api に弾かれるので、api のテスト
/// （`login_identifier_type_codes_match_the_contract`）が enum との一致を固定する。
pub const LOGIN_IDENTIFIER_TYPE_CODES: &[&str] =
    &["username", "email", "phone_number", "employee_number"];

/// `require_specific_method` の要求内容。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredMethodsPayload {
    /// 許可する認証方式。**いずれか 1 つ**を使っていれば満たす。
    #[serde(default)]
    pub methods: Vec<String>,
    /// WebAuthn の User Verification（生体・PIN）を必須とするか。
    #[serde(default)]
    pub user_verification: bool,
}

/// 適用時間帯。タイムゾーンは固定 UTC オフセット（分）で表す。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindowPayload {
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
