//! 管理コンソール（web）が api の JSON 管理 API（`/admin/*`）を呼ぶときに共有する DTO 契約。
//!
//! これらは api の `RequirePerms<IdpAdmin>` で保護される内部認可 API のレスポンス型で、web は
//! 管理者の SSO Cookie を転送して呼ぶ（ADR-0007 §4）。OpenAPI（外部公開 API）とは別系統のため
//! `utoipa` は付けない。

use serde::{Deserialize, Serialize};

/// `GET /internal/root-tenant` のレスポンス（ADR-0009 §7）。web が起動時／初回に root テナント UUID を
/// 解決し、`/{tenant_id}/admin/*` パスの前置に使う（過渡期。root UUID は環境毎に動的採番のため
/// 設定に埋め込まない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootTenantResponse {
    /// root テナントの UUID（`parent_tenant_id IS NULL` の唯一の行）。
    pub tenant_id: String,
}

/// `GET /admin/whoami` のレスポンス。アクセスできること自体が「有効な SSO ＋ `idp.tenant.admin` 保有」を意味する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    /// 認可済み管理利用者の内部 ID（UUID 文字列）。
    pub user_id: String,
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
