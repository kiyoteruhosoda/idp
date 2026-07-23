//! web が受け取るフォーム DTO。

use serde::Deserialize;

/// ログインフォーム（`POST /login`）。ログイン識別子はメールアドレスに統一する（ADR-0009 §8）。
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    pub csrf_token: String,
}

/// TOTP 確認フォーム（`POST /account/mfa/totp/setup`）。
#[derive(Debug, Deserialize)]
pub struct TotpConfirmForm {
    /// 認証アプリから入力した 6 桁コード。
    pub code: String,
}

/// ポータル TOTP 入力フォーム（`POST /{tenant_id}/login/mfa`）。
#[derive(Debug, Deserialize)]
pub struct PortalTotpForm {
    pub totp_code: String,
    pub csrf_token: String,
}

/// 同意フォーム（`POST /consent`、F3）。
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub auth_session_id: String,
    pub csrf_token: String,
    /// `approve` または `deny`。
    pub action: String,
}

/// 強制パスワード変更フォーム（`POST /password-change`、ADR-0009 §5）。ログインフロー中
/// （パスワード検証済み・SSO 未発行）の `auth_session_id` を前提とする。
#[derive(Debug, Deserialize)]
pub struct PasswordChangeForm {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}

/// 強制パスワード変更フォーム（初回ログイン時。ADR-0009 §5）。管理コンソールログイン
/// （`POST /admin/password-change`）とポータル（一般）ログイン（`POST /login/password-change`）で
/// 共有する。どちらも `auth_session_id` のような一時状態を持たないため、`email`（ログイン識別子）を
/// 含めフルに再送し、api 側で現行パスワードを含め再検証する。
#[derive(Debug, Deserialize)]
pub struct ForcedPasswordChangeForm {
    pub email: String,
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}

/// 設定画面のテナント表示名フォーム（`POST /{tenant_id}/admin/settings/tenant`。MT14）。
#[derive(Debug, Deserialize)]
pub struct AdminTenantSettingsForm {
    pub name: String,
    /// 自己登録トグル（SEC6）。チェックボックスはチェック時のみ送られる（`Some(_)` = 有効）。
    #[serde(default)]
    pub self_registration_enabled: Option<String>,
    pub csrf_token: String,
}

/// 設定画面のシステム設定（SMTP）フォーム（`POST /{tenant_id}/admin/system-settings`。MT14）。
/// `smtp_port` は文字列で受け、`smtp_use_tls` はチェックボックス（チェック時のみ送られる）。
/// `smtp_password` が空文字なら現行のパスワードを維持する（変更しない）。
#[derive(Debug, Deserialize)]
pub struct AdminSystemSettingsForm {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: Option<String>,
    pub csrf_token: String,
}

/// セルフサービスのパスワード変更フォーム（`POST /{tenant_id}/settings/password`。MT15）。
/// `from` は管理コンソールから開いた文脈の引き継ぎ（`admin` のとき PRG 後も戻り導線を維持する）。
#[derive(Debug, Deserialize)]
pub struct AccountPasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    #[serde(default)]
    pub from: Option<String>,
}

/// 設定画面の GET クエリ（言語一時切替・保存/エラーバナー表示・遷移元の引き継ぎ）。
#[derive(Debug, Default, Deserialize)]
pub struct SettingsQuery {
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// 遷移元（`admin` = 管理コンソール。左上に戻るリンクを表示する）。
    #[serde(default)]
    pub from: Option<String>,
}

/// テナント登録フォーム（`POST /{tenant_id}/admin/tenants`。root / `idp.system.admin` 専用）。
#[derive(Debug, Deserialize)]
pub struct AdminTenantCreateForm {
    pub name: String,
    pub admin_email: String,
    pub csrf_token: String,
}

/// テナント管理画面の GET クエリ。
#[derive(Debug, Default, Deserialize)]
pub struct TenantsQuery {
    #[serde(default)]
    pub error: Option<String>,
}

/// テナント管理画面の CSRF のみのアクション（削除等）のフォーム。
#[derive(Debug, Deserialize)]
pub struct AdminTenantActionForm {
    pub csrf_token: String,
}

/// 管理者によるパスワード再発行フォーム（対象をメールアドレスで指定する）。
#[derive(Debug, Deserialize)]
pub struct AdminPasswordResetForm {
    #[serde(default)]
    pub email: String,
    pub csrf_token: String,
}

/// メンバー一覧の利用者状態変更フォーム（`ACTIVE` / `DISABLED`）。
#[derive(Debug, Deserialize)]
pub struct MemberStatusForm {
    pub status: String,
    pub csrf_token: String,
}

/// メンバー一覧の CSRF のみのアクション（削除・パスワード再発行等）のフォーム。
/// `email` は結果画面の表示用（省略可。認可・対象解決には使わない）。
#[derive(Debug, Deserialize)]
pub struct MemberActionForm {
    #[serde(default)]
    pub email: String,
    pub csrf_token: String,
}

/// 設定画面のランタイム設定（DB 上書き）フォーム
/// （`POST /{tenant_id}/admin/system-settings/runtime`）。`value` が空 = 上書き解除。
#[derive(Debug, Deserialize)]
pub struct AdminRuntimeSettingForm {
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub csrf_token: String,
}

/// SAML SP（クライアント）登録フォーム（`POST /{tenant_id}/admin/saml-clients`）。
#[derive(Debug, Deserialize)]
pub struct AdminSamlServiceProviderForm {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub name_id_format: String,
    #[serde(default)]
    pub x509_certificate: String,
    #[serde(default)]
    pub enabled: Option<String>,
    pub csrf_token: String,
}
