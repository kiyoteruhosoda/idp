//! web が受け取るフォーム DTO。

use serde::Deserialize;

/// ログインフォーム（`POST /login`）。ログイン識別子はユーザー名（`preferred_username`。ADR-0009 §8）。
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// SAML SSO 継続画面のクエリ（`GET /saml/continue`）。
#[derive(Debug, Deserialize)]
pub struct SamlContinueQuery {
    /// api の `/saml/sso` がハンドオフ URL に載せた単回・短命のハンドル。web は即座に
    /// `/internal/saml/resume` で交換する（ADR-0018 決定 2 と同方式）。
    #[serde(default)]
    pub handle: Option<String>,
}

/// ログイン画面のクエリ（`GET /login`）。
#[derive(Debug, Deserialize)]
pub struct LoginPageQuery {
    /// api の `/authorize` がハンドオフ URL に載せた単回・短命のハンドル（ADR-0018 決定 2）。
    /// web は即座に `/internal/authorize/resume` で交換し、303 で URL から除去する。
    #[serde(default)]
    pub auth_session: Option<String>,
    /// POST の失敗（CSRF 不一致等）から PRG で戻ったときのエラー種別（`csrf` のみ）。
    /// 新しいトークンで再描画したフォームにエラーバナーを出す。
    #[serde(default)]
    pub error: Option<String>,
}

/// フォーム系ページ共通の PRG 戻りクエリ（`?error=csrf`）。CSRF 不一致の POST から 303 で GET へ
/// 戻したときに、新しいトークンで再描画したフォームへエラーバナーを出すために使う。
#[derive(Debug, Default, Deserialize)]
pub struct FormPageQuery {
    #[serde(default)]
    pub error: Option<String>,
}

/// RP-initiated Logout のクエリ（`GET /logout`、OIDC RP-initiated Logout 1.0。ADR-0018 決定 2）。
#[derive(Debug, Deserialize)]
pub struct RpLogoutQuery {
    /// ログアウト対象を示す ID Token（任意。G12）。api が署名・issuer を検証し、
    /// `post_logout_redirect_uri` の照合先と「誰のログアウトか」の確認に使う。
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// ログアウト後のリダイレクト先（登録済みのもののみ api が許可する）。
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    /// RP が受け取るランダム値（redirect_uri に透過的に付与）。
    #[serde(default)]
    pub state: Option<String>,
    /// post_logout_redirect_uri の検証に使う（任意）。
    #[serde(default)]
    pub client_id: Option<String>,
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
/// 共有する。どちらも `auth_session_id` のような一時状態を持たないため、`username`（ログイン識別子）を
/// 含めフルに再送し、api 側で現行パスワードを含め再検証する。
#[derive(Debug, Deserialize)]
pub struct ForcedPasswordChangeForm {
    pub username: String,
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
    /// SMS ゲートウェイ（AP13）。`sms_auth_token` が空文字なら現行のトークンを維持する。
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    #[serde(default)]
    pub sms_auth_token: String,
    #[serde(default)]
    pub sms_sender_id: String,
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

/// セルフサービスの表示名変更フォーム（`POST /{tenant_id}/settings/name`）。
/// `from` は管理コンソールから開いた文脈の引き継ぎ（PRG 後も戻り導線を維持する）。
#[derive(Debug, Deserialize)]
pub struct AccountNameForm {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
}

/// 設定画面の GET クエリ（言語・配色の一時切替・保存/エラーバナー表示・遷移元の引き継ぎ）。
#[derive(Debug, Default, Deserialize)]
pub struct SettingsQuery {
    #[serde(default)]
    pub lang: Option<String>,
    /// 配色の選択（`?theme=`）。保存は middleware が行うが、**この画面はセレクタの選択状態を
    /// 描くために自分でも読む**（DB への保存は応答の後、Cookie の書き換えは応答の中で起きるため、
    /// 保存直後のこのリクエストでは古い値しか手元に無い）。
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// 遷移元（`admin` = 管理コンソール。左上に戻るリンクを表示する）。
    #[serde(default)]
    pub from: Option<String>,
}

/// テナント登録フォーム（`POST /{tenant_id}/admin/tenants`。root / `idp.system.admin` 専用）。
/// 作成者自身が新テナントのブートストラップ管理者になるため初期管理者メールは受け取らない（ADR-0009 §4）。
#[derive(Debug, Deserialize)]
pub struct AdminTenantCreateForm {
    pub name: String,
    pub csrf_token: String,
}

/// テナント管理画面の GET クエリ。
#[derive(Debug, Default, Deserialize)]
pub struct TenantsQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// 更新完了通知（Post/Redirect/Get で戻ったときに成功バナーを出す）。
    #[serde(default)]
    pub saved: Option<String>,
    /// ページャの読み飛ばし件数。未指定は 0（G7）。
    #[serde(default)]
    pub offset: Option<i64>,
}

/// 子テナントの編集フォーム（`POST /{tenant_id}/admin/tenants/{child_id}/update`。MT23）。
/// 表示名と状態（`ACTIVE` / `DISABLED`）を変更する。api の `PATCH /admin/tenants/{child_id}` へ委ねる。
#[derive(Debug, Deserialize)]
pub struct AdminTenantUpdateForm {
    pub name: String,
    pub status: String,
    pub csrf_token: String,
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

/// api・web の再起動フォーム（`POST /{tenant_id}/admin/restart`。ADR-0017）。
#[derive(Debug, Deserialize)]
pub struct AdminRestartForm {
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

/// SAML SP（クライアント）削除フォーム（`POST /{tenant_id}/admin/saml-clients/{id}/delete`）。
#[derive(Debug, Deserialize)]
pub struct AdminSamlServiceProviderDeleteForm {
    pub csrf_token: String,
}

/// 認証ポリシーの作成・編集フォーム（`POST /{tenant_id}/admin/authentication-policies`、AP1）。
///
/// 個数が可変の条件（対象クライアント・利用者・CIDR・`acr_values`・時間帯）は、HTML の入力欄へ
/// 1 対 1 で置けないためテキスト領域で受ける。書式と往復は
/// [`crate::authentication_policy_form`] に集約する。
#[derive(Debug, Deserialize)]
pub struct AdminAuthenticationPolicyForm {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: String,
    /// チェックボックスは未チェックだと送信されないため `Option` で受ける。
    #[serde(default)]
    pub enabled: Option<String>,
    pub effect: String,
    /// `require_specific_method` で許可する認証方式（チェックボックス群）。
    ///
    /// 繰り返しキー（`methods=a&methods=b`）を `Vec` で受けないのは、フォームの復号に使う
    /// `serde_urlencoded` が列（sequence）に対応しないためである。方式は閉じた語彙
    /// （[`idp_contracts::admin::AUTHENTICATION_METHOD_CODES`]）なので、方式ごとに独立した
    /// チェックボックスとして受ける。
    #[serde(default)]
    pub method_password: Option<String>,
    #[serde(default)]
    pub method_totp: Option<String>,
    #[serde(default)]
    pub method_webauthn: Option<String>,
    #[serde(default)]
    pub method_recovery_code: Option<String>,
    #[serde(default)]
    pub method_email_otp: Option<String>,
    #[serde(default)]
    pub method_sms_otp: Option<String>,
    #[serde(default)]
    pub method_external_idp: Option<String>,
    #[serde(default)]
    pub user_verification: Option<String>,
    #[serde(default)]
    pub client_ids: String,
    #[serde(default)]
    pub user_ids: String,
    #[serde(default)]
    pub ip_cidrs: String,
    #[serde(default)]
    pub time_windows: String,
    #[serde(default)]
    pub requested_acr: String,
    pub csrf_token: String,
}

/// 認証ポリシー削除フォーム（`POST /{tenant_id}/admin/authentication-policies/{id}/delete`）。
#[derive(Debug, Deserialize)]
pub struct AdminAuthenticationPolicyDeleteForm {
    pub csrf_token: String,
}
