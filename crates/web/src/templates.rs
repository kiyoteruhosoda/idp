//! サーバレンダリング画面の Askama テンプレート定義（`templates/` 配下の `.html` に対応）。
//!
//! 旧来の `format!` による HTML 組み立てを置き換える。テンプレートは `.html` 拡張子のため
//! `{{ }}` の出力は **自動的に HTML エスケープ**され、格納型 XSS を既定で防ぐ（旧 `html::escape` の
//! 手動呼び出しは不要になった）。翻訳文言は各テンプレートが `messages.get("key")` を直接呼び出す。
//!
//! 各テンプレート構造体は対応する `.html` を `#[template(path = ...)]` で束ね、コンパイル時に
//! 型検証される（sqlx のコンパイル時クエリ検証と同じ思想）。

use crate::admin_dto::{
    AuditLogView, ClientView, SamlServiceProviderView, SigningKeyView, TenantCreatedView,
    TenantView,
};
use crate::i18n::Messages;
use askama::Template;
use idp_contracts::admin::{ClientStatusResponse, UserSummaryResponse};
use idp_contracts::auth::PasskeyCredentialInfo;
use idp_contracts::version::{BuildTimeVersionInfoProvider, VersionInfo, VersionInfoProvider};

/// フッタなどの共通 UI に表示する Cargo パッケージバージョン。
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// フッタに表示するバージョン表記。Git バージョン（`git describe`。ビルド時に埋め込み）が
/// 取得できていれば `v{package} ({git})`、なければパッケージ版のみ（`v{package}`）。
pub fn footer_version() -> String {
    let git = BuildTimeVersionInfoProvider::new(app_version())
        .version_info()
        .git_version;
    if git.is_empty() || git == "unknown" {
        format!("v{}", app_version())
    } else {
        format!("v{} ({git})", app_version())
    }
}

/// テンプレートを描画して HTML 文字列を返す。描画エラー（実質 fmt エラーのみ）は握りつぶさず
/// ログに残し、最小限のエラーページへフォールバックする（フェイルソフト）。
pub fn render<T: Template>(template: &T) -> String {
    template.render().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render template");
        "<!DOCTYPE html><html><body><p>Internal Server Error</p></body></html>".to_string()
    })
}

/// TOTP セットアップ画面（`GET /account/mfa/totp/setup`）。
/// QR コード SVG と生シークレット（base32）を両方表示する（QR が使えないユーザー向け）。
#[derive(Template)]
#[template(path = "mfa_totp_setup.html")]
pub struct TotpSetupTemplate<'a> {
    pub messages: &'a Messages,
    /// QR コードの SVG 文字列（インライン埋め込み）。
    pub qr_svg: &'a str,
    /// base32 エンコードされた生シークレット（QR が使えないユーザー向けに直接表示）。
    pub secret_base32: &'a str,
    pub error_key: Option<&'a str>,
}

/// ログインフロー TOTP 入力ページ（`GET /mfa/totp`）。
#[derive(Template)]
#[template(path = "mfa_totp_verify.html")]
pub struct TotpVerifyTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（Passkey JSON API の絶対パス組み立てに使う。ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// エンドユーザー・ポータルのログイン画面（`GET /{tenant_id}/login`。OIDC の `auth_session` を持たない
/// 直接ログイン）。IdP 自身のアカウント画面へ入るための画面で、共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "portal_login.html")]
pub struct PortalLogin<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先・リンクの組み立てに使う。ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// ポータルの TOTP 入力画面（`GET /{tenant_id}/login/mfa`）。`mfa_ticket` Cookie を保持した状態で表示する。
#[derive(Template)]
#[template(path = "portal_mfa.html")]
pub struct PortalMfa<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 同意画面（`GET /consent`、F3）。
#[derive(Template)]
#[template(path = "consent.html")]
pub struct ConsentTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub auth_session_id: &'a str,
    pub client_name: &'a str,
    pub requested_scopes: &'a [String],
}

/// タイトルと本文のみの最小ページ（ログインのエラー・権限不足など、共通レイアウトに載せない画面）。
#[derive(Template)]
#[template(path = "message_page.html")]
pub struct MessagePage {
    pub title: String,
    pub message: String,
}

/// バージョン情報ページ（`GET /version`）。
#[derive(Template)]
#[template(path = "version.html")]
pub struct VersionTemplate {
    pub info: VersionInfo,
}

/// 強制パスワード変更画面（`GET /{tenant_id}/password-change`、ADR-0009 §5）。ログインフロー中
/// （パスワード検証済み・SSO 未発行）に表示する。共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "password_change.html")]
pub struct PasswordChangeTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 管理コンソールの強制パスワード変更画面（`GET/POST /{tenant_id}/admin/password-change`、
/// ADR-0009 §5）。管理ログインは一時状態を持たないため `username` を隠しフィールドで維持する。
#[derive(Template)]
#[template(path = "console/password_change.html")]
pub struct AdminPasswordChange<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先の組み立てに使う。ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub csrf: &'a str,
    pub username: &'a str,
    pub error_key: Option<&'a str>,
}

/// 管理コンソール共通レイアウトのヘッダに載せる管理者識別子（未認証時は `None`）。
/// 各コンソール画面テンプレートが持ち、`console/layout.html` から参照される。
pub type Admin<'a> = Option<&'a str>;

/// 管理コンソールのホーム（`GET /{tenant_id}/admin`）。
#[derive(Template)]
#[template(path = "console/home.html")]
pub struct ConsoleHome<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant: &'a str,
    pub admin: Admin<'a>,
}

/// 管理コンソールのログイン画面（`GET /{tenant_id}/admin/login`）。共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "console/login.html")]
pub struct ConsoleLogin<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 共通レイアウト上の告知（エラーバナー・404・戻るリンク付きメッセージ）。各コンソール画面の
/// エラー系レスポンスで再利用する。`is_error` で `role="alert"` の付いたエラーバナー表示を切り替える。
#[derive(Template)]
#[template(path = "console/notice.html")]
pub struct ConsoleNotice<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: Option<&'a str>,
    pub message: &'a str,
    pub is_error: bool,
    pub back_href: Option<&'a str>,
    pub back_label: &'a str,
}

/// 監査ログ一覧（`GET /{tenant_id}/admin/audit-logs`）。フィルタ値は再入力用に展開済み文字列で渡す。
/// ページャの前後リンク（クエリ文字列を組み立て済み）は該当がなければ `None`。
#[derive(Template)]
#[template(path = "console/audit_logs.html")]
pub struct AuditLogs<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub date_error: bool,
    pub event_type: &'a str,
    pub result: &'a str,
    pub client_id: &'a str,
    pub correlation_id: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub entries: &'a [AuditLogView],
    pub prev_href: Option<String>,
    pub next_href: Option<String>,
}

/// クライアント状況一覧（`GET /{tenant_id}/admin/status`）。
#[derive(Template)]
#[template(path = "console/client_status.html")]
pub struct ClientStatus<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub views: &'a [ClientStatusResponse],
}

/// 利用者検索画面（`GET /{tenant_id}/admin/users`）。`user` が該当利用者、`not_found` は検索したが
/// 見つからなかったことを表す（未検索時は両方 `None`/`false`）。
#[derive(Template)]
#[template(path = "console/users_search.html")]
pub struct UsersSearch<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub term: &'a str,
    pub user: Option<&'a UserSummaryResponse>,
    pub not_found: bool,
}

/// 利用者の権限画面（`GET /{tenant_id}/admin/users/{id}/permissions`）。
#[derive(Template)]
#[template(path = "console/users_permissions.html")]
pub struct UsersPermissions<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub user: &'a UserSummaryResponse,
    pub codes: &'a [String],
    pub available: &'a [String],
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 利用者作成フォーム（`GET/POST /{tenant_id}/admin/users/new`、ADR-0009 §5・§6）。
#[derive(Template)]
#[template(path = "console/user_form.html")]
pub struct UserForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub email: &'a str,
    pub preferred_username: &'a str,
    pub name: &'a str,
}

/// 利用者作成結果（`POST /{tenant_id}/admin/users/new` 成功時）。`generated_password` を一度だけ表示する。
#[derive(Template)]
#[template(path = "console/user_created.html")]
pub struct UserCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub email: &'a str,
    pub generated_password: &'a str,
}

/// メンバー一覧（`GET /{tenant_id}/admin/members`。HOME / GUEST を問わない。ADR-0009 §3）。
#[derive(Template)]
#[template(path = "console/members_list.html")]
pub struct MembersList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub members: &'a [crate::admin_dto::MemberView],
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// 管理者によるパスワード再発行の結果画面（一度限りの生成パスワード表示。ADR-0009 §5）。
/// メンバー一覧（HOME 利用者）とテナント管理（子テナント管理者）の双方から使う。
#[derive(Template)]
#[template(path = "console/password_reset_result.html")]
pub struct PasswordResetResult<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    /// 対象の表示（メールアドレス等）。
    pub subject: &'a str,
    /// 生成パスワード（平文。一度限り表示）。
    pub generated_password: &'a str,
    pub back_href: &'a str,
    /// 戻りリンクの文言キー。
    pub back_label_key: &'a str,
}

/// ゲスト招待フォーム（`GET/POST /{tenant_id}/admin/invitations`、ADR-0009 §3）。
#[derive(Template)]
#[template(path = "console/invitation_form.html")]
pub struct InvitationForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub user_id: &'a str,
}

/// ゲスト招待作成結果（`POST /{tenant_id}/admin/invitations` 成功時）。招待トークンを一度だけ表示する。
#[derive(Template)]
#[template(path = "console/invitation_created.html")]
pub struct InvitationCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub token: &'a str,
    pub expires_at: &'a str,
    /// 招待メール（承諾リンク）を送信できたか（MT17）。false ならトークンの手動伝達を促す。
    pub email_sent: bool,
    pub invitee_email: &'a str,
}

/// パスワードリセット要求画面（`GET/POST /{tenant_id}/forgot-password`。MT18）。未ログイン経路。
/// 要求受理後はアカウントの有無を問わず同じ完了文言を表示する（列挙防止）。
#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPassword<'a> {
    pub messages: &'a Messages,
    /// 要求を受理した後の完了表示。
    pub accepted: bool,
    pub error_key: Option<&'a str>,
}

/// パスワード再設定画面（`GET/POST /{tenant_id}/password-reset?token=...`。MT18）。
/// リセットメールのリンクから開く。
#[derive(Template)]
#[template(path = "password_reset.html")]
pub struct PasswordReset<'a> {
    pub messages: &'a Messages,
    pub tenant_prefix: &'a str,
    pub show_form: bool,
    pub token: &'a str,
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// 招待承諾画面（`GET/POST /{tenant_id}/invitations/accept`。MT17）。被招待者本人が招待メールの
/// リンクから開く。共通レイアウト（管理コンソール）には載せない。
#[derive(Template)]
#[template(path = "invitation_accept.html")]
pub struct InvitationAccept<'a> {
    pub messages: &'a Messages,
    /// 承諾フォームを表示するか（SSO ログイン済みのときのみ true）。
    pub show_form: bool,
    pub token: &'a str,
    pub csrf: &'a str,
    /// 承諾に成功したか（成功画面表示）。
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// メール検証画面（`GET/POST /{tenant_id}/verify-email?token=...`。SEC6b）。自己登録の確認メールの
/// リンクから開く。GET は確認ボタン（POST でトークンを消費）を表示し、リンクのプリフェッチで
/// トークンを消費しないようにする。未ログイン経路（SSO 不要）。
#[derive(Template)]
#[template(path = "verify_email.html")]
pub struct VerifyEmail<'a> {
    pub messages: &'a Messages,
    /// 確認フォーム（POST ボタン）を表示するか（トークンがあるとき true）。
    pub show_form: bool,
    pub token: &'a str,
    /// 検証に成功したか（成功画面表示）。
    pub success: bool,
    pub error_key: Option<&'a str>,
}

/// クライアント登録・編集フォームの入力値（新規/再表示の両方で使う）。テンプレートの再入力欄へ
/// そのまま流し込む。`redirect_uris` は 1 行 1 URI、`scopes` は空白区切りの生文字列。
pub struct ClientFormValues {
    pub app_name: String,
    pub client_type: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub require_pkce: bool,
    pub client_status: String,
}

impl ClientFormValues {
    /// 新規登録フォームの初期値（confidential・PKCE 必須・openid スコープ）。
    pub fn default_new() -> Self {
        Self {
            app_name: String::new(),
            client_type: "confidential".to_string(),
            redirect_uris: String::new(),
            scopes: "openid".to_string(),
            require_pkce: true,
            client_status: "ACTIVE".to_string(),
        }
    }

    /// 既存クライアントから編集フォームの初期値を作る（URI は改行区切り、scope は空白区切り）。
    pub fn from_client(c: &ClientView) -> Self {
        Self {
            app_name: c.app_name.clone(),
            client_type: c.client_type.clone(),
            redirect_uris: c.redirect_uris.join("\n"),
            scopes: c.scopes.join(" "),
            require_pkce: c.require_pkce,
            client_status: c.client_status.clone(),
        }
    }
}

/// クライアント一覧（`GET /{tenant_id}/admin/clients`）。
#[derive(Template)]
#[template(path = "console/clients_list.html")]
pub struct ClientsList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub clients: &'a [ClientView],
}

/// クライアント登録・編集フォーム（`is_new` で新規/編集を切り替える）。
#[derive(Template)]
#[template(path = "console/client_form.html")]
pub struct ClientForm<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub heading: &'a str,
    pub action: &'a str,
    pub is_new: bool,
    pub values: &'a ClientFormValues,
}

/// クライアント詳細（`GET /{tenant_id}/admin/clients/{id}`）。
#[derive(Template)]
#[template(path = "console/client_detail.html")]
pub struct ClientDetail<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub client: &'a ClientView,
    pub csrf: &'a str,
}

/// secret 表示画面（作成直後・再発行直後。`secret` が `None` なら public で秘密なし）。
#[derive(Template)]
#[template(path = "console/client_secret.html")]
pub struct ClientSecret<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub heading: &'a str,
    pub client_id: &'a str,
    pub secret: Option<&'a str>,
}

/// 署名鍵一覧・管理画面（`GET /{tenant_id}/admin/signing-keys`、K1）。
#[derive(Template)]
#[template(path = "console/signing_keys.html")]
pub struct SigningKeysList<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub keys: &'a [SigningKeyView],
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}

/// root 管理者向けのテナント一覧・登録画面（`GET /{tenant_id}/admin/tenants`）。
#[derive(Template)]
#[template(path = "console/tenants.html")]
pub struct TenantsConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub tenants: &'a [TenantView],
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// テナント作成結果（`POST /{tenant_id}/admin/tenants` 成功時）。
#[derive(Template)]
#[template(path = "console/tenant_created.html")]
pub struct TenantCreated<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub created: &'a TenantCreatedView,
}

/// 管理コンソールの設定画面（`GET /{tenant_id}/admin/settings`。MT14）。テナント設定区画（自テナント
/// 表示名）と、root（idp.system.admin）のみ表示するシステム設定区画（SMTP）。`system` が `None` の
/// ときはシステム設定区画を描画しない。
#[derive(Template)]
#[template(path = "console/admin_settings.html")]
pub struct AdminSettings<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub tenant_id: &'a str,
    pub tenant_name: &'a str,
    pub tenant_status: &'a str,
    /// 自己登録（/auth/register）の許可トグル（SEC6）。
    pub tenant_self_registration: bool,
    pub csrf: &'a str,
    /// 保存成功のバナー表示。
    pub saved: bool,
    pub error_key: Option<&'a str>,
    /// root のみ `Some`。SMTP 設定区画を描画する。
    pub system: Option<&'a crate::admin_dto::SystemSettingsView>,
}

/// 利用者のセルフサービス設定画面（`GET /{tenant_id}/settings`。MT15）。パスワード変更・言語設定・
/// MFA への導線。管理コンソールとは別の利用者向け画面のため共通レイアウトには載せない。
#[derive(Template)]
#[template(path = "user_settings.html")]
pub struct UserSettings<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（フォーム送信先・MFA リンクの組み立てに使う。ADR-0009 §6）。
    pub tenant: &'a str,
    /// 現在の表示言語（`ja` / `en`）。言語セレクタの初期選択に使う。
    pub current_lang: &'a str,
    /// 保存成功メッセージのキー（`None` なら非表示）。
    pub saved_key: Option<&'a str>,
    pub error_key: Option<&'a str>,
    /// 管理コンソール（`?from=admin`）から開いたか。左上に戻るリンクを出し、フォーム送信でも維持する。
    pub from_admin: bool,
}

/// Passkey 一覧画面（`GET /account/passkey`）。登録済みクレデンシャルの一覧と削除ボタン。
#[derive(Template)]
#[template(path = "passkey_list.html")]
pub struct PasskeyListTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub credentials: &'a [PasskeyCredentialInfo],
}

/// Passkey 登録画面（`GET /account/passkey/register`）。WebAuthn JS フローを起動する。
#[derive(Template)]
#[template(path = "passkey_register.html")]
pub struct PasskeyRegisterTemplate<'a> {
    pub messages: &'a Messages,
    /// `/{tenant_id}` プレフィクス（ADR-0009 §6）。
    pub tenant_prefix: &'a str,
    pub error_key: Option<&'a str>,
}

/// SAML SP（クライアント）一覧・追加画面（`GET /{tenant_id}/admin/saml-clients`）。
#[derive(Template)]
#[template(path = "console/saml_service_providers.html")]
pub struct SamlServiceProvidersConsole<'a> {
    pub messages: &'a Messages,
    pub tenant: &'a str,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub saved: bool,
    /// メタデータ取り込みで初期値を反映した直後か（案内バナー表示・追加パネル展開に使う）。
    pub imported: bool,
    pub error_key: Option<&'a str>,
    pub providers: &'a [SamlServiceProviderView],
    pub values: &'a SamlServiceProviderFormValues,
}

/// SAML SP（クライアント）追加フォームの入力値。
#[derive(Default)]
pub struct SamlServiceProviderFormValues {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    pub x509_certificate: String,
    pub enabled: bool,
}
