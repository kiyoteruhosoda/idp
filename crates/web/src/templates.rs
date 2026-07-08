//! サーバレンダリング画面の Askama テンプレート定義（`templates/` 配下の `.html` に対応）。
//!
//! 旧来の `format!` による HTML 組み立てを置き換える。テンプレートは `.html` 拡張子のため
//! `{{ }}` の出力は **自動的に HTML エスケープ**され、格納型 XSS を既定で防ぐ（旧 `html::escape` の
//! 手動呼び出しは不要になった）。翻訳文言は各テンプレートが `messages.get("key")` を直接呼び出す。
//!
//! 各テンプレート構造体は対応する `.html` を `#[template(path = ...)]` で束ね、コンパイル時に
//! 型検証される（sqlx のコンパイル時クエリ検証と同じ思想）。

use crate::admin_dto::{AuditLogView, ClientView, SigningKeyView};
use crate::i18n::Messages;
use askama::Template;
use idp_contracts::admin::{ClientStatusResponse, UserSummaryResponse};

/// テンプレートを描画して HTML 文字列を返す。描画エラー（実質 fmt エラーのみ）は握りつぶさず
/// ログに残し、最小限のエラーページへフォールバックする（フェイルソフト）。
pub fn render<T: Template>(template: &T) -> String {
    template.render().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render template");
        "<!DOCTYPE html><html><body><p>Internal Server Error</p></body></html>".to_string()
    })
}

/// 利用者ログイン画面（`GET /login`）。
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub messages: &'a Messages,
    pub csrf: &'a str,
    pub error_key: Option<&'a str>,
}

/// タイトルと本文のみの最小ページ（ログインのエラー・権限不足など、共通レイアウトに載せない画面）。
#[derive(Template)]
#[template(path = "message_page.html")]
pub struct MessagePage {
    pub title: String,
    pub message: String,
}

/// 管理コンソール共通レイアウトのヘッダに載せる管理者識別子（未認証時は `None`）。
/// 各コンソール画面テンプレートが持ち、`console/layout.html` から参照される。
pub type Admin<'a> = Option<&'a str>;

/// 管理コンソールのホーム（`GET /admin/console`）。
#[derive(Template)]
#[template(path = "console/home.html")]
pub struct ConsoleHome<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
}

/// 管理コンソールのログイン画面（`GET /admin/console/login`）。共通レイアウトには載せない。
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
    pub admin: Admin<'a>,
    pub heading: Option<&'a str>,
    pub message: &'a str,
    pub is_error: bool,
    pub back_href: Option<&'a str>,
    pub back_label: &'a str,
}

/// 監査ログ一覧（`GET /admin/console/audit-logs`）。フィルタ値は再入力用に展開済み文字列で渡す。
/// ページャの前後リンク（クエリ文字列を組み立て済み）は該当がなければ `None`。
#[derive(Template)]
#[template(path = "console/audit_logs.html")]
pub struct AuditLogs<'a> {
    pub messages: &'a Messages,
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

/// クライアント状況一覧（`GET /admin/console/status`）。
#[derive(Template)]
#[template(path = "console/client_status.html")]
pub struct ClientStatus<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub views: &'a [ClientStatusResponse],
}

/// 利用者検索画面（`GET /admin/console/users`）。`user` が該当利用者、`not_found` は検索したが
/// 見つからなかったことを表す（未検索時は両方 `None`/`false`）。
#[derive(Template)]
#[template(path = "console/users_search.html")]
pub struct UsersSearch<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub term: &'a str,
    pub user: Option<&'a UserSummaryResponse>,
    pub not_found: bool,
}

/// 利用者の権限画面（`GET /admin/console/users/{id}/permissions`）。
#[derive(Template)]
#[template(path = "console/users_permissions.html")]
pub struct UsersPermissions<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub user: &'a UserSummaryResponse,
    pub codes: &'a [String],
    pub available: &'a [String],
    pub csrf: &'a str,
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

/// クライアント一覧（`GET /admin/console/clients`）。
#[derive(Template)]
#[template(path = "console/clients_list.html")]
pub struct ClientsList<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub clients: &'a [ClientView],
}

/// クライアント登録・編集フォーム（`is_new` で新規/編集を切り替える）。
#[derive(Template)]
#[template(path = "console/client_form.html")]
pub struct ClientForm<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub csrf: &'a str,
    pub error: Option<&'a str>,
    pub heading: &'a str,
    pub action: &'a str,
    pub is_new: bool,
    pub values: &'a ClientFormValues,
}

/// クライアント詳細（`GET /admin/console/clients/{id}`）。
#[derive(Template)]
#[template(path = "console/client_detail.html")]
pub struct ClientDetail<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub client: &'a ClientView,
    pub csrf: &'a str,
}

/// secret 表示画面（作成直後・再発行直後。`secret` が `None` なら public で秘密なし）。
#[derive(Template)]
#[template(path = "console/client_secret.html")]
pub struct ClientSecret<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub heading: &'a str,
    pub client_id: &'a str,
    pub secret: Option<&'a str>,
}

/// 署名鍵一覧・管理画面（`GET /admin/console/signing-keys`、K1）。
#[derive(Template)]
#[template(path = "console/signing_keys.html")]
pub struct SigningKeysList<'a> {
    pub messages: &'a Messages,
    pub admin: Admin<'a>,
    pub keys: &'a [SigningKeyView],
    pub csrf: &'a str,
    pub error: Option<&'a str>,
}
