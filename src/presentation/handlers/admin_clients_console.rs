//! クライアント（RP）管理のサーバレンダリング画面（A1、設計仕様 §9.3）。
//!
//! 既存の JSON 管理 API（`/admin/clients*`、OpenAPI の正典）とは経路を分け、ブラウザ向けに
//! `/admin/console/clients*` で提供する。認可は画面用 extractor [`AdminHtmlSession`]（未認証は
//! ログイン画面へ 302、権限不足は 403 HTML）。データ操作は API と同じ [`ClientManagementService`] を
//! 通す（検証・監査記録・secret 発行のロジックを二重化しない）。
//!
//! 状態変更フォーム（作成／更新／secret 再発行）は SSO セッション由来の同期トークンで CSRF から守る
//! （[`console_csrf_token`]）。利用者入力を HTML へ差し込む箇所はすべて [`html::escape`] を通す。
//!
//! `client_secret` は confidential の作成・再発行時に**その画面でのみ**平文表示する（DB はハッシュのみ）。

use crate::application::client_management::{
    ClientManagementError, RegisterClientCommand, UpdateClientCommand,
};
use crate::domain::client::Client;
use crate::domain::values::{ClientStatus, ClientType};
use crate::presentation::admin::AdminHtmlSession;
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::handlers::admin_console::{console_csrf_token, render_layout};
use crate::presentation::handlers::{found, request_context};
use crate::presentation::html::escape;
use crate::presentation::i18n::{Locale, Messages};
use crate::presentation::state::AppState;
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const CLIENTS_PATH: &str = "/admin/console/clients";

// ── 一覧（GET /admin/console/clients） ────────────────────────────────────────

pub async fn list(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // `Messages`（FluentBundle）は Send でないため await をまたいで保持しない（login.rs と同じ理由）。
    let result = state.clients_admin.list().await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(clients) => Html(render_list(&messages, &admin, &clients)).into_response(),
        Err(e) => internal_error(&messages, &admin, e),
    }
}

// ── 新規登録フォーム（GET /admin/console/clients/new） ─────────────────────────

pub async fn new_form(AdminHtmlSession(admin): AdminHtmlSession, headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    Html(render_new_form(
        &messages,
        &admin,
        &csrf,
        &FormValues::default_new(),
        None,
    ))
    .into_response()
}

// ── 新規登録の実行（POST /admin/console/clients/new） ──────────────────────────

#[derive(Debug, Deserialize)]
pub struct NewClientForm {
    pub app_name: String,
    pub client_type: String,
    pub redirect_uris: String,
    pub scopes: String,
    #[serde(default)]
    pub require_pkce: Option<String>,
    pub csrf_token: String,
}

/// 作成処理の結果（`Messages` を await 後に生成するため、awaitを含む判定を先に確定させる）。
enum CreateOutcome {
    Csrf,
    BadType,
    Created(Box<crate::application::client_management::RegisteredClient>),
    Invalid(String),
    Internal(ClientManagementError),
}

pub async fn create(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<NewClientForm>,
) -> Response {
    let values = FormValues {
        app_name: form.app_name.clone(),
        client_type: form.client_type.clone(),
        redirect_uris: form.redirect_uris.clone(),
        scopes: form.scopes.clone(),
        require_pkce: form.require_pkce.is_some(),
        client_status: ClientStatus::Active.as_str().to_string(),
    };

    let outcome = if !csrf_valid(&headers, &form.csrf_token) {
        CreateOutcome::Csrf
    } else {
        match ClientType::parse(&form.client_type) {
            Err(_) => CreateOutcome::BadType,
            Ok(client_type) => {
                let cmd = RegisterClientCommand {
                    app_name: form.app_name,
                    client_type,
                    redirect_uris: parse_uris(&form.redirect_uris),
                    scopes: parse_scopes(&form.scopes),
                    require_pkce: Some(form.require_pkce.is_some()),
                };
                let ctx = request_context(&headers, &correlation);
                match state.clients_admin.register(cmd, admin.user_id, &ctx).await {
                    Ok(registered) => CreateOutcome::Created(Box::new(registered)),
                    Err(ClientManagementError::Validation(m))
                    | Err(ClientManagementError::Conflict(m)) => CreateOutcome::Invalid(m),
                    Err(e) => CreateOutcome::Internal(e),
                }
            }
        }
    };

    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    match outcome {
        CreateOutcome::Created(registered) => Html(render_secret_result(
            &messages,
            &admin,
            &registered.client,
            registered.client_secret.as_deref(),
            true,
        ))
        .into_response(),
        CreateOutcome::Csrf => bad_request_form(render_new_form(
            &messages,
            &admin,
            &csrf,
            &values,
            Some("admin-error-csrf"),
        )),
        CreateOutcome::BadType => bad_request_form(render_new_form(
            &messages,
            &admin,
            &csrf,
            &values,
            Some("admin-client-error-type"),
        )),
        CreateOutcome::Invalid(m) => bad_request_form(render_new_form_with_message(
            &messages, &admin, &csrf, &values, &m,
        )),
        CreateOutcome::Internal(e) => internal_error(&messages, &admin, e),
    }
}

// ── 詳細（GET /admin/console/clients/{client_id}） ─────────────────────────────

pub async fn detail(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    let result = state.clients_admin.get(&client_id).await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    match result {
        Ok(client) => Html(render_detail(&messages, &admin, &client, &csrf)).into_response(),
        Err(ClientManagementError::NotFound) => not_found(&messages, &admin),
        Err(e) => internal_error(&messages, &admin, e),
    }
}

// ── 編集フォーム（GET /admin/console/clients/{client_id}/edit） ────────────────

pub async fn edit_form(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Response {
    let result = state.clients_admin.get(&client_id).await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    match result {
        Ok(client) => {
            let values = FormValues::from_client(&client);
            Html(render_edit_form(
                &messages, &admin, &client, &csrf, &values, None,
            ))
            .into_response()
        }
        Err(ClientManagementError::NotFound) => not_found(&messages, &admin),
        Err(e) => internal_error(&messages, &admin, e),
    }
}

// ── 編集の実行（POST /admin/console/clients/{client_id}/edit） ─────────────────

#[derive(Debug, Deserialize)]
pub struct EditClientForm {
    pub app_name: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub client_status: String,
    pub csrf_token: String,
}

/// 更新処理の結果（await を含む判定を先に確定させ、`Messages` は await 後に生成する）。
enum UpdateOutcome {
    NotFound,
    Internal(ClientManagementError),
    /// 更新成功。詳細へリダイレクトする。
    Updated,
    /// 再表示が必要（フォーム値保持のため現行 client と任意のエラー文言を持つ）。
    Reshow(Box<Client>, Option<String>, Option<&'static str>),
}

pub async fn update(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Form(form): Form<EditClientForm>,
) -> Response {
    let values = FormValues {
        app_name: form.app_name.clone(),
        client_type: String::new(), // 現行 client から後で埋める（読み取り専用表示用）。
        redirect_uris: form.redirect_uris.clone(),
        scopes: form.scopes.clone(),
        require_pkce: false,
        client_status: form.client_status.clone(),
    };

    let outcome = match state.clients_admin.get(&client_id).await {
        Err(ClientManagementError::NotFound) => UpdateOutcome::NotFound,
        Err(e) => UpdateOutcome::Internal(e),
        Ok(client) => {
            if !csrf_valid(&headers, &form.csrf_token) {
                UpdateOutcome::Reshow(Box::new(client), None, Some("admin-error-csrf"))
            } else {
                match ClientStatus::parse(&form.client_status) {
                    Err(_) => UpdateOutcome::Reshow(
                        Box::new(client),
                        None,
                        Some("admin-client-error-status"),
                    ),
                    Ok(status) => {
                        let cmd = UpdateClientCommand {
                            app_name: Some(form.app_name.clone()),
                            redirect_uris: Some(parse_uris(&form.redirect_uris)),
                            scopes: Some(parse_scopes(&form.scopes)),
                            status: Some(status),
                        };
                        let ctx = request_context(&headers, &correlation);
                        match state
                            .clients_admin
                            .update(&client_id, cmd, admin.user_id, &ctx)
                            .await
                        {
                            Ok(_) => UpdateOutcome::Updated,
                            Err(ClientManagementError::Validation(m))
                            | Err(ClientManagementError::Conflict(m)) => {
                                UpdateOutcome::Reshow(Box::new(client), Some(m), None)
                            }
                            Err(ClientManagementError::NotFound) => UpdateOutcome::NotFound,
                            Err(e) => UpdateOutcome::Internal(e),
                        }
                    }
                }
            }
        }
    };

    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    match outcome {
        UpdateOutcome::Updated => found(&format!("{CLIENTS_PATH}/{client_id}")),
        UpdateOutcome::NotFound => not_found(&messages, &admin),
        UpdateOutcome::Internal(e) => internal_error(&messages, &admin, e),
        UpdateOutcome::Reshow(client, message, error_key) => {
            let mut values = values;
            values.client_type = client.client_type.as_str().to_string();
            values.require_pkce = client.require_pkce;
            let error = message.or_else(|| error_key.map(|k| messages.get(k)));
            bad_request_form(render_edit_form(
                &messages, &admin, &client, &csrf, &values, error,
            ))
        }
    }
}

// ── secret 再発行（POST /admin/console/clients/{client_id}/rotate-secret） ─────

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

enum RotateOutcome {
    Csrf,
    Rotated(Box<Client>, String),
    Invalid(String),
    NotFound,
    Internal(ClientManagementError),
}

pub async fn rotate_secret(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let outcome = if !csrf_valid(&headers, &form.csrf_token) {
        RotateOutcome::Csrf
    } else {
        let ctx = request_context(&headers, &correlation);
        match state
            .clients_admin
            .rotate_secret(&client_id, admin.user_id, &ctx)
            .await
        {
            Ok((client, secret)) => RotateOutcome::Rotated(Box::new(client), secret),
            Err(ClientManagementError::Validation(m)) => RotateOutcome::Invalid(m),
            Err(ClientManagementError::NotFound) => RotateOutcome::NotFound,
            Err(e) => RotateOutcome::Internal(e),
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        RotateOutcome::Rotated(client, secret) => Html(render_secret_result(
            &messages,
            &admin,
            &client,
            Some(&secret),
            false,
        ))
        .into_response(),
        RotateOutcome::Csrf => bad_request_page(&messages, &admin, "admin-error-csrf"),
        RotateOutcome::Invalid(m) => bad_request_page_msg(&messages, &admin, &m),
        RotateOutcome::NotFound => not_found(&messages, &admin),
        RotateOutcome::Internal(e) => internal_error(&messages, &admin, e),
    }
}

// ── フォームの共通表現 ────────────────────────────────────────────────────────

/// 画面へ再表示するためのフォーム値（利用者入力の保持用）。
struct FormValues {
    app_name: String,
    client_type: String,
    redirect_uris: String,
    scopes: String,
    require_pkce: bool,
    client_status: String,
}

impl FormValues {
    fn default_new() -> Self {
        Self {
            app_name: String::new(),
            client_type: ClientType::Confidential.as_str().to_string(),
            redirect_uris: String::new(),
            scopes: "openid".to_string(),
            require_pkce: true,
            client_status: ClientStatus::Active.as_str().to_string(),
        }
    }

    fn from_client(c: &Client) -> Self {
        Self {
            app_name: c.app_name.clone(),
            client_type: c.client_type.as_str().to_string(),
            redirect_uris: c.redirect_uris.join("\n"),
            scopes: c.scopes.join(" "),
            require_pkce: c.require_pkce,
            client_status: c.client_status.as_str().to_string(),
        }
    }
}

// ── 入力パース ────────────────────────────────────────────────────────────────

/// textarea（1 行 1 URI）から redirect URI 群を取り出す。空白・空行は捨てる。
/// URI は空白を含まないため空白区切りでも安全に分割できる。
fn parse_uris(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

/// テキスト入力（空白／カンマ区切り）から scope 群を取り出す。
fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split([' ', '\t', '\n', '\r', ','])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// ── CSRF ─────────────────────────────────────────────────────────────────────

/// フォームへ埋め込む CSRF トークンを SSO Cookie から導出する（Cookie が無ければ空）。
fn csrf_from(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|sso| console_csrf_token(&sso))
        .unwrap_or_default()
}

/// 提出された CSRF トークンが SSO Cookie 由来の期待値と一致するか。
fn csrf_valid(headers: &HeaderMap, submitted: &str) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|sso| console_csrf_token(&sso) == submitted)
        .unwrap_or(false)
}

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_list(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    clients: &[Client],
) -> String {
    let heading = escape(&messages.get("admin-clients-title"));
    let new_label = escape(&messages.get("admin-clients-new"));
    let body = if clients.is_empty() {
        format!("<p>{}</p>", escape(&messages.get("admin-clients-none")))
    } else {
        let rows: String = clients
            .iter()
            .map(|c| {
                format!(
                    "<tr><td><a href=\"{path}/{id}\">{name}</a></td><td><code>{id}</code></td>\
                     <td>{ctype}</td><td>{status}</td><td>{scopes}</td></tr>",
                    path = CLIENTS_PATH,
                    id = escape(&c.client_id),
                    name = escape(&c.app_name),
                    ctype = escape(c.client_type.as_str()),
                    status = escape(c.client_status.as_str()),
                    scopes = escape(&c.scopes.join(" ")),
                )
            })
            .collect();
        format!(
            "<table>\n<thead><tr><th>{name}</th><th>{id}</th><th>{ctype}</th><th>{status}</th><th>{scopes}</th></tr></thead>\n\
             <tbody>{rows}</tbody></table>",
            name = escape(&messages.get("admin-client-col-name")),
            id = escape(&messages.get("admin-client-col-id")),
            ctype = escape(&messages.get("admin-client-col-type")),
            status = escape(&messages.get("admin-client-col-status")),
            scopes = escape(&messages.get("admin-client-col-scopes")),
        )
    };
    let content = format!(
        "<h2>{heading}</h2>\n<p><a href=\"{path}/new\">{new_label}</a></p>\n{body}",
        path = CLIENTS_PATH,
    );
    render_layout(messages, Some(admin), &content)
}

fn render_new_form(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    csrf: &str,
    values: &FormValues,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render_client_form(
        messages,
        admin,
        csrf,
        values,
        error.as_deref(),
        &messages.get("admin-clients-new"),
        &format!("{CLIENTS_PATH}/new"),
        true,
    )
}

fn render_new_form_with_message(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    csrf: &str,
    values: &FormValues,
    error: &str,
) -> String {
    render_client_form(
        messages,
        admin,
        csrf,
        values,
        Some(error),
        &messages.get("admin-clients-new"),
        &format!("{CLIENTS_PATH}/new"),
        true,
    )
}

fn render_edit_form(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    client: &Client,
    csrf: &str,
    values: &FormValues,
    error: Option<String>,
) -> String {
    render_client_form(
        messages,
        admin,
        csrf,
        values,
        error.as_deref(),
        &format!("{}: {}", messages.get("admin-client-edit"), client.app_name),
        &format!("{CLIENTS_PATH}/{}/edit", client.client_id),
        false,
    )
}

/// 作成・編集で共通のクライアントフォーム。`is_new` のときのみ種別選択と PKCE チェックを出す。
#[allow(clippy::too_many_arguments)]
fn render_client_form(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    csrf: &str,
    values: &FormValues,
    error: Option<&str>,
    heading: &str,
    action: &str,
    is_new: bool,
) -> String {
    let error_html = error
        .map(|e| format!("<p class=\"error\" role=\"alert\">{}</p>", escape(e)))
        .unwrap_or_default();

    // 種別（新規は選択、編集は読み取り専用表示）。
    let type_field = if is_new {
        format!(
            "<label>{label}<br>\n<select name=\"client_type\">\n\
             <option value=\"confidential\"{c}>confidential</option>\n\
             <option value=\"public\"{p}>public</option>\n</select></label>",
            label = escape(&messages.get("admin-client-field-type")),
            c = selected(values.client_type == "confidential"),
            p = selected(values.client_type == "public"),
        )
    } else {
        format!(
            "<p>{label}: <code>{value}</code></p>",
            label = escape(&messages.get("admin-client-field-type")),
            value = escape(&values.client_type),
        )
    };

    // PKCE（新規のみ。public は常に必須のため案内を添える）。
    let pkce_field = if is_new {
        format!(
            "<label><input type=\"checkbox\" name=\"require_pkce\"{checked}> {label}</label>\
             <small>{hint}</small>",
            checked = if values.require_pkce { " checked" } else { "" },
            label = escape(&messages.get("admin-client-field-pkce")),
            hint = escape(&messages.get("admin-client-field-pkce-hint")),
        )
    } else {
        String::new()
    };

    // 状態（編集のみ）。
    let status_field = if is_new {
        String::new()
    } else {
        format!(
            "<label>{label}<br>\n<select name=\"client_status\">\n\
             <option value=\"ACTIVE\"{a}>ACTIVE</option>\n\
             <option value=\"DISABLED\"{d}>DISABLED</option>\n</select></label>",
            label = escape(&messages.get("admin-client-field-status")),
            a = selected(values.client_status == "ACTIVE"),
            d = selected(values.client_status == "DISABLED"),
        )
    };

    let content = format!(
        "<h2>{heading}</h2>\n{error_html}\n\
         <form method=\"post\" action=\"{action}\">\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
         <p><label>{name_label}<br>\n<input type=\"text\" name=\"app_name\" value=\"{app_name}\" required></label></p>\n\
         <p>{type_field}</p>\n\
         <p><label>{uris_label}<br>\n<textarea name=\"redirect_uris\" rows=\"4\" cols=\"60\">{uris}</textarea></label><br><small>{uris_hint}</small></p>\n\
         <p><label>{scopes_label}<br>\n<input type=\"text\" name=\"scopes\" value=\"{scopes}\"></label><br><small>{scopes_hint}</small></p>\n\
         <p>{status_field}</p>\n\
         <p>{pkce_field}</p>\n\
         <p><button type=\"submit\">{submit}</button> <a href=\"{path}\">{cancel}</a></p>\n\
         </form>",
        heading = escape(heading),
        csrf = escape(csrf),
        name_label = escape(&messages.get("admin-client-field-name")),
        app_name = escape(&values.app_name),
        uris_label = escape(&messages.get("admin-client-field-uris")),
        uris = escape(&values.redirect_uris),
        uris_hint = escape(&messages.get("admin-client-field-uris-hint")),
        scopes_label = escape(&messages.get("admin-client-field-scopes")),
        scopes = escape(&values.scopes),
        scopes_hint = escape(&messages.get("admin-client-field-scopes-hint")),
        submit = escape(&messages.get("admin-form-save")),
        cancel = escape(&messages.get("admin-form-cancel")),
        path = CLIENTS_PATH,
    );
    render_layout(messages, Some(admin), &content)
}

fn render_detail(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    client: &Client,
    csrf: &str,
) -> String {
    let rotate = if client.client_type == ClientType::Confidential {
        format!(
            "<form method=\"post\" action=\"{path}/{id}/rotate-secret\">\
             <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
             <button type=\"submit\">{label}</button></form>",
            path = CLIENTS_PATH,
            id = escape(&client.client_id),
            csrf = escape(csrf),
            label = escape(&messages.get("admin-client-rotate-secret")),
        )
    } else {
        String::new()
    };

    let content = format!(
        "<h2>{name}</h2>\n\
         <dl>\n\
         <dt>{id_label}</dt><dd><code>{id}</code></dd>\n\
         <dt>{type_label}</dt><dd>{ctype}</dd>\n\
         <dt>{status_label}</dt><dd>{status}</dd>\n\
         <dt>{auth_label}</dt><dd>{auth}</dd>\n\
         <dt>{pkce_label}</dt><dd>{pkce}</dd>\n\
         <dt>{uris_label}</dt><dd>{uris}</dd>\n\
         <dt>{scopes_label}</dt><dd>{scopes}</dd>\n\
         <dt>{grant_label}</dt><dd>{grants}</dd>\n\
         <dt>{created_label}</dt><dd>{created}</dd>\n\
         <dt>{updated_label}</dt><dd>{updated}</dd>\n\
         </dl>\n\
         <p><a href=\"{path}/{id}/edit\">{edit}</a> | <a href=\"{path}\">{back}</a></p>\n\
         {rotate}",
        name = escape(&client.app_name),
        id_label = escape(&messages.get("admin-client-col-id")),
        id = escape(&client.client_id),
        type_label = escape(&messages.get("admin-client-col-type")),
        ctype = escape(client.client_type.as_str()),
        status_label = escape(&messages.get("admin-client-col-status")),
        status = escape(client.client_status.as_str()),
        auth_label = escape(&messages.get("admin-client-field-auth-method")),
        auth = escape(client.token_endpoint_auth_method.as_str()),
        pkce_label = escape(&messages.get("admin-client-field-pkce")),
        pkce = if client.require_pkce { "true" } else { "false" },
        uris_label = escape(&messages.get("admin-client-field-uris")),
        uris = render_list_items(&client.redirect_uris),
        scopes_label = escape(&messages.get("admin-client-col-scopes")),
        scopes = escape(&client.scopes.join(" ")),
        grant_label = escape(&messages.get("admin-client-field-grants")),
        grants = escape(&client.grant_types.join(" ")),
        created_label = escape(&messages.get("admin-client-field-created")),
        created = escape(&client.created_at.to_rfc3339()),
        updated_label = escape(&messages.get("admin-client-field-updated")),
        updated = escape(&client.updated_at.to_rfc3339()),
        path = CLIENTS_PATH,
        edit = escape(&messages.get("admin-client-edit")),
        back = escape(&messages.get("admin-client-back")),
        rotate = rotate,
    );
    render_layout(messages, Some(admin), &content)
}

/// 作成・再発行後に client_secret を一度だけ表示する結果画面。
fn render_secret_result(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    client: &Client,
    secret: Option<&str>,
    is_new: bool,
) -> String {
    let heading = if is_new {
        messages.get("admin-client-created-title")
    } else {
        messages.get("admin-client-secret-rotated-title")
    };
    let secret_html = match secret {
        Some(s) => format!(
            "<p class=\"secret-warning\">{warn}</p>\n\
             <p>{label}: <code>{secret}</code></p>",
            warn = escape(&messages.get("admin-client-secret-warning")),
            label = escape(&messages.get("admin-client-secret-label")),
            secret = escape(s),
        ),
        // public クライアントは secret を持たない。
        None => format!("<p>{}</p>", escape(&messages.get("admin-client-no-secret"))),
    };
    let content = format!(
        "<h2>{heading}</h2>\n\
         <p>{id_label}: <code>{id}</code></p>\n\
         {secret_html}\n\
         <p><a href=\"{path}/{id}\">{detail}</a> | <a href=\"{path}\">{back}</a></p>",
        heading = escape(&heading),
        id_label = escape(&messages.get("admin-client-col-id")),
        id = escape(&client.client_id),
        path = CLIENTS_PATH,
        detail = escape(&messages.get("admin-client-detail")),
        back = escape(&messages.get("admin-client-back")),
    );
    render_layout(messages, Some(admin), &content)
}

/// 文字列群を `<ul>` として描画する（各要素はエスケープ）。
fn render_list_items(items: &[String]) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    let lis: String = items
        .iter()
        .map(|i| format!("<li><code>{}</code></li>", escape(i)))
        .collect();
    format!("<ul>{lis}</ul>")
}

fn render_not_found_page(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
) -> String {
    let content = format!(
        "<h2>{title}</h2>\n<p>{msg}</p>\n<p><a href=\"{path}\">{back}</a></p>",
        title = escape(&messages.get("admin-client-not-found-title")),
        msg = escape(&messages.get("admin-client-not-found-message")),
        path = CLIENTS_PATH,
        back = escape(&messages.get("admin-client-back")),
    );
    render_layout(messages, Some(admin), &content)
}

// ── レスポンスの共通ヘルパー ──────────────────────────────────────────────────

fn selected(on: bool) -> &'static str {
    if on {
        " selected"
    } else {
        ""
    }
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn bad_request_form(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

fn bad_request_page(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    error_key: &str,
) -> Response {
    bad_request_page_msg(messages, admin, &messages.get(error_key))
}

fn bad_request_page_msg(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    message: &str,
) -> Response {
    let content = format!(
        "<p class=\"error\" role=\"alert\">{}</p>\n<p><a href=\"{path}\">{back}</a></p>",
        escape(message),
        path = CLIENTS_PATH,
        back = escape(&messages.get("admin-client-back")),
    );
    (
        StatusCode::BAD_REQUEST,
        Html(render_layout(messages, Some(admin), &content)),
    )
        .into_response()
}

fn not_found(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render_not_found_page(messages, admin)),
    )
        .into_response()
}

fn internal_error(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    e: ClientManagementError,
) -> Response {
    tracing::error!(error = %e, "admin client console failed");
    let content = format!(
        "<p class=\"error\" role=\"alert\">{}</p>",
        escape(&messages.get("admin-error-internal"))
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render_layout(messages, Some(admin), &content)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uris_splits_and_drops_blanks() {
        let raw = "https://a.example.com/cb\n  https://b.example.com/cb \n\n";
        assert_eq!(
            parse_uris(raw),
            vec![
                "https://a.example.com/cb".to_string(),
                "https://b.example.com/cb".to_string()
            ]
        );
        assert!(parse_uris("   \n  ").is_empty());
    }

    #[test]
    fn parse_scopes_splits_on_space_and_comma() {
        assert_eq!(
            parse_scopes("openid, profile  email"),
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string()
            ]
        );
        assert!(parse_scopes("").is_empty());
    }

    #[test]
    fn list_escapes_client_fields() {
        let messages = Messages::new(Locale::En);
        let admin = crate::application::admin_access::AuthorizedAdmin {
            user_id: uuid::Uuid::new_v4(),
        };
        let client = Client {
            id: uuid::Uuid::new_v4(),
            client_id: "abc123".to_string(),
            client_secret_hash: None,
            client_type: ClientType::Public,
            client_status: ClientStatus::Active,
            app_name: "<script>Evil</script>".to_string(),
            redirect_uris: vec!["https://a.example.com/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string()],
            token_endpoint_auth_method: crate::domain::values::TokenEndpointAuthMethod::None,
            require_pkce: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let html = render_list(&messages, &admin, &[client]);
        assert!(html.contains("&lt;script&gt;Evil&lt;/script&gt;"));
        assert!(!html.contains("<script>Evil"));
    }
}
