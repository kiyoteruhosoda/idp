//! クライアント（RP）管理のサーバレンダリング画面（web。ADR-0007 §4）。
//!
//! api の JSON 管理 API（`/admin/clients*`、`RequirePerms<IdpAdmin>`）を管理者の SSO Cookie 転送で呼び、
//! 結果を HTML に描画する。認可・データ操作・監査は api 側。web は画面と CSRF（`console_csrf_token`）のみ。
//! HTML の描画は Askama テンプレート（`templates/console/`）で行い、利用者入力は自動エスケープされる。
//! `client_secret` は作成・再発行時にその画面でのみ平文表示する。

use crate::admin_dto::{ClientCreatedView, ClientView};
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{
    render, ClientDetail, ClientForm, ClientFormValues, ClientSecret, ClientsList, ConsoleNotice,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::json;

const CLIENTS_SEGMENT: &str = "/admin/clients";

/// 各ハンドラ冒頭の共通前処理: 管理者を解決し、user_id を返すか誘導 Response を返す。
macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

// ── 一覧 ──────────────────────────────────────────────────────────────────────

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let result = state
        .api
        .list_clients(&correlation.0, &tenant.0, &sso(&headers))
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(clients) => Html(render_list(&messages, &tenant, &admin, &clients)).into_response(),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── 新規登録フォーム ──────────────────────────────────────────────────────────

pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    Html(render_new_form(
        &messages,
        &tenant,
        &admin,
        &csrf,
        &ClientFormValues::default_new(),
        None,
    ))
    .into_response()
}

// ── 新規登録の実行 ────────────────────────────────────────────────────────────

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

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<NewClientForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let values = ClientFormValues {
        app_name: form.app_name.clone(),
        client_type: form.client_type.clone(),
        redirect_uris: form.redirect_uris.clone(),
        scopes: form.scopes.clone(),
        require_pkce: form.require_pkce.is_some(),
        client_status: "ACTIVE".to_string(),
    };

    // Messages（FluentBundle）は Send でないため、api の await をまたいで保持しない（login.rs と同じ理由）。
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
        return bad_request_form(render_new_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &values,
            Some("admin-error-csrf"),
        ));
    }

    let body = json!({
        "app_name": form.app_name,
        "client_type": form.client_type,
        "redirect_uris": parse_uris(&form.redirect_uris),
        "scopes": parse_scopes(&form.scopes),
        "require_pkce": form.require_pkce.is_some(),
    });
    let result = state
        .api
        .create_client(&correlation.0, &tenant.0, &sso(&headers), body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(created) => Html(render_secret_result(
            &messages, &tenant, &admin, &created, true,
        ))
        .into_response(),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => bad_request_form(
            render_new_form_with_message(&messages, &tenant, &admin, &csrf, &values, &m),
        ),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── 詳細 ──────────────────────────────────────────────────────────────────────

pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let result = state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(client) => {
            Html(render_detail(&messages, &tenant, &admin, &client, &csrf)).into_response()
        }
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── 編集フォーム ──────────────────────────────────────────────────────────────

pub async fn edit_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let result = state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(client) => {
            let values = ClientFormValues::from_client(&client);
            Html(render_edit_form(
                &messages, &tenant, &admin, &client, &csrf, &values, None,
            ))
            .into_response()
        }
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── 編集の実行 ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EditClientForm {
    pub app_name: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub client_status: String,
    pub csrf_token: String,
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<EditClientForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    // 再表示に備え、現行 client を取得する（種別など読み取り専用表示のため）。ClientView は Send。
    let client = match state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await
    {
        Ok(c) => c,
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            return not_found(&messages, &tenant, &admin);
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    let mut values = ClientFormValues::from_client(&client);
    values.app_name = form.app_name.clone();
    values.redirect_uris = form.redirect_uris.clone();
    values.scopes = form.scopes.clone();
    values.client_status = form.client_status.clone();

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
        let err = messages.get("admin-error-csrf");
        return bad_request_form(render_edit_form(
            &messages,
            &tenant,
            &admin,
            &client,
            &csrf,
            &values,
            Some(err),
        ));
    }

    let body = json!({
        "app_name": form.app_name,
        "redirect_uris": parse_uris(&form.redirect_uris),
        "scopes": parse_scopes(&form.scopes),
        "client_status": form.client_status,
    });
    let result = state
        .api
        .update_client(&correlation.0, &tenant.0, &sso(&headers), &client_id, body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(_) => found(&format!("{}{CLIENTS_SEGMENT}/{client_id}", tenant.prefix())),
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => bad_request_form(
            render_edit_form(&messages, &tenant, &admin, &client, &csrf, &values, Some(m)),
        ),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── secret 再発行 ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

pub async fn rotate_secret(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        return bad_request_page(&messages, &tenant, &admin, "admin-error-csrf");
    }
    let rotated = state
        .api
        .rotate_client_secret(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    match rotated {
        Ok(secret) => {
            // 再発行結果は詳細を取り直して表示する（ClientView は Send）。
            let client = state
                .api
                .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
                .await;
            let messages = Messages::new(locale(&headers));
            match client {
                Ok(client) => Html(render_rotated_result(
                    &messages,
                    &tenant,
                    &admin,
                    &client,
                    &secret.client_secret,
                ))
                .into_response(),
                Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
            }
        }
        Err(AdminApiError::Validation(m)) => {
            let messages = Messages::new(locale(&headers));
            bad_request_page_msg(&messages, &tenant, &admin, &m)
        }
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &tenant, &admin)
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_data_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

// ── フォームの共通表現・パース ────────────────────────────────────────────────

fn parse_uris(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

fn parse_scopes(raw: &str) -> Vec<String> {
    raw.split([' ', '\t', '\n', '\r', ','])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// ── CSRF ─────────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key) == submitted)
        .unwrap_or(false)
}

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    clients: &[ClientView],
) -> String {
    render(&ClientsList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        clients,
    })
}

fn render_new_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    values: &ClientFormValues,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: error.as_deref(),
        heading: &messages.get("admin-clients-new"),
        action: &format!("{}{CLIENTS_SEGMENT}/new", tenant.prefix()),
        is_new: true,
        values,
    })
}

fn render_new_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    values: &ClientFormValues,
    error: &str,
) -> String {
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: Some(error),
        heading: &messages.get("admin-clients-new"),
        action: &format!("{}{CLIENTS_SEGMENT}/new", tenant.prefix()),
        is_new: true,
        values,
    })
}

fn render_edit_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    client: &ClientView,
    csrf: &str,
    values: &ClientFormValues,
    error: Option<String>,
) -> String {
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: error.as_deref(),
        heading: &format!("{}: {}", messages.get("admin-client-edit"), client.app_name),
        action: &format!(
            "{}{CLIENTS_SEGMENT}/{}/edit",
            tenant.prefix(),
            client.client_id
        ),
        is_new: false,
        values,
    })
}

fn render_detail(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    client: &ClientView,
    csrf: &str,
) -> String {
    render(&ClientDetail {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        client,
        csrf,
    })
}

fn render_secret_result(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    created: &ClientCreatedView,
    is_new: bool,
) -> String {
    render_secret_page(
        messages,
        tenant,
        admin,
        &created.client.client_id,
        created.client_secret.as_deref(),
        is_new,
    )
}

fn render_rotated_result(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    client: &ClientView,
    secret: &str,
) -> String {
    render_secret_page(
        messages,
        tenant,
        admin,
        &client.client_id,
        Some(secret),
        false,
    )
}

fn render_secret_page(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    client_id: &str,
    secret: Option<&str>,
    is_new: bool,
) -> String {
    let heading = if is_new {
        messages.get("admin-client-created-title")
    } else {
        messages.get("admin-client-secret-rotated-title")
    };
    render(&ClientSecret {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        heading: &heading,
        client_id,
        secret,
    })
}

// ── レスポンスの共通ヘルパー ──────────────────────────────────────────────────

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

/// api の 401/403 を web の画面挙動へ写す（ログイン誘導 / 403 画面）。それ以外は 500。
fn map_data_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        AdminApiError::NotFound => not_found(messages, tenant, admin),
        other => {
            tracing::error!(error = ?debug_error(&other), "admin client console data error");
            let body = render(&ConsoleNotice {
                messages,
                tenant: &tenant.prefix(),
                admin: Some(admin),
                heading: None,
                message: &messages.get("admin-error-internal"),
                is_error: true,
                back_href: None,
                back_label: "",
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response()
        }
    }
}

fn debug_error(e: &AdminApiError) -> String {
    match e {
        AdminApiError::Validation(m) => format!("validation: {m}"),
        AdminApiError::Conflict(m) => format!("conflict: {m}"),
        AdminApiError::Transport(m) => format!("transport: {m}"),
        AdminApiError::NotFound => "not_found".into(),
        AdminApiError::Unauthorized => "unauthorized".into(),
        AdminApiError::Forbidden => "forbidden".into(),
    }
}

fn bad_request_form(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

fn bad_request_page(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    error_key: &str,
) -> Response {
    bad_request_page_msg(messages, tenant, admin, &messages.get(error_key))
}

fn bad_request_page_msg(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    message: &str,
) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        heading: None,
        message,
        is_error: true,
        back_href: Some(&format!("{}{CLIENTS_SEGMENT}", tenant.prefix())),
        back_label: &messages.get("admin-client-back"),
    });
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &str) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        heading: Some(&messages.get("admin-client-not-found-title")),
        message: &messages.get("admin-client-not-found-message"),
        is_error: false,
        back_href: Some(&format!("{}{CLIENTS_SEGMENT}", tenant.prefix())),
        back_label: &messages.get("admin-client-back"),
    });
    (StatusCode::NOT_FOUND, Html(body)).into_response()
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
    }

    #[test]
    fn list_escapes_client_fields() {
        let messages = Messages::new(Locale::Ja);
        let client = ClientView {
            id: "id".into(),
            client_id: "abc123".into(),
            client_type: "public".into(),
            client_status: "ACTIVE".into(),
            app_name: "<script>Evil</script>".into(),
            redirect_uris: vec!["https://a.example.com/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scopes: vec!["openid".into()],
            token_endpoint_auth_method: "none".into(),
            require_pkce: true,
            created_at: "2026-07-06T00:00:00Z".into(),
            updated_at: "2026-07-06T00:00:00Z".into(),
        };
        let tenant = WebTenant("00000000-0000-7000-8000-000000000000".to_string());
        let html = render_list(&messages, &tenant, "admin-1", &[client]);
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。生タグが残らないことを確認する。
        assert!(html.contains("&#60;script&#62;Evil&#60;/script&#62;"));
        assert!(!html.contains("<script>Evil"));
    }
}
