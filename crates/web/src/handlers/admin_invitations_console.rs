//! ゲスト招待作成画面（web。ADR-0009 §3・§6・MT13）。
//!
//! api の JSON 管理 API（`POST /admin/invitations`）を管理者の SSO Cookie 転送で呼ぶ。招待対象は
//! 所属元が他テナントの既存利用者で、内部 ID（UUID）で指定する（利用者検索は所属元テナント限定の
//! ため、本画面では ID を管理者が別途確認して入力する）。招待トークンはこの結果画面でのみ表示する。

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, InvitationCreated, InvitationForm};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

/// 招待フォーム（`GET /{tenant_id}/admin/invitations`）。
pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    Html(render_form(&messages, &tenant, &admin, &csrf, "", None)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct InvitationRequestForm {
    pub user_id: String,
    pub csrf_token: String,
}

/// 招待の作成（`POST /{tenant_id}/admin/invitations`）。招待トークンを一度だけ表示する。
pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<InvitationRequestForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
        return bad_request(render_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &form.user_id,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .create_invitation(&correlation.0, &tenant.0, &sso(&headers), &form.user_id)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(created) => Html(render(&InvitationCreated {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(&admin),
            token: &created.token,
            expires_at: &created.expires_at,
            email_sent: created.email_sent,
            invitee_email: &created.invitee_email,
        }))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => {
            let csrf = csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.user_id,
                &m,
            ))
        }
        Err(AdminApiError::NotFound) => {
            let csrf = csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.user_id,
                &messages.get("admin-invitations-error-notfound"),
            ))
        }
        Err(_) => {
            let csrf = csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.user_id,
                &messages.get("admin-error-internal"),
            ))
        }
    }
}

fn render_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    user_id: &str,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&InvitationForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: error.as_deref(),
        user_id,
    })
}

fn render_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    user_id: &str,
    error: &str,
) -> String {
    render(&InvitationForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: Some(error),
        user_id,
    })
}

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

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
