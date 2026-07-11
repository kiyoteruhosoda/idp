//! テナントメンバー（HOME/GUEST）管理画面（web。ADR-0009 §3・§6・MT13）。
//!
//! api の JSON 管理 API（`GET /admin/members`・`DELETE /admin/members/{user_id}`）を管理者の SSO Cookie
//! 転送で呼ぶ。ゲストメンバーシップの解除のみでき、HOME は解除できない（api 側が 403 を返す）。

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
use crate::templates::{render, ConsoleNotice, MembersList};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const MEMBERS_SEGMENT: &str = "/admin/members";

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
}

/// メンバー一覧（`GET /{tenant_id}/admin/members`）。
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let result = state
        .api
        .list_members(&correlation.0, &tenant.0, &sso(&headers))
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    let error_key = query.error.as_deref().and_then(error_key_for);
    match result {
        Ok(members) => Html(render(&MembersList {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(&admin),
            members: &members,
            csrf: &csrf,
            error_key,
        }))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub csrf_token: String,
}

/// ゲストメンバーシップの解除（`POST /{tenant_id}/admin/members/{user_id}/revoke`）。
pub async fn revoke(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<RevokeForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .revoke_member(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-members-error-home"),
        "notfound" => Some("admin-members-error-notfound"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s) == submitted)
        .unwrap_or(false)
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &str) -> Response {
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
