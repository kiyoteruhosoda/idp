//! root 管理者向けテナント一覧・登録画面（web）。
//!
//! 画面は React 風の reducer/component 分割を持つ小さなプログレッシブ UI として再構成し、
//! 認可・永続化は api の `/{tenant_id}/admin/tenants`（`idp.system.admin` 必須）へ委譲する。

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{
    AdminPasswordResetForm, AdminTenantActionForm, AdminTenantCreateForm, TenantsQuery,
};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, PasswordResetResult, TenantCreated, TenantsConsole};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

const TENANTS_SEGMENT: &str = "/admin/tenants";

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<TenantsQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);
    let tenants = match state
        .api
        .list_tenants(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return forbidden_response(&headers),
        Err(e) => {
            tracing::error!(error = %describe(&e), "failed to load tenants");
            Vec::new()
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&TenantsConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        tenants: &tenants,
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantCreateForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    let created = match state
        .api
        .create_tenant(
            &correlation.0,
            &tenant.0,
            &sso,
            form.name.trim(),
            form.admin_email.trim(),
        )
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => return found(&format!("{base}?error=validation")),
        Err(AdminApiError::Conflict(_)) => return found(&format!("{base}?error=conflict")),
        Err(e) => {
            tracing::error!(error = %describe(&e), "failed to create tenant");
            return found(&format!("{base}?error=internal"));
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&TenantCreated {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        created: &created,
    }))
    .into_response()
}

/// 子テナントの削除（`POST /{tenant_id}/admin/tenants/{child_id}/delete`）。配下に子テナント・
/// ユーザー・クライアントが残っている場合は api が 409 を返す（`?error=delete-conflict`）。
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, child_id)): Path<(String, String)>,
    Form(form): Form<AdminTenantActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_tenant(&correlation.0, &tenant.0, &sso, &child_id)
        .await
    {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(AdminApiError::Conflict(_)) => found(&format!("{base}?error=delete-conflict")),
        Err(e) => {
            tracing::error!(error = %describe(&e), "failed to delete tenant");
            found(&format!("{base}?error=internal"))
        }
    }
}

/// 子テナント管理者のパスワード再発行
/// （`POST /{tenant_id}/admin/tenants/{child_id}/reset-admin-password`）。
/// 成功時は生成パスワードを一度だけ表示する。
pub async fn reset_admin_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, child_id)): Path<(String, String)>,
    Form(form): Form<AdminPasswordResetForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    let email = form.email.trim();
    if email.is_empty() {
        return found(&format!("{base}?error=validation"));
    }
    let reset = match state
        .api
        .reset_tenant_admin_password(&correlation.0, &tenant.0, &sso, &child_id, email)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => return found(&format!("{base}?error=reset-notfound")),
        Err(AdminApiError::Validation(_)) => return found(&format!("{base}?error=validation")),
        Err(e) => {
            tracing::error!(error = %describe(&e), "failed to reset tenant admin password");
            return found(&format!("{base}?error=internal"));
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&PasswordResetResult {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        subject: email,
        generated_password: &reset.generated_password,
        back_href: &base,
        back_label_key: "admin-tenants-back",
    }))
    .into_response()
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-tenants-error-forbidden"),
        "validation" => Some("admin-tenants-error-validation"),
        "conflict" => Some("admin-tenants-error-conflict"),
        "delete-conflict" => Some("admin-tenants-error-delete-conflict"),
        "notfound" => Some("admin-tenants-error-notfound"),
        "reset-notfound" => Some("admin-tenants-error-reset-notfound"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn describe(e: &AdminApiError) -> String {
    match e {
        AdminApiError::Unauthorized => "unauthorized".to_string(),
        AdminApiError::Forbidden => "forbidden".to_string(),
        AdminApiError::NotFound => "not_found".to_string(),
        AdminApiError::Validation(m) => format!("validation: {m}"),
        AdminApiError::Conflict(m) => format!("conflict: {m}"),
        AdminApiError::Transport(m) => format!("transport: {m}"),
    }
}
