//! 管理コンソールの設定画面（web。`/{tenant_id}/admin/settings`。MT14）。
//!
//! テナント設定区画（自テナント表示名。`idp.tenant.admin`）と、root（`idp.system.admin`）のみに見える
//! システム設定区画（SMTP）を 1 画面に集約する。web はフォーム描画のみを担い、更新は api の
//! `/{tenant_id}/admin/settings/tenant`（PATCH）・`/{tenant_id}/admin/system-settings`（PUT）へ SSO
//! Cookie 転送で委ねる。システム設定区画の可否は「api への GET が 403 か否か」で判定する（root 判定を
//! web が別途持たず、認可の単一の出所を api に集約する）。

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{AdminSystemSettingsForm, AdminTenantSettingsForm, SettingsQuery};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, AdminSettings, ConsoleNotice};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

const SETTINGS_SEGMENT: &str = "/admin/settings";

/// 設定画面（`GET /{tenant_id}/admin/settings`）。
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);

    // FluentBundle（Messages）は !Send のため、api 呼び出し（await）はすべて先に済ませてから生成する。
    let tenant_result = state
        .api
        .get_current_tenant(&correlation.0, &tenant.0, &sso)
        .await;
    // システム設定区画は root（idp.system.admin）のみ。403 は「root ではない」ことを意味するので非表示にする。
    let system_result = state
        .api
        .get_system_settings(&correlation.0, &tenant.0, &sso)
        .await;

    let messages = Messages::new(locale(&headers));

    let tenant_view = match tenant_result {
        Ok(t) => t,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return forbidden_response(&headers),
        Err(_) => return internal_error(&messages, &tenant, &admin),
    };

    let system = match system_result {
        Ok(s) => Some(s),
        Err(AdminApiError::Forbidden) => None,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(e) => {
            tracing::error!(error = %describe(&e), "failed to load system settings");
            None
        }
    };

    Html(render(&AdminSettings {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        tenant_id: &tenant_view.id,
        tenant_name: &tenant_view.name,
        tenant_status: &tenant_view.status,
        tenant_self_registration: tenant_view.self_registration_enabled,
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        error_key: query.error.as_deref().and_then(error_key_for),
        system: system.as_ref(),
    }))
    .into_response()
}

/// テナント表示名の更新（`POST /{tenant_id}/admin/settings/tenant`）。
pub async fn update_tenant(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSettingsForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .update_current_tenant(
            &correlation.0,
            &tenant.0,
            &sso,
            form.name.trim(),
            form.self_registration_enabled.is_some(),
        )
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// システム設定（SMTP）の更新（`POST /{tenant_id}/admin/system-settings`）。
pub async fn update_system(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminSystemSettingsForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if console_csrf_token(&sso, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    let port: Option<u16> = {
        let trimmed = form.smtp_port.trim();
        if trimmed.is_empty() {
            None
        } else {
            match trimmed.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => return found(&format!("{base}?error=validation")),
            }
        }
    };
    // 空欄は「現行維持」（null を送ると api 側で維持される）。
    let password: Option<String> = if form.smtp_password.is_empty() {
        None
    } else {
        Some(form.smtp_password)
    };
    let body = serde_json::json!({
        "smtp_host": form.smtp_host,
        "smtp_port": port,
        "smtp_username": form.smtp_username,
        "smtp_password": password,
        "smtp_from_address": form.smtp_from_address,
        "smtp_use_tls": form.smtp_use_tls.is_some(),
    });
    match state
        .api
        .update_system_settings(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-settings-error-validation"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
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
