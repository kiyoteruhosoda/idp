//! 管理コンソールの設定画面（web。`/{tenant_id}/admin/settings`。MT14）。
//!
//! テナント設定区画（自テナント表示名。`idp.tenant.admin`）と、root（`idp.system.admin`）のみに見える
//! システム設定区画（SMTP）を 1 画面に集約する。web はフォーム描画のみを担い、更新は api の
//! `/{tenant_id}/admin/settings/tenant`（PATCH）・`/{tenant_id}/admin/system-settings`（PUT）へ SSO
//! Cookie 転送で委ねる。システム設定区画の可否は「api への GET が 403 か否か」で判定する（root 判定を
//! web が別途持たず、認可の単一の出所を api に集約する）。

use super::locale;
use crate::api_client::AdminApiError;
use crate::config;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{
    AdminRuntimeSettingForm, AdminSystemSettingsForm, AdminTenantSettingsForm, SettingsQuery,
};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AdminSettings, ConsoleNotice};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
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
    // web への未反映（MT27）: web が起動時に受け取った共有設定と、api が今配っている共有設定のずれ。
    // api だけを再起動した状態がこれに当たる（ADR-0013 §Consequences）。システム設定区画を見られない
    // 管理者（root 以外）には出さないので、その場合は問い合わせない。
    let stale_web_keys = if system_result.is_ok() {
        stale_web_shared_settings(&state).await
    } else {
        Vec::new()
    };

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
            tracing::error!(error = %e, "failed to load system settings");
            None
        }
    };

    // 保存済みだが api へ未反映のキー（MT27）。判定は api が返す（規則の単一の出所は core）。
    let pending_api_keys: Vec<String> = system
        .as_ref()
        .map(|s| {
            s.runtime_settings
                .iter()
                .filter(|item| item.pending_restart)
                .map(|item| item.key.clone())
                .collect()
        })
        .unwrap_or_default();

    Html(render(&AdminSettings {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        tenant_id: &tenant_view.id,
        tenant_name: &tenant_view.name,
        tenant_status: &tenant_view.status,
        tenant_self_registration: tenant_view.self_registration_enabled,
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        error_key: query.error.as_deref().and_then(error_key_for),
        system: system.as_ref(),
        pending_api_keys: &pending_api_keys,
        stale_web_keys: &stale_web_keys,
    }))
    .into_response()
}

/// web が起動時に適用した共有設定と、api が現在配っている共有設定を突き合わせ、**web に未反映の**
/// キー名を返す（MT27）。
///
/// 取得に失敗したら空を返す（設定画面そのものは表示できる方が運用上有用で、ここでの失敗は
/// 「未反映が無い」ではなく「判定できない」に過ぎない）。起動時の fail-fast（ADR-0013 §4）とは
/// 目的が違う点に注意する。あちらは誤った設定で動き続けないため、こちらは補助表示のため。
async fn stale_web_shared_settings(state: &WebState) -> Vec<String> {
    match state.api.fetch_shared_runtime_settings().await {
        Ok(current) => {
            config::stale_shared_settings(state.config.shared_runtime_settings(), &current)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to check shared runtime settings for staleness");
            Vec::new()
        }
    }
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
    if !assay_contracts::csrf::verify(
        &console_csrf_token(&sso, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
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
    if !assay_contracts::csrf::verify(
        &console_csrf_token(&sso, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
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
        // SMTP パスワードと同じ規則: 空欄は「変更しない」（キーごと落とす）。
        "sms_gateway_url": form.sms_gateway_url,
        "sms_auth_header": form.sms_auth_header,
        "sms_auth_token": if form.sms_auth_token.is_empty() { None } else { Some(form.sms_auth_token) },
        "sms_sender_id": form.sms_sender_id,
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

/// ランタイム設定の DB 上書き（`POST /{tenant_id}/admin/system-settings/runtime`）。
/// `value` が空欄なら上書きを解除する（既定値・環境変数へ戻る）。反映には再起動が必要。
pub async fn update_runtime(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminRuntimeSettingForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !assay_contracts::csrf::verify(
        &console_csrf_token(&sso, state.config.csrf_secret()),
        &form.csrf_token,
    ) {
        return found(&format!("{base}?error=csrf"));
    }
    let value = form.value.trim();
    let value = (!value.is_empty()).then_some(value);
    match state
        .api
        .update_runtime_setting(&correlation.0, &tenant.0, &sso, form.key.trim(), value)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#runtime-settings")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => {
            found(&format!("{base}?error=runtime-validation#runtime-settings"))
        }
        // 409 = 書式は正しいが、その値では次回起動できない（ADR-0017）。
        Err(AdminApiError::Conflict(_)) => found(&format!(
            "{base}?error=runtime-not-bootable#runtime-settings"
        )),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-settings-error-validation"),
        "runtime-validation" => Some("admin-settings-error-runtime-validation"),
        // 書式は正しいが、その値では起動できない（ADR-0017）。書式エラーと同じ文言にすると
        // 運用者は URL を疑い続けて、実際に足りない secret に辿り着けない。
        "runtime-not-bootable" => Some("admin-settings-error-runtime-not-bootable"),
        "restart" => Some("admin-restart-error"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: None,
        message: &messages.get("admin-error-internal"),
        is_error: true,
        back_href: None,
        back_label: "",
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response()
}
