//! SAML 連携アプリ管理コンソール画面（`/{tenant_id}/admin/saml`）。
//!
//! 登録済みの SAML 連携アプリ（外部 IdP）を一覧し、Entity ID・SSO URL・証明書による
//! 新規追加を提供する。データ操作は api の `/admin/saml-providers` へ SSO Cookie 転送で委譲する。

use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::AdminSamlProviderForm;
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, SamlProviderFormValues, SamlProvidersConsole};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::admin::SamlProviderRegisterRequest;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SamlQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SamlQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let result = state
        .api
        .list_saml_providers(&correlation.0, &tenant.0, &sso)
        .await;
    let messages = Messages::new(locale(&headers));
    let (providers, error_key) = match result {
        Ok(providers) => (providers, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(_) => (Vec::new(), Some("admin-error-internal")),
    };
    Html(render(&SamlProvidersConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &csrf_from(&headers, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        error_key,
        providers: &providers,
        values: &SamlProviderFormValues::default(),
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminSamlProviderForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/saml", tenant.prefix());
    if csrf_from(&headers, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    if form.display_name.trim().is_empty()
        || form.entity_id.trim().is_empty()
        || form.sso_url.trim().is_empty()
        || form.x509_certificate.trim().is_empty()
    {
        return found(&format!("{base}?error=validation"));
    }
    if !sso_url_allowed(&form.sso_url) {
        return found(&format!("{base}?error=sso-url"));
    }

    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .register_saml_provider(
            &correlation.0,
            &tenant.0,
            &sso,
            SamlProviderRegisterRequest {
                display_name: form.display_name,
                entity_id: form.entity_id,
                sso_url: form.sso_url,
                x509_certificate: form.x509_certificate,
                enabled: form.enabled.is_some(),
            },
        )
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(AdminApiError::Conflict(_)) => found(&format!("{base}?error=conflict")),
        Err(AdminApiError::NotFound | AdminApiError::Transport(_)) => {
            found(&format!("{base}?error=internal"))
        }
    }
}

fn csrf_from(headers: &HeaderMap, secret: &[u8]) -> String {
    let sso = crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    console_csrf_token(&sso, secret)
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn sso_url_allowed(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw.trim()) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")),
        _ => false,
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "validation" => Some("admin-saml-error-validation"),
        "sso-url" => Some("admin-saml-error-sso-url"),
        "conflict" => Some("admin-saml-error-conflict"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}
