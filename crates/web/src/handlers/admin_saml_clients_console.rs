//! SAML SP（クライアント）管理コンソール画面（`/{tenant_id}/admin/saml-clients`）。
//!
//! 本プロダクト（IdP）が信頼する SP を一覧・追加する。SP メタデータ XML の取り込みで登録フォームを
//! 初期化できる。データ操作は api の `/admin/saml-service-providers` へ SSO Cookie 転送で委譲する。

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{AdminSamlServiceProviderForm, AdminSamlSpMetadataImportForm};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, SamlServiceProviderFormValues, SamlServiceProvidersConsole};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::admin::SamlServiceProviderRegisterRequest;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SamlClientQuery {
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
    Query(query): Query<SamlClientQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let result = state
        .api
        .list_saml_service_providers(&correlation.0, &tenant.0, &sso)
        .await;
    let (providers, error_key) = match result {
        Ok(providers) => (providers, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(_) => (Vec::new(), Some("admin-error-internal")),
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&SamlServiceProvidersConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &csrf_from(&headers, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        imported: false,
        error_key,
        providers: &providers,
        values: &SamlServiceProviderFormValues::default(),
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminSamlServiceProviderForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/saml-clients", tenant.prefix());
    if csrf_from(&headers, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    if form.display_name.trim().is_empty()
        || form.entity_id.trim().is_empty()
        || form.acs_url.trim().is_empty()
    {
        return found(&format!("{base}?error=validation"));
    }
    if !acs_url_allowed(&form.acs_url) {
        return found(&format!("{base}?error=acs-url"));
    }

    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let x509 = form.x509_certificate.trim();
    match state
        .api
        .register_saml_service_provider(
            &correlation.0,
            &tenant.0,
            &sso,
            SamlServiceProviderRegisterRequest {
                display_name: form.display_name,
                entity_id: form.entity_id,
                acs_url: form.acs_url,
                name_id_format: form.name_id_format,
                x509_certificate: (!x509.is_empty()).then(|| x509.to_string()),
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

/// SP メタデータ XML を取り込み、登録フォームに初期値を反映して再描画する（PRG は挟まない）。
pub async fn import_metadata(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminSamlSpMetadataImportForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}/admin/saml-clients", tenant.prefix());
    if csrf_from(&headers, state.config.csrf_secret()) != form.csrf_token {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();

    let (values, imported, error_key) = match state
        .api
        .import_saml_sp_metadata(&correlation.0, &tenant.0, &sso, &form.metadata_xml)
        .await
    {
        Ok(parsed) => (
            SamlServiceProviderFormValues {
                display_name: parsed.display_name,
                entity_id: parsed.entity_id,
                acs_url: parsed.acs_url,
                name_id_format: parsed.name_id_format,
                x509_certificate: parsed.x509_certificate,
                enabled: true,
            },
            true,
            None,
        ),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (
            SamlServiceProviderFormValues::default(),
            false,
            Some("admin-settings-error-forbidden"),
        ),
        Err(AdminApiError::Validation(_) | AdminApiError::NotFound) => (
            SamlServiceProviderFormValues::default(),
            false,
            Some("admin-saml-client-error-import"),
        ),
        Err(AdminApiError::Conflict(_) | AdminApiError::Transport(_)) => (
            SamlServiceProviderFormValues::default(),
            false,
            Some("admin-error-internal"),
        ),
    };

    let providers = state
        .api
        .list_saml_service_providers(&correlation.0, &tenant.0, &sso)
        .await
        .unwrap_or_default();

    let messages = Messages::new(locale(&headers));
    Html(render(&SamlServiceProvidersConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &csrf_from(&headers, state.config.csrf_secret()),
        saved: false,
        imported,
        error_key,
        providers: &providers,
        values: &values,
    }))
    .into_response()
}

fn csrf_from(headers: &HeaderMap, secret: &[u8]) -> String {
    let sso = crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    console_csrf_token(&sso, secret)
}

fn acs_url_allowed(raw: &str) -> bool {
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
        "validation" => Some("admin-saml-client-error-validation"),
        "acs-url" => Some("admin-saml-client-error-acs-url"),
        "conflict" => Some("admin-saml-client-error-conflict"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}
