//! SAML SP (client) admin console screen (`/{tenant_id}/admin/saml-clients`).
//!
//! Lists, adds, changes and deletes the SPs this product (the IdP) trusts. The registration form can be
//! prefilled by importing SP metadata XML. Data operations are delegated to the api's `/admin/saml-service-providers`
//! by forwarding the SSO cookie (HTML forms cannot send PUT/DELETE, so updates and deletes go through the dedicated
//! POST paths `/{id}/update` and `/{id}/delete` and are converted to PUT/DELETE on the api).

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::dto::{AdminSamlServiceProviderDeleteForm, AdminSamlServiceProviderForm};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, SamlServiceProviderFormValues, SamlServiceProvidersConsole};
use crate::tenant::WebTenant;
use assay_contracts::admin::{
    SamlServiceProviderRegisterRequest, SamlServiceProviderUpdateRequest,
};
use axum::extract::{Extension, Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SamlClientQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
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
        idp_metadata_url: &idp_metadata_url(&tenant),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_from(&headers, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        updated: query.updated.is_some(),
        deleted: query.deleted.is_some(),
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
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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

/// Reads an uploaded SP metadata file as a UTF-8 string. `Ok(None)` if empty;
/// `Err(())` if over the size limit, not UTF-8, or the read fails.
async fn read_metadata_file(
    field: axum::extract::multipart::Field<'_>,
) -> Result<Option<String>, ()> {
    // Metadata is normally a few KB. The whole request is also limited by DefaultBodyLimit, but set a cap just in case.
    const MAX_METADATA_BYTES: usize = 1024 * 1024;
    let bytes = field.bytes().await.map_err(|_| ())?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(());
    }
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| ())?;
    Ok((!text.trim().is_empty()).then_some(text))
}

/// Imports SP metadata, prefills the registration form with it and re-renders (no PRG).
/// Source is a file upload (`metadata_file`) or pasted text (`metadata_xml`). The file takes priority.
pub async fn import_metadata(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}/admin/saml-clients", tenant.prefix());

    // Read the CSRF token, pasted XML and uploaded file from the multipart body.
    let mut csrf_token = String::new();
    let mut pasted_xml = String::new();
    let mut uploaded_xml: Option<String> = None;
    let mut read_failed = false;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => match field.name() {
                Some("csrf_token") => csrf_token = field.text().await.unwrap_or_default(),
                Some("metadata_xml") => pasted_xml = field.text().await.unwrap_or_default(),
                Some("metadata_file") => match read_metadata_file(field).await {
                    Ok(Some(xml)) => uploaded_xml = Some(xml),
                    Ok(None) => {}
                    Err(()) => read_failed = true,
                },
                _ => {
                    let _ = field.bytes().await;
                }
            },
            Ok(None) => break,
            Err(_) => {
                read_failed = true;
                break;
            }
        }
    }

    if !console_csrf_valid_in(&headers, &csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();

    // If there is a file, prefer its content; otherwise use the pasted text.
    let metadata_xml = uploaded_xml
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(pasted_xml);

    let (values, imported, error_key) = if read_failed || metadata_xml.trim().is_empty() {
        (
            SamlServiceProviderFormValues::default(),
            false,
            Some("admin-saml-client-error-import"),
        )
    } else {
        match state
            .api
            .import_saml_sp_metadata(&correlation.0, &tenant.0, &sso, &metadata_xml)
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
        }
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
        idp_metadata_url: &idp_metadata_url(&tenant),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_from(&headers, state.config.csrf_secret()),
        saved: false,
        updated: false,
        deleted: false,
        imported,
        error_key,
        providers: &providers,
        values: &values,
    }))
    .into_response()
}

/// Updates an SP (`POST /{tenant_id}/admin/saml-clients/{id}/update`).
pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, id)): Path<(String, String)>,
    Form(form): Form<AdminSamlServiceProviderForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/saml-clients", tenant.prefix());
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
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
        .update_saml_service_provider(
            &correlation.0,
            &tenant.0,
            &sso,
            &id,
            SamlServiceProviderUpdateRequest {
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
        Ok(_) => found(&format!("{base}?updated=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(AdminApiError::Conflict(_)) => found(&format!("{base}?error=conflict")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(AdminApiError::Transport(_)) => found(&format!("{base}?error=internal")),
    }
}

/// Deletes an SP (`POST /{tenant_id}/admin/saml-clients/{id}/delete`).
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, id)): Path<(String, String)>,
    Form(form): Form<AdminSamlServiceProviderDeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/saml-clients", tenant.prefix());
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .delete_saml_service_provider(&correlation.0, &tenant.0, &sso, &id)
        .await
    {
        Ok(()) => found(&format!("{base}?deleted=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// Download URL of the IdP metadata used from the admin screen.
fn idp_metadata_url(tenant: &WebTenant) -> String {
    format!("{}/admin/saml-clients/idp-metadata", tenant.prefix())
}

/// Fetches the api's public metadata and returns it as a file from the same web origin as the admin screen.
pub async fn download_idp_metadata(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(response) => return response,
    }

    match state
        .api
        .fetch_saml_idp_metadata(&correlation.0, &tenant.0)
        .await
    {
        Ok(xml) => (
            [
                (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"idp-metadata.xml\"",
                ),
            ],
            xml,
        )
            .into_response(),
        Err(error) => {
            tracing::error!(error = %error, tenant_id = %tenant.0, "failed to download IdP metadata");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
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
        "notfound" => Some("admin-saml-client-error-notfound"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin screen link must not expose the api and must point to web's download use case.
    #[test]
    fn idp_metadata_url_points_to_the_web_download_route() {
        let tenant = WebTenant("00000000-0000-7000-8000-000000000001".to_string());
        assert_eq!(
            idp_metadata_url(&tenant),
            "/00000000-0000-7000-8000-000000000001/admin/saml-clients/idp-metadata"
        );
    }
}
