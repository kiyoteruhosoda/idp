//! SAML 連携登録コンソール画面（`/{tenant_id}/admin/saml`）。
//!
//! 外部 IdP との SAML 連携に必要な Entity ID・SSO URL・証明書を登録するための UI を提供する。
//! 現段階では web 側で入力値を検証し、後続の永続化 API 追加に備えてフォーム DTO と画面責務を分離する。

use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::AdminSamlProviderForm;
use crate::handlers::admin_console::{resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, SamlProviderForm, SamlProviderFormValues};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SamlQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn new_form(
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
    let messages = Messages::new(locale(&headers));
    Html(render(&SamlProviderForm {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        csrf: &csrf_from(&headers, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        error_key: query.error.as_deref().and_then(error_key_for),
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
    if !(form.sso_url.starts_with("https://") || form.sso_url.starts_with("http://localhost")) {
        return found(&format!("{base}?error=sso-url"));
    }
    found(&format!("{base}?saved=1"))
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

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "validation" => Some("admin-saml-error-validation"),
        "sso-url" => Some("admin-saml-error-sso-url"),
        _ => None,
    }
}
