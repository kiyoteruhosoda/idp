//! Admin console screen for external IdP settings (`/{tenant_id}/admin/external-idps`. AP16).
//!
//! AP10 added the external IdP (OIDC) settings API, but there was no screen and it could only be touched with curl.
//! An external IdP is **a source of user authentication**; a mistake means users cannot sign in, or someone who
//! must not be able to sign in can. Being able to check and roll back only with curl is unfit for operations.
//!
//! Data operations are delegated to the api's `/admin/external-idps` by forwarding the SSO cookie. HTML forms
//! cannot send PATCH/DELETE, so updates and deletes go through dedicated POST paths (`/{id}/update`, `/{id}/delete`)
//! and are converted to the api's PATCH/DELETE (same scheme as the authentication policy screen).
//!
//! # The protocol is chosen at the registration entry
//!
//! There are two kinds of external IdP, OIDC and SAML (ADR-0027), with entirely different fields. Previously one
//! form had sections for both, hidden by JS depending on the choice, but **the screen did not tell "what am I
//! registering right now"** (fields to fill and fields not needed lived side by side).
//!
//! Now the protocol is chosen first, and only that protocol's screens are shown afterwards.
//!
//! | Screen | Role |
//! |---|---|
//! | `GET /admin/external-idps` | List only (no registration form) |
//! | `GET /admin/external-idps/new` | Choosing the protocol |
//! | `GET /admin/external-idps/new/oidc` / `.../new/saml` | Registration form for that protocol |
//! | `GET /admin/external-idps/{id}/edit` | Edit form (protocol fixed to the registered value) |
//!
//! The new registration screens for both protocols can import from the peer's public document. SAML takes IdP metadata
//! XML (pasted or file); OIDC takes the issuer's discovery document (entering the issuer makes the api read
//! `/.well-known/openid-configuration`. task #77). Neither **registers**; they transcribe into the form.
//!
//! With this shape, **the server renders only the chosen protocol's fields**, and the JS for switching them
//! is no longer needed (both protocols can be registered even where JS does not run).
//!
//! **The protocol of a registered provider cannot be changed** (the api rejects it. Switching with the same
//! `provider_code` would leave existing links pointing at identifiers of another protocol). The form offers no choice;
//! the value is carried in a hidden field.
//!
//! `protocol` is always sent, even on update. The api's partial update replaces protocol-specific settings
//! **as a whole**, and omitting `protocol` silently ignores endpoint changes.
//!
//! # Handling the client secret
//!
//! The api **never returns** the secret (stored encrypted, decrypted only at the moment of a token request to the external IdP).
//! So the edit form cannot show the current value. An empty field means "do not change", and `client_secret` is dropped
//! from the request. Interpreting empty as "delete" would break the link just by fixing the display name.

use super::locale;
use crate::admin_dto::ExternalIdpView;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, ExternalIdpFormPage, ExternalIdpFormValues, ExternalIdpProtocolChoice,
    ExternalIdpsConsole,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::{json, Value};

const SEGMENT: &str = "/admin/external-idps";

/// List state (result display carried through Post/Redirect/Get).
#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Form screen state (only the reason a registration/update failed).
#[derive(Debug, Default, Deserialize)]
pub struct FormQuery {
    #[serde(default)]
    pub error: Option<String>,
}

/// Registration/update form. A checkbox is "sent only when checked", so it is received as `Option<String>`.
///
/// All protocol-specific fields are `#[serde(default)]`. Submissions from a screen showing only one protocol's fields
/// must be accepted, and **the api decides what is required**
/// (making them required here would scatter the decision into two places).
#[derive(Debug, Deserialize)]
pub struct ExternalIdpForm {
    #[serde(default)]
    pub provider_code: String,
    pub display_name: String,
    /// `oidc` / `saml`. Unspecified means `oidc` (do not break submissions from existing forms).
    #[serde(default)]
    pub protocol: String,
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// Requested scopes. The two common ones are checkboxes; others are received in `scopes_extra`.
    #[serde(default)]
    pub scope_profile: Option<String>,
    #[serde(default)]
    pub scope_email: Option<String>,
    #[serde(default)]
    pub scopes_extra: String,
    #[serde(default)]
    pub saml_sso_url: String,
    #[serde(default)]
    pub saml_certificates: String,
    #[serde(default)]
    pub saml_name_id_format: String,
    #[serde(default)]
    pub enabled: Option<String>,
    #[serde(default)]
    pub allow_auto_link: Option<String>,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    pub csrf_token: String,
}

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
    let sso = sso(&headers);
    let (providers, error_key) = match state
        .api
        .list_external_idps(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(v) => (v, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(e) => {
            tracing::error!(error = %e, "failed to load external idps");
            (Vec::new(), Some("admin-error-internal"))
        }
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpsConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        providers: &providers,
        saved: query.saved.is_some(),
        deleted: query.deleted.is_some(),
        error_key,
    }))
    .into_response()
}

/// Screen choosing the protocol to register (`GET /admin/external-idps/new`).
pub async fn choose_protocol(
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
    Html(render(&ExternalIdpProtocolChoice {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
    }))
    .into_response()
}

/// OIDC registration form (`GET /admin/external-idps/new/oidc`).
pub async fn new_oidc_form(
    state: State<WebState>,
    correlation: Extension<CorrelationId>,
    tenant: Extension<WebTenant>,
    headers: HeaderMap,
    query: Query<FormQuery>,
) -> Response {
    new_form(state, correlation, tenant, headers, query, "oidc").await
}

/// SAML registration form (`GET /admin/external-idps/new/saml`). Metadata import also appears here.
pub async fn new_saml_form(
    state: State<WebState>,
    correlation: Extension<CorrelationId>,
    tenant: Extension<WebTenant>,
    headers: HeaderMap,
    query: Query<FormQuery>,
) -> Response {
    new_form(state, correlation, tenant, headers, query, "saml").await
}

/// Registration form. **The route decides the protocol** — receiving and interpreting it as a path parameter would create
/// a decision here about whether to round a misspelled URL to the default protocol. With two routes in the router,
/// unknown spellings simply become 404.
async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<FormQuery>,
    protocol: &str,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let values = ExternalIdpFormValues {
        protocol: protocol.to_string(),
        ..ExternalIdpFormValues::default()
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpFormPage {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso(&headers), state.config.csrf_secret()),
        editing: None,
        values: &values,
        imported: false,
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// Edit form (`GET /admin/external-idps/{id}/edit`).
///
/// Initial values come from the list (no extra round trip to the api). An id not in the list (deleted, another tenant)
/// returns to the list with the reason — showing an empty form would lead to a new registration while meaning to edit.
pub async fn edit_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Query(query): Query<FormQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    let providers = match state
        .api
        .list_external_idps(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=forbidden")),
        Err(e) => {
            tracing::error!(error = %e, "failed to load external idps");
            return found(&format!("{base}?error=internal"));
        }
    };
    let Some(provider) = providers.iter().find(|p| p.id == id) else {
        return found(&format!("{base}?error=notfound"));
    };
    let values = values_from(provider);

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpFormPage {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        editing: Some(provider.id.as_str()),
        values: &values,
        imported: false,
        error_key: query.error.as_deref().and_then(error_key_for),
    }))
    .into_response()
}

/// Imports external IdP metadata, prefills the SAML registration form with it and re-renders (AP12).
///
/// Importing is **not registration**, so no PRG (the admin registers after checking the values). The source is
/// a file upload (`metadata_file`) or pasted text (`metadata_xml`), the file taking priority
/// (same operation as SP metadata import; differing operations per screen would confuse).
pub async fn import_metadata(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    let upload = read_metadata_upload(multipart).await;
    if !console_csrf_valid(&sso, &upload.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}/new/saml?error=csrf"));
    }

    let (values, imported, error_key) = match upload.metadata_xml() {
        None => (
            saml_defaults(),
            false,
            Some("admin-external-idps-error-import"),
        ),
        Some(xml) => match state
            .api
            .import_external_idp_metadata(&correlation.0, &tenant.0, &sso, &xml)
            .await
        {
            Ok(parsed) => (
                ExternalIdpFormValues {
                    display_name: parsed.display_name,
                    // The entityID is the `issuer` as is (the value matched exactly against the assertion's `<Issuer>`).
                    issuer: parsed.entity_id,
                    saml_sso_url: parsed.sso_url,
                    saml_certificates: parsed.certificates.join("\n\n"),
                    saml_name_id_format: parsed.name_id_format,
                    ..saml_defaults()
                },
                true,
                None,
            ),
            Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
            Err(AdminApiError::Forbidden) => (
                saml_defaults(),
                false,
                Some("admin-settings-error-forbidden"),
            ),
            // Unparseable XML (SP metadata pasted, no SSO, etc.) is a user input error.
            Err(AdminApiError::Validation(_) | AdminApiError::NotFound) => (
                saml_defaults(),
                false,
                Some("admin-external-idps-error-import"),
            ),
            Err(e) => {
                tracing::error!(error = %e, "failed to import external idp metadata");
                (saml_defaults(), false, Some("admin-error-internal"))
            }
        },
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpFormPage {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        editing: None,
        values: &values,
        imported,
        error_key,
    }))
    .into_response()
}

/// Form for the discovery import.
#[derive(Debug, Deserialize)]
pub struct DiscoveryImportForm {
    #[serde(default)]
    pub issuer: String,
    pub csrf_token: String,
}

/// Imports the external OIDC IdP's discovery document, prefills the OIDC registration form with it and re-renders
/// (task #77).
///
/// Like SAML metadata import, it is **not registration**, so no PRG (the admin registers after checking the
/// values). Fetching, destination checks and `issuer` matching are all done by the api (web never reaches the external IdP).
/// On failure it re-renders keeping the entered issuer (so it can be fixed and resubmitted).
pub async fn import_discovery(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<DiscoveryImportForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}/new/oidc?error=csrf"));
    }

    let issuer = form.issuer.trim();
    // Keep the entered issuer even when re-rendering after a failure.
    let entered = ExternalIdpFormValues {
        issuer: issuer.to_string(),
        ..ExternalIdpFormValues::default()
    };
    let (values, imported, error_key) = if issuer.is_empty() {
        (entered, false, Some("admin-external-idps-error-discovery"))
    } else {
        match state
            .api
            .import_external_idp_discovery(&correlation.0, &tenant.0, &sso, issuer)
            .await
        {
            Ok(imported) => (
                ExternalIdpFormValues {
                    // The document's `issuer` (exactly matching the input). The value matched against the ID Token's `iss`.
                    issuer: imported.issuer,
                    authorization_endpoint: imported.authorization_endpoint,
                    token_endpoint: imported.token_endpoint,
                    jwks_uri: imported.jwks_uri,
                    ..ExternalIdpFormValues::default()
                },
                true,
                None,
            ),
            Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
            Err(AdminApiError::Forbidden) => {
                (entered, false, Some("admin-settings-error-forbidden"))
            }
            // Destination check failed, fetch failed, issuer mismatch, etc. The reason (operational language) is logged.
            Err(AdminApiError::Validation(reason)) => {
                tracing::info!(reason = %reason, "external idp discovery import was rejected");
                (entered, false, Some("admin-external-idps-error-discovery"))
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to import external idp discovery document");
                (entered, false, Some("admin-error-internal"))
            }
        }
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&ExternalIdpFormPage {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        editing: None,
        values: &values,
        imported,
        error_key,
    }))
    .into_response()
}

/// The form after import opens as SAML (right after reading IdP metadata).
fn saml_defaults() -> ExternalIdpFormValues {
    ExternalIdpFormValues {
        protocol: "saml".to_string(),
        ..ExternalIdpFormValues::default()
    }
}

/// Import input read from the multipart body.
struct MetadataUpload {
    csrf_token: String,
    pasted: String,
    uploaded: Option<String>,
    /// Reading failed (too large, not UTF-8, broken multipart).
    read_failed: bool,
}

impl MetadataUpload {
    /// XML used for import. The file takes priority if present; otherwise the pasted text.
    fn metadata_xml(&self) -> Option<String> {
        if self.read_failed {
            return None;
        }
        self.uploaded
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| Some(self.pasted.clone()))
            .filter(|s| !s.trim().is_empty())
    }
}

/// Uploaded metadata is normally a few KB. The whole request is also limited by `DefaultBodyLimit`, but
/// a cap is set just in case (same value as SP metadata import).
const MAX_METADATA_BYTES: usize = 1024 * 1024;

async fn read_metadata_upload(mut multipart: Multipart) -> MetadataUpload {
    let mut upload = MetadataUpload {
        csrf_token: String::new(),
        pasted: String::new(),
        uploaded: None,
        read_failed: false,
    };
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => match field.name() {
                Some("csrf_token") => upload.csrf_token = field.text().await.unwrap_or_default(),
                Some("metadata_xml") => upload.pasted = field.text().await.unwrap_or_default(),
                Some("metadata_file") => match field.bytes().await {
                    Ok(bytes) if bytes.is_empty() => {}
                    Ok(bytes) if bytes.len() > MAX_METADATA_BYTES => upload.read_failed = true,
                    Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
                        Ok(text) => upload.uploaded = Some(text),
                        Err(_) => upload.read_failed = true,
                    },
                    Err(_) => upload.read_failed = true,
                },
                _ => {
                    let _ = field.bytes().await;
                }
            },
            Ok(None) => break,
            Err(_) => {
                upload.read_failed = true;
                break;
            }
        }
    }
    upload
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ExternalIdpForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    // On failure return to the same protocol's form (do not make them choose again). **The destination is limited to
    // the two routes in the router** — `protocol` comes from the form, and `protocol_of` passes unknown spellings through
    // without rounding (to let the api decide). Inserting it as is into the redirect path would put a URL with no
    // destination (404) or a query broken by `?` `#` into Location. Unknown protocols have nowhere to go,
    // so fall back to the list, which can show the reason.
    let form_url = match protocol_of(&form) {
        "saml" => format!("{base}/new/saml"),
        "oidc" => format!("{base}/new/oidc"),
        _ => base.clone(),
    };
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{form_url}?error=csrf"));
    }
    let mut body = common_fields(&form);
    body["provider_code"] = json!(form.provider_code.trim());
    // An empty field on new registration means "no secret (public client)". It means something else when editing, so they are separate.
    if !form.client_secret.is_empty() {
        body["client_secret"] = json!(form.client_secret);
    }

    match state
        .api
        .create_external_idp(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(e) => found(&format!("{form_url}?error={}", error_code(&e))),
    }
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Form(form): Form<ExternalIdpForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let form_url = format!("{base}/{id}/edit");
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{form_url}?error=csrf"));
    }
    let mut body = common_fields(&form);
    // An empty field when editing means "do not change". The api's partial update leaves unspecified fields alone, so drop the key.
    if !form.client_secret.is_empty() {
        body["client_secret"] = json!(form.client_secret);
    }

    match state
        .api
        .update_external_idp(&correlation.0, &tenant.0, &sso, &id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(e) => found(&format!("{form_url}?error={}", error_code(&e))),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_external_idp(&correlation.0, &tenant.0, &sso, &id)
        .await
    {
        Ok(()) => found(&format!("{base}?deleted=1")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

/// Fields shared by create and update. `provider_code` (create only) and `client_secret` (branching on presence) are added by the caller.
///
/// Protocol-specific fields are included **only for the chosen side**. `protocol` is always sent even on update (without it
/// the api does not replace protocol-specific settings).
fn common_fields(form: &ExternalIdpForm) -> Value {
    let protocol = protocol_of(form);
    let mut body = json!({
        "display_name": form.display_name.trim(),
        "protocol": protocol,
        "issuer": form.issuer.trim(),
        "enabled": form.enabled.is_some(),
        "allow_auto_link": form.allow_auto_link.is_some(),
    });
    if protocol == "saml" {
        body["saml_sso_url"] = json!(form.saml_sso_url.trim());
        body["saml_certificates"] = json!(parse_certificates(&form.saml_certificates));
        body["saml_name_id_format"] = json!(form.saml_name_id_format.trim());
    } else {
        body["authorization_endpoint"] = json!(form.authorization_endpoint.trim());
        body["token_endpoint"] = json!(form.token_endpoint.trim());
        body["jwks_uri"] = json!(form.jwks_uri.trim());
        body["client_id"] = json!(form.client_id.trim());
        body["scopes"] = json!(selected_scopes(form));
    }
    body
}

/// The form's protocol. Unknown values are **passed to the api as is**, not rounded to `oidc` — rounding would register
/// settings meant for SAML as OIDC. Only an empty field falls back to the default (`oidc`).
fn protocol_of(form: &ExternalIdpForm) -> &str {
    match form.protocol.trim() {
        "" => "oidc",
        other => other,
    }
}

/// Builds the requested scopes.
///
/// `openid` is always put first. Without receiving an ID Token from the external IdP, `iss` + `sub` cannot be
/// obtained and the very basis of identity disappears (ADR-0023). **Since it is not shown as a checkbox,
/// there must be no way for it to be left out.**
///
/// Even if `openid` or `profile` is repeated in the free input, it is included only once (requesting duplicate scopes
/// makes some peers reject the request itself).
fn selected_scopes(form: &ExternalIdpForm) -> Vec<String> {
    let mut scopes = vec!["openid".to_string()];
    let mut push = |scope: &str| {
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_string());
        }
    };
    if form.scope_profile.is_some() {
        push("profile");
    }
    if form.scope_email.is_some() {
        push("email");
    }
    for scope in form.scopes_extra.split_whitespace() {
        push(scope);
    }
    scopes
}

/// Certificate field to an array. **Separated by blank lines** — PEM bodies are wrapped across lines, so separating by
/// line would split one certificate into several. Newlines and whitespace inside each certificate are collapsed here.
///
/// Separators are **not detected by string match** on `"\n\n"`. Browsers normalize `textarea` newlines to
/// CRLF on submission, so blank lines arrive as `"\r\n\r\n"`. A string match would find no separators at all,
/// joining every certificate into one base64 so that **none can be read** (failing exactly during a certificate rollover,
/// which needs multiple certificates). Split into lines and treat "whitespace-only lines" as separators.
fn parse_certificates(raw: &str) -> Vec<String> {
    // Normalize lone CRs to newlines too (practically no client sends them as newlines, but if one did, separators would vanish).
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in normalized.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
        } else {
            current.extend(line.split_whitespace());
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

fn values_from(provider: &ExternalIdpView) -> ExternalIdpFormValues {
    ExternalIdpFormValues {
        provider_code: provider.provider_code.clone(),
        display_name: provider.display_name.clone(),
        protocol: provider.protocol.clone(),
        issuer: provider.issuer.clone(),
        authorization_endpoint: provider.authorization_endpoint.clone().unwrap_or_default(),
        token_endpoint: provider.token_endpoint.clone().unwrap_or_default(),
        jwks_uri: provider.jwks_uri.clone().unwrap_or_default(),
        client_id: provider.client_id.clone().unwrap_or_default(),
        has_client_secret: provider.has_client_secret,
        scopes: provider.scopes.join(" "),
        saml_sso_url: provider.saml_sso_url.clone().unwrap_or_default(),
        // Saved certificates are returned separated by blank lines (same shape as input; can be appended to or replaced when editing).
        saml_certificates: provider.saml_certificates.join("\n\n"),
        saml_name_id_format: provider.saml_name_id_format.clone().unwrap_or_default(),
        enabled: provider.enabled,
        allow_auto_link: provider.allow_auto_link,
    }
}

/// Maps api errors to query string codes (carrying the reason through Post/Redirect/Get).
fn error_code(e: &AdminApiError) -> &'static str {
    match e {
        AdminApiError::Forbidden => "forbidden",
        AdminApiError::Validation(_) => "validation",
        AdminApiError::Conflict(_) => "conflict",
        AdminApiError::NotFound => "notfound",
        _ => "internal",
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "import" => Some("admin-external-idps-error-import"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-external-idps-error-validation"),
        "conflict" => Some("admin-external-idps-error-conflict"),
        "notfound" => Some("admin-external-idps-error-not-found"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(secret: &str) -> ExternalIdpForm {
        ExternalIdpForm {
            provider_code: "corp".into(),
            display_name: "Corp IdP".into(),
            protocol: "oidc".into(),
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/authorize".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            client_id: "abc".into(),
            client_secret: secret.into(),
            scope_profile: None,
            scope_email: Some("1".into()),
            scopes_extra: String::new(),
            saml_sso_url: String::new(),
            saml_certificates: String::new(),
            saml_name_id_format: String::new(),
            enabled: Some("1".into()),
            allow_auto_link: None,
            csrf_token: "t".into(),
        }
    }

    fn saml_form() -> ExternalIdpForm {
        ExternalIdpForm {
            protocol: "saml".into(),
            issuer: "urn:idp:corp".into(),
            saml_sso_url: "https://idp.example.com/sso".into(),
            saml_certificates: "MIIB\nAAAA==\n\nMIIC\nBBBB==".into(),
            saml_name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into(),
            ..form("")
        }
    }

    /// Checked scopes become an array. **`openid` is always included** — without receiving an ID Token from the
    /// external IdP, `iss` + `sub` cannot be obtained and the very basis of identity disappears.
    #[test]
    fn openid_is_always_requested_and_checked_scopes_follow() {
        assert_eq!(selected_scopes(&form("")), vec!["openid", "email"]);
        let none = ExternalIdpForm {
            scope_email: None,
            ..form("")
        };
        assert_eq!(selected_scopes(&none), vec!["openid"]);
    }

    /// Scopes defined by the peer are received as free input (options are not closed to fixed values). **Duplicates are collapsed** —
    /// requesting the same scope twice makes some peers reject the request itself.
    #[test]
    fn extra_scopes_are_appended_without_duplicating_the_checked_ones() {
        let extra = ExternalIdpForm {
            scope_profile: Some("1".into()),
            scopes_extra: "  groups openid profile User.Read ".into(),
            ..form("")
        };
        assert_eq!(
            selected_scopes(&extra),
            vec!["openid", "profile", "email", "groups", "User.Read"]
        );
    }

    /// Certificates are separated by **blank lines**. Separating by line would split one wrapped PEM body
    /// into several certificates, none of which could be read.
    #[test]
    fn certificates_are_split_on_blank_lines_not_line_breaks() {
        assert_eq!(
            parse_certificates("MIIB\nAAAA==\n\nMIIC\nBBBB=="),
            vec!["MIIBAAAA==", "MIICBBBB=="]
        );
        assert_eq!(parse_certificates("MIIB\nAAAA=="), vec!["MIIBAAAA=="]);
        assert!(parse_certificates("  \n\n  ").is_empty());
    }

    /// **Browsers send `textarea` newlines as CRLF.** Searching for separators by string match on `"\n\n"`
    /// finds no blank lines, joining everything into one base64 so that **none can be read**
    /// (failing exactly during a certificate rollover, which needs multiple certificates).
    #[test]
    fn crlf_from_a_browser_still_separates_the_certificates() {
        assert_eq!(
            parse_certificates("MIIB\r\nAAAA==\r\n\r\nMIIC\r\nBBBB=="),
            vec!["MIIBAAAA==", "MIICBBBB=="]
        );
        // Blank separator lines containing whitespace are still treated as separators (it slips in when pasting).
        assert_eq!(
            parse_certificates("MIIB\r\nAAAA==\r\n \t\r\nMIIC\r\nBBBB=="),
            vec!["MIIBAAAA==", "MIICBBBB=="]
        );
    }

    /// Only **the chosen protocol's fields** are sent. Sending both would let the api build a half-baked setting,
    /// and the mistake would not surface until login.
    #[test]
    fn only_the_selected_protocols_fields_are_sent() {
        let oidc = common_fields(&form(""));
        assert_eq!(oidc["protocol"], json!("oidc"));
        assert_eq!(
            oidc["authorization_endpoint"],
            json!("https://idp.example.com/authorize")
        );
        assert!(oidc.get("saml_sso_url").is_none());

        let saml = common_fields(&saml_form());
        assert_eq!(saml["protocol"], json!("saml"));
        assert_eq!(saml["saml_sso_url"], json!("https://idp.example.com/sso"));
        assert_eq!(
            saml["saml_certificates"],
            json!(["MIIBAAAA==", "MIICBBBB=="])
        );
        assert!(saml.get("authorization_endpoint").is_none());
        assert!(saml.get("scopes").is_none());
    }

    /// `protocol` is always sent even on update. Without it the api does not replace protocol-specific settings,
    /// so omitting it silently ignores endpoint changes.
    #[test]
    fn the_protocol_is_always_sent_so_endpoint_edits_are_not_ignored() {
        assert_eq!(common_fields(&form("s3cret"))["protocol"], json!("oidc"));
        // Unknown values are not rounded to the default (rounding would register settings meant for SAML as OIDC).
        let unknown = ExternalIdpForm {
            protocol: "ws-fed".into(),
            ..form("")
        };
        assert_eq!(common_fields(&unknown)["protocol"], json!("ws-fed"));
        // Only an empty field falls back to the default (oidc).
        let blank = ExternalIdpForm {
            protocol: String::new(),
            ..form("")
        };
        assert_eq!(common_fields(&blank)["protocol"], json!("oidc"));
    }

    /// Unchecked checkboxes are not submitted. Send them as `false` (leaving them unspecified would make the api's
    /// partial update read "do not change", so unchecking could not disable it).
    #[test]
    fn unchecked_boxes_are_sent_as_false_not_omitted() {
        let body = common_fields(&form(""));
        assert_eq!(body["enabled"], serde_json::json!(true));
        assert_eq!(body["allow_auto_link"], serde_json::json!(false));
    }

    /// The secret is not among the form's shared fields. Since an empty field when editing means "do not change",
    /// the presence decision is left to the caller (always including it here would make empty mean delete).
    #[test]
    fn the_client_secret_is_never_part_of_the_common_fields() {
        assert!(common_fields(&form("s3cret"))
            .get("client_secret")
            .is_none());
        assert!(common_fields(&form("")).get("client_secret").is_none());
    }
}
