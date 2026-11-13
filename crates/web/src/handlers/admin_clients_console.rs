//! Server-rendered screens for client (RP) management (web. ADR-0007 §4).
//!
//! Calls the api's JSON admin APIs (`/admin/clients*`, `RequirePerms<IdpAdmin>`) by forwarding the admin's SSO cookie and
//! renders the results as HTML. Authorization, data operations and auditing are on the api side; web only has screens and CSRF (`console_csrf_token`).
//! HTML is rendered with Askama templates (`templates/console/`), and user input is auto-escaped.
//! `client_secret` is shown in plaintext only on the screen at creation/reissue.

use super::locale;
use crate::admin_dto::{ClientCreatedView, ClientListView, ClientView};
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    client_usage, render, ClientDetail, ClientForm, ClientFormValues, ClientSecret, ClientsList,
    ConsoleNotice,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::json;

const CLIENTS_SEGMENT: &str = "/admin/clients";

/// Registration lineage (ADR-0038). **Rows of the same `clients` table are routed to two screens by purpose.**
///
/// Integrations go in the `/admin/clients` list and single-item screen; service accounts go in the account list
/// (`/admin/accounts?kind=service_account`) and the `/admin/service-accounts/{client_id}` screen
/// (ADR-0065). Edit, secret reissue, delete and permission paths share `/admin/clients/{client_id}/*`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientKind {
    /// Integration (OIDC RP). Has `authorization_code`.
    RelyingParty,
    /// Service account (a machine principal). Has `client_credentials`.
    ServiceAccount,
}

impl ClientKind {
    fn usage(self) -> &'static str {
        match self {
            Self::RelyingParty => client_usage::USER_LOGIN,
            Self::ServiceAccount => client_usage::SYSTEM,
        }
    }

    fn new_key(self) -> &'static str {
        match self {
            Self::RelyingParty => "admin-clients-new",
            Self::ServiceAccount => "admin-service-accounts-new",
        }
    }

    /// Which lineage a registered client belongs to. The presence of `client_credentials` alone decides it.
    fn of(client: &ClientView) -> Self {
        if is_system_client(client) {
            Self::ServiceAccount
        } else {
            Self::RelyingParty
        }
    }

    /// Reverse lookup from the purpose string (the form's hidden value). Unknown values fall back to integration.
    fn from_usage(usage: &str) -> Self {
        if usage == client_usage::SYSTEM {
            Self::ServiceAccount
        } else {
            Self::RelyingParty
        }
    }

    /// The new registration screen (also the form's submit target).
    fn new_href(self, tenant: &WebTenant) -> String {
        match self {
            Self::RelyingParty => format!("{}{CLIENTS_SEGMENT}/new", tenant.prefix()),
            Self::ServiceAccount => format!("{}/admin/service-accounts/new", tenant.prefix()),
        }
    }

    /// The list to return to. Service accounts are listed in the account list (ADR-0065).
    fn list_href(self, tenant: &WebTenant) -> String {
        match self {
            Self::RelyingParty => format!("{}{CLIENTS_SEGMENT}", tenant.prefix()),
            Self::ServiceAccount => {
                format!("{}/admin/accounts?kind=service_account", tenant.prefix())
            }
        }
    }
}

/// Common preprocessing at the start of each handler: resolves the admin and returns the user_id or a redirect Response.
macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

// ── List ──────────────────────────────────────────────────────────────────────

/// List of integrations (OIDC RPs) (`GET /{tenant_id}/admin/clients`).
///
/// Paging is done on the api (DB) side (G7). web carries over the page position in the query and only builds the pager's
/// prev/next links from the response's `total`, never receiving all rows. Service accounts are not listed here
/// (they are in the account list. ADR-0065). **Filtering is passed to the api** — receiving one page and thinning it
/// in web would make the total and pager disagree with the actual counts (ADR-0038).
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let offset = query.offset.unwrap_or(0).max(0);
    let mut page_query = crate::pagination::page_query(offset);
    // Both together cannot be created (ADR-0032 Revised), so a single grant splits them exclusively.
    page_query.push(("grant_type", "authorization_code".to_string()));
    let result = state
        .api
        .list_clients(&correlation.0, &tenant.0, &sso(&headers), &page_query)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(page) => Html(render_list(&messages, &tenant, &admin, &page, offset)).into_response(),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

/// Query of the client list. Only the page position is carried over (no filtering).
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub offset: Option<i64>,
}

// ── New registration form ──────────────────────────────────────────────────────────

/// New registration form for integrations (`/admin/clients/new`).
pub async fn new_form(
    state: State<WebState>,
    correlation: Extension<CorrelationId>,
    tenant: Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    new_form_of_kind(
        ClientKind::RelyingParty,
        state,
        correlation,
        tenant,
        headers,
    )
    .await
}

/// New registration form for service accounts (`/admin/service-accounts/new`).
pub async fn new_service_account_form(
    state: State<WebState>,
    correlation: Extension<CorrelationId>,
    tenant: Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    new_form_of_kind(
        ClientKind::ServiceAccount,
        state,
        correlation,
        tenant,
        headers,
    )
    .await
}

/// **The entry point decides the purpose** (ADR-0038). The form offers no choice and carries it in a hidden field.
async fn new_form_of_kind(
    kind: ClientKind,
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    let mut values = ClientFormValues::default_new();
    values.usage = kind.usage().to_string();
    Html(render_new_form(
        &messages, &tenant, &admin, &csrf, &values, None,
    ))
    .into_response()
}

// ── Executing new registration ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NewClientForm {
    pub app_name: String,
    /// Client type. The field is hidden for system use, so it must be accepted even when not sent
    /// (`client_type_for` leans toward confidential. ADR-0032).
    #[serde(default)]
    pub client_type: String,
    pub redirect_uris: String,
    /// Scopes are received as checkboxes (accepted values are limited to the 4 OIDC ones).
    /// A check is "sent only when checked", so it is received as `Option`. `openid` is required, so it
    /// has no field and `selected_scopes` always adds it.
    #[serde(default)]
    pub scope_profile: Option<String>,
    #[serde(default)]
    pub scope_email: Option<String>,
    #[serde(default)]
    pub scope_offline_access: Option<String>,
    /// Client purpose (`client_usage`. ADR-0032). The api does not hold this value, so web
    /// translates it into the presence of `redirect_uris` and `allow_client_credentials`.
    pub usage: String,
    /// Client authentication method (G3). The select is rendered only for confidential, so it is optional.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Verification key for `private_key_jwt` (JWK Set JSON. ADR-0030). Likewise rendered only for confidential.
    #[serde(default)]
    pub jwks: Option<String>,
    /// Admin note (ADR-0065). A field drawn only for new service account registrations, so it is optional.
    #[serde(default)]
    pub note: String,
    pub csrf_token: String,
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<NewClientForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let values = ClientFormValues {
        app_name: form.app_name.clone(),
        client_type: form.client_type.clone(),
        redirect_uris: form.redirect_uris.clone(),
        scopes: selected_scopes(
            &form.scope_profile,
            &form.scope_email,
            &form.scope_offline_access,
        )
        .join(" "),
        client_status: "ACTIVE".to_string(),
        usage: form.usage.clone(),
        token_endpoint_auth_method: auth_method_or_default(&form.token_endpoint_auth_method),
        jwks: form.jwks.clone().unwrap_or_default(),
        note: form.note.clone(),
    };

    // Messages (FluentBundle) is not Send, so it is not held across the api await (same reason as login.rs).
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request_form(render_new_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &values,
            Some("admin-error-csrf"),
        ));
    }

    // For system use the client_type select is not rendered, so send confidential even if no value arrives
    // (with public, neither `client_credentials` nor `private_key_jwt` can work).
    let client_type = client_type_for(&form.usage, &form.client_type);
    let body = json!({
        "app_name": form.app_name,
        "client_type": client_type,
        "redirect_uris": redirect_uris_for(&form.usage, &form.redirect_uris),
        "scopes": selected_scopes(
            &form.scope_profile,
            &form.scope_email,
            &form.scope_offline_access,
        ),
        "allow_client_credentials": allows_client_credentials(&form.usage),
        // The new form keeps the method/verification key fields in the DOM while public is selected (just hidden).
        // Hidden fields are still submitted, so for public drop the verification key before passing to the api — sending a key
        // with public is rejected as "cannot register with this method". The method itself is not read by the api for
        // public (always `none`), so it can be passed as is.
        "token_endpoint_auth_method": form.token_endpoint_auth_method,
        "jwks": jwks_for_new_client(&client_type, &form.token_endpoint_auth_method, &form.jwks),
        // The note is sent only for service accounts (sending it for an integration makes the api refuse with 400. ADR-0065). Empty is not sent.
        "note": note_for_new_client(&form.usage, &form.note),
    });
    // Carry over the resolved language so the api's validation/conflict messages show on this screen (MT20).
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_client(&correlation.0, &tenant.0, &sso(&headers), body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(created) => Html(render_secret_result(
            &messages, &tenant, &admin, &created, true,
        ))
        .into_response(),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => bad_request_form(
            render_new_form_with_message(&messages, &tenant, &admin, &csrf, &values, &m),
        ),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── Details ──────────────────────────────────────────────────────────────────────

pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Query(query): Query<DetailQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    // `Messages` (the fluent bundle) is not Send, so build it **after all awaits are done**.
    // Holding it across an await makes the handler's future non-Send, failing axum's `Handler`.
    let client = match state
        .api
        .get_client(&correlation.0, &tenant.0, &sso, &client_id)
        .await
    {
        Ok(client) => Some(client),
        Err(AdminApiError::NotFound) => None,
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    let Some(client) = client else {
        let messages = Messages::new(locale(&headers));
        return not_found(&messages, &tenant, &admin);
    };
    // A service account's single-item screen is on the account side (ADR-0065). When returning here from an edit or
    // permission change, send it there keeping the result (`?error=`).
    if is_system_client(&client) {
        let mut href = service_account_href(&tenant, &client_id);
        if let Some(error) = query.error.as_deref() {
            href.push_str(&format!("?error={}", urlencoding(error)));
        }
        return found(&href);
    }

    // Admin permissions (ADR-0037). If fetching held codes fails, fail the whole screen — confusing an empty list with an
    // unreadable one could wrongly lead to re-granting "missing" permissions that are actually there.
    let permission_codes = match state
        .api
        .list_client_permissions(&correlation.0, &tenant.0, &sso, &client_id)
        .await
    {
        Ok(p) => p.permission_codes,
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    // Only integrations reach here (service accounts were sent to their own screen above). Integrations have no way to get
    // an admin token, so grant candidates are not fetched — if any are still held, only revocation is shown (ADR-0037).
    let grantable: Vec<String> = Vec::new();
    let permissions_load_failed = false;

    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    Html(render_detail(
        &messages,
        &tenant,
        &admin,
        &client,
        &csrf,
        &permission_codes,
        &grantable,
        permissions_load_failed,
        query.error.as_deref().and_then(permission_error_key),
    ))
    .into_response()
}

/// Query of the details screen. Carries the error kind when returning via Post/Redirect/Get from grant/revoke.
#[derive(Debug, Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    pub error: Option<String>,
}

pub(crate) fn permission_error_key(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "code" => Some("api-client-permission-not-grantable"),
        "notfound" => Some("admin-client-not-found-message"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

// ── Granting/revoking admin permissions (ADR-0037. Post/Redirect/Get) ──────────────────────────

#[derive(Debug, Deserialize)]
pub struct PermissionForm {
    pub permission_code: String,
    pub csrf_token: String,
}

pub async fn grant_permission(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_permission_change(
        &state,
        &correlation,
        &tenant,
        &headers,
        &client_id,
        &form,
        true,
    )
    .await
}

pub async fn revoke_permission(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_permission_change(
        &state,
        &correlation,
        &tenant,
        &headers,
        &client_id,
        &form,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn apply_permission_change(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    client_id: &str,
    form: &PermissionForm,
    grant: bool,
) -> Response {
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{CLIENTS_SEGMENT}/{client_id}", tenant.prefix());
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = sso(headers);
    let result = if grant {
        state
            .api
            .grant_client_permission(
                &correlation.0,
                &tenant.0,
                &sso,
                client_id,
                &form.permission_code,
            )
            .await
    } else {
        state
            .api
            .revoke_client_permission(
                &correlation.0,
                &tenant.0,
                &sso,
                client_id,
                &form.permission_code,
            )
            .await
    };
    match result {
        Ok(_) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(headers),
        // Blanket admin permissions and unknown codes end up here (they are not among the screen's options,
        // but the api rejects them when POSTed directly. ADR-0037).
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=code")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

// ── Edit form ──────────────────────────────────────────────────────────────

pub async fn edit_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let result = state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(client) => {
            let values = ClientFormValues::from_client(&client);
            Html(render_edit_form(
                &messages, &tenant, &admin, &client, &csrf, &values, None,
            ))
            .into_response()
        }
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── Executing the edit ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EditClientForm {
    pub app_name: String,
    pub redirect_uris: String,
    /// Scopes are received as checkboxes (same as new registration; `openid` is required so it has no field).
    #[serde(default)]
    pub scope_profile: Option<String>,
    #[serde(default)]
    pub scope_email: Option<String>,
    #[serde(default)]
    pub scope_offline_access: Option<String>,
    pub client_status: String,
    /// Client purpose (`client_usage`. ADR-0032). Goes through the same translation as new registration.
    pub usage: String,
    /// Client authentication method (G3). Sent only for confidential.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Verification key for `private_key_jwt` (JWK Set JSON. ADR-0030). Key rotation is done by replacing
    /// this field.
    #[serde(default)]
    pub jwks: Option<String>,
    pub csrf_token: String,
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<EditClientForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    // Fetch the current client in case of re-display (for read-only display such as the type). ClientView is Send.
    let client = match state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await
    {
        Ok(c) => c,
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            return not_found(&messages, &tenant, &admin);
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    let mut values = ClientFormValues::from_client(&client);
    values.app_name = form.app_name.clone();
    values.redirect_uris = form.redirect_uris.clone();
    values.scopes = selected_scopes(
        &form.scope_profile,
        &form.scope_email,
        &form.scope_offline_access,
    )
    .join(" ");
    values.client_status = form.client_status.clone();
    values.usage = form.usage.clone();
    if let Some(method) = form.token_endpoint_auth_method.as_deref() {
        values.token_endpoint_auth_method = method.to_string();
    }
    values.jwks = form.jwks.clone().unwrap_or_default();

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        let err = messages.get("admin-error-csrf");
        return bad_request_form(render_edit_form(
            &messages,
            &tenant,
            &admin,
            &client,
            &csrf,
            &values,
            Some(err),
        ));
    }

    let body = json!({
        "app_name": form.app_name,
        "redirect_uris": redirect_uris_for(&form.usage, &form.redirect_uris),
        "scopes": selected_scopes(
            &form.scope_profile,
            &form.scope_email,
            &form.scope_offline_access,
        ),
        "client_status": form.client_status,
        "allow_client_credentials": allow_client_credentials_update(&form.usage),
        "token_endpoint_auth_method": form.token_endpoint_auth_method,
        "jwks": jwks_for_method(&form.token_endpoint_auth_method, &form.jwks),
    });
    let result = state
        .api
        .for_locale(locale(&headers))
        .update_client(&correlation.0, &tenant.0, &sso(&headers), &client_id, body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(_) => found(&format!("{}{CLIENTS_SEGMENT}/{client_id}", tenant.prefix())),
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => bad_request_form(
            render_edit_form(&messages, &tenant, &admin, &client, &csrf, &values, Some(m)),
        ),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── Secret reissue ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

/// Logically deletes a client (ADR-0035). The row remains, disappears from the list, and authorization/tokens stop working.
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        return bad_request_page(&messages, &tenant, &admin, "admin-error-csrf");
    }
    // The list to return to differs by lineage (service accounts go to the account list. ADR-0065). It cannot be looked up
    // after deletion, so read it first. Deletion proceeds even if it cannot be read (the return just becomes the integration list).
    let kind = state
        .api
        .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await
        .map(|c| ClientKind::of(&c))
        .unwrap_or(ClientKind::RelyingParty);
    let result = state
        .api
        .for_locale(locale(&headers))
        .delete_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        // After deletion the details page is 404, so return to the list.
        Ok(()) => found(&kind.list_href(&tenant)),
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

pub async fn rotate_secret(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        return bad_request_page(&messages, &tenant, &admin, "admin-error-csrf");
    }
    let rotated = state
        .api
        .for_locale(locale(&headers))
        .rotate_client_secret(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    match rotated {
        Ok(secret) => {
            // The reissue result is shown by re-fetching the details (ClientView is Send).
            let client = state
                .api
                .get_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
                .await;
            let messages = Messages::new(locale(&headers));
            match client {
                Ok(client) => Html(render_rotated_result(
                    &messages,
                    &tenant,
                    &admin,
                    &client,
                    &secret.client_secret,
                ))
                .into_response(),
                Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
            }
        }
        Err(AdminApiError::Validation(m)) => {
            let messages = Messages::new(locale(&headers));
            bad_request_page_msg(&messages, &tenant, &admin, &m)
        }
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &tenant, &admin)
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_data_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

// ── Shared form representation and parsing ────────────────────────────────────────────────

/// Note sent to the api on new registration. Sent only for service accounts and only when not empty (ADR-0065).
fn note_for_new_client(usage: &str, note: &str) -> Option<String> {
    (usage == client_usage::SYSTEM && !note.trim().is_empty()).then(|| note.to_string())
}

/// Single-item screen for a service account (ADR-0065).
fn service_account_href(tenant: &WebTenant, client_id: &str) -> String {
    format!("{}/admin/service-accounts/{client_id}", tenant.prefix())
}

/// Minimal encoding of query values (values re-put into `?error=`; everything except alphanumerics and `-` becomes %XX).
fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Whether the purpose includes `client_credentials` (ADR-0032).
fn allows_client_credentials(usage: &str) -> bool {
    usage == client_usage::SYSTEM
}

/// `allow_client_credentials` sent to the api on update.
///
/// Since the grace clause of ADR-0032 was removed on 2026-08-27, the "both" shape (`client_credentials` + redirect_uri) is
/// rejected by the api on both registration and update, so **the purpose is always uniquely determined by the screen value**.
/// This function used to return `None` (= leave alone) to preserve existing combinations, but that input can no longer be created.
fn allow_client_credentials_update(usage: &str) -> bool {
    allows_client_credentials(usage)
}

/// redirect_uri according to the purpose. System use has none, so leftover field values are not sent
/// (so hidden field values do not survive when saving after switching the purpose).
fn redirect_uris_for(usage: &str, raw: &str) -> Vec<String> {
    if usage == client_usage::SYSTEM {
        Vec::new()
    } else {
        parse_uris(raw)
    }
}

/// client_type according to the purpose. For system use the select is not rendered, so it is confidential
/// even if no value arrives.
fn client_type_for(usage: &str, raw: &str) -> String {
    if usage == client_usage::SYSTEM {
        "confidential".to_string()
    } else {
        raw.to_string()
    }
}

fn parse_uris(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(str::to_string).collect()
}

/// Empty fields (and whitespace-only) are treated as "unspecified" and not sent to the api. Sending an empty string as is
/// makes the api read it as "a value was specified" and fail validation.
fn blank_to_none(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The verification key is sent only when `private_key_jwt` is selected (ADR-0030).
///
/// The edit form's field still contains the current key, so sending it as is in an update switching to another method
/// would make the api read "a key was specified" and reject it for anything but `private_key_jwt`
/// (= the method could not be switched from the screen). Values not matching the method are not sent.
fn jwks_for_method(method: &Option<String>, raw: &Option<String>) -> Option<String> {
    if method.as_deref() != Some("private_key_jwt") {
        return None;
    }
    blank_to_none(raw)
}

/// Verification key sent to the api on new registration.
///
/// `jwks_for_method` plus the client type check. The new form keeps the verification key field in the DOM even while
/// public is selected (if not rendered, the field would not reappear when JS switches back to confidential),
/// so values submitted while still public are dropped here. The edit form does not show the method/key fields for public,
/// so this check is not needed there (the client type cannot be changed after registration).
fn jwks_for_new_client(
    client_type: &str,
    method: &Option<String>,
    raw: &Option<String>,
) -> Option<String> {
    if client_type != "confidential" {
        return None;
    }
    jwks_for_method(method, raw)
}

/// Authentication method when re-rendering the new registration form after an input error.
///
/// The new form's select is always rendered so a value normally arrives, but if not, it is aligned to the same
/// `private_key_jwt` as the new form's initial selection (`ClientFormValues::default_new`) and the api's default (ADR-0036).
/// If the 3 places had separate defaults, the selection would change between the initial display and a re-render.
fn auth_method_or_default(raw: &Option<String>) -> String {
    raw.as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("private_key_jwt")
        .to_string()
}

/// Turns the checked scopes into the array sent to the api.
///
/// `openid` is required at registration (`validate_scopes`), so it has no field and is always put first.
/// Making it removable would show an option that always yields a 400 the moment it is removed.
fn selected_scopes(
    profile: &Option<String>,
    email: &Option<String>,
    offline_access: &Option<String>,
) -> Vec<String> {
    let mut scopes = vec!["openid".to_string()];
    for (checked, scope) in [
        (profile, "profile"),
        (email, "email"),
        (offline_access, "offline_access"),
    ] {
        if checked.is_some() {
            scopes.push(scope.to_string());
        }
    }
    scopes
}

// ── CSRF ─────────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

// ── Rendering ──────────────────────────────────────────────────────────────

fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    page: &ClientListView,
    offset: i64,
) -> String {
    let list_href = ClientKind::RelyingParty.list_href(tenant);
    let links = crate::pagination::pager_links(&list_href, &[], offset, page.limit, page.total);
    render(&ClientsList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        title: messages.get("admin-clients-title"),
        new_label: messages.get(ClientKind::RelyingParty.new_key()),
        new_href: ClientKind::RelyingParty.new_href(tenant),
        none_label: messages.get("admin-clients-none"),
        clients: &page.clients,
        total: page.total,
        prev_href: links.prev,
        next_href: links.next,
    })
}

fn render_new_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    values: &ClientFormValues,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: error.as_deref(),
        heading: &messages.get(ClientKind::from_usage(&values.usage).new_key()),
        action: &ClientKind::from_usage(&values.usage).new_href(tenant),
        is_new: true,
        values,
        list_href: ClientKind::from_usage(&values.usage).list_href(tenant),
    })
}

fn render_new_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    values: &ClientFormValues,
    error: &str,
) -> String {
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: Some(error),
        heading: &messages.get(ClientKind::from_usage(&values.usage).new_key()),
        action: &ClientKind::from_usage(&values.usage).new_href(tenant),
        is_new: true,
        values,
        list_href: ClientKind::from_usage(&values.usage).list_href(tenant),
    })
}

fn render_edit_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    client: &ClientView,
    csrf: &str,
    values: &ClientFormValues,
    error: Option<String>,
) -> String {
    render(&ClientForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: error.as_deref(),
        heading: &format!("{}: {}", messages.get("admin-client-edit"), client.app_name),
        action: &format!(
            "{}{CLIENTS_SEGMENT}/{}/edit",
            tenant.prefix(),
            client.client_id
        ),
        is_new: false,
        values,
        list_href: ClientKind::of(client).list_href(tenant),
    })
}

#[allow(clippy::too_many_arguments)]
fn render_detail(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    client: &ClientView,
    csrf: &str,
    permission_codes: &[String],
    grantable_permissions: &[String],
    permissions_load_failed: bool,
    error_key: Option<&'static str>,
) -> String {
    render(&ClientDetail {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        client,
        csrf,
        permission_codes,
        grantable_permissions,
        permissions_load_failed,
        // Only clients that can use `client_credentials` can get tokens for an audience. Which audiences are allowed is
        // decided not here but by the "principals" of the app claiming that audience (ADR-0059).
        shows_resources: is_system_client(client),
        // Only system clients can get admin tokens (ADR-0037). Attaching to others would have no effect,
        // so the whole section is hidden. However, if already held, it is shown so it can be revoked.
        shows_permissions: is_system_client(client) || !permission_codes.is_empty(),
        // Unlike revocation, the grant form is shown only for system clients. Do not let ineffective permissions be added to
        // a browser-login client that merely still has permissions left after its purpose changed, etc.
        shows_grant_form: is_system_client(client),
        error_key,
        list_href: ClientKind::of(client).list_href(tenant),
    })
}

/// Whether it is a system client (can use `client_credentials`). Only this kind can get admin tokens (`resource={issuer}/
/// {tenant_id}/admin`), so admin permissions actually take effect only here
/// (ADR-0037). The api does not let public clients have `client_credentials`, so
/// the presence in grant_types alone decides it.
fn is_system_client(client: &ClientView) -> bool {
    client.grant_types.iter().any(|g| g == "client_credentials")
}

fn render_secret_result(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    created: &ClientCreatedView,
    is_new: bool,
) -> String {
    render_secret_page(
        ClientKind::of(&created.client),
        messages,
        tenant,
        admin,
        &created.client.client_id,
        created.client_secret.as_deref(),
        is_new,
    )
}

fn render_rotated_result(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    client: &ClientView,
    secret: &str,
) -> String {
    render_secret_page(
        ClientKind::of(client),
        messages,
        tenant,
        admin,
        &client.client_id,
        Some(secret),
        false,
    )
}

fn render_secret_page(
    kind: ClientKind,
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    client_id: &str,
    secret: Option<&str>,
    is_new: bool,
) -> String {
    let heading = if is_new {
        messages.get("admin-client-created-title")
    } else {
        messages.get("admin-client-secret-rotated-title")
    };
    render(&ClientSecret {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: &heading,
        client_id,
        secret,
        list_href: kind.list_href(tenant),
    })
}

// ── Shared response helpers ──────────────────────────────────────────────────

/// Maps the api's 401/403 to web screen behavior (lead to login / 403 screen). Anything else is 500.
fn map_data_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        AdminApiError::NotFound => not_found(messages, tenant, admin),
        other => {
            tracing::error!(error = ?debug_error(&other), "admin client console data error");
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
    }
}

fn debug_error(e: &AdminApiError) -> String {
    match e {
        AdminApiError::Validation(m) => format!("validation: {m}"),
        AdminApiError::Conflict(m) => format!("conflict: {m}"),
        AdminApiError::Transport(m) => format!("transport: {m}"),
        AdminApiError::NotFound => "not_found".into(),
        AdminApiError::Unauthorized => "unauthorized".into(),
        AdminApiError::Forbidden => "forbidden".into(),
    }
}

fn bad_request_form(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

fn bad_request_page(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    error_key: &str,
) -> Response {
    bad_request_page_msg(messages, tenant, admin, &messages.get(error_key))
}

fn bad_request_page_msg(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    message: &str,
) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: None,
        message,
        is_error: true,
        back_href: Some(&format!("{}{CLIENTS_SEGMENT}", tenant.prefix())),
        back_label: &messages.get("admin-client-back"),
    });
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: Some(&messages.get("admin-client-not-found-title")),
        message: &messages.get("admin-client-not-found-message"),
        is_error: false,
        back_href: Some(&format!("{}{CLIENTS_SEGMENT}", tenant.prefix())),
        back_label: &messages.get("admin-client-back"),
    });
    (StatusCode::NOT_FOUND, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    /// An update switching the method does not send the key left in the field (the api would reject it).
    #[test]
    fn the_jwks_field_is_only_sent_for_private_key_jwt() {
        let keys = Some(r#"{"keys":[]}"#.to_string());
        assert_eq!(
            jwks_for_method(&Some("private_key_jwt".to_string()), &keys),
            keys
        );
        assert_eq!(
            jwks_for_method(&Some("client_secret_basic".to_string()), &keys),
            None
        );
        // Opening a public client in the edit form sends no method at all.
        assert_eq!(jwks_for_method(&None, &keys), None);
        // Empty means "unspecified".
        assert_eq!(
            jwks_for_method(
                &Some("private_key_jwt".to_string()),
                &Some("  ".to_string())
            ),
            None
        );
    }

    /// In new registration the verification key field stays in the DOM while public is selected (only hidden).
    /// Input where a key was written and then switched to public is not sent to the api as is.
    #[test]
    fn a_new_public_client_never_carries_a_jwks() {
        let keys = Some(r#"{"keys":[]}"#.to_string());
        let method = Some("private_key_jwt".to_string());
        assert_eq!(jwks_for_new_client("public", &method, &keys), None);
        assert_eq!(jwks_for_new_client("confidential", &method, &keys), keys);
    }

    /// ADR-0032: translates the screen's single "purpose" into the api's two values.
    #[test]
    fn usage_maps_to_the_two_values_the_api_actually_has() {
        let uris = "https://a.example.com/cb";

        // User login: has redirect_uri and no client_credentials.
        assert!(!allows_client_credentials(client_usage::USER_LOGIN));
        assert_eq!(redirect_uris_for(client_usage::USER_LOGIN, uris).len(), 1);

        // System use: has client_credentials and no redirect_uri.
        assert!(allows_client_credentials(client_usage::SYSTEM));
        assert!(redirect_uris_for(client_usage::SYSTEM, uris).is_empty());
    }

    /// When saving after switching the purpose to "system", hidden field values are not sent.
    /// (Sending them would attach `authorization_code` on the api side, leaving a path that should be closed.)
    #[test]
    fn switching_to_a_system_client_drops_the_hidden_redirect_uris() {
        assert!(
            redirect_uris_for(client_usage::SYSTEM, "https://leftover.example.com/cb").is_empty()
        );
    }

    /// List lineage and routing of registered clients (ADR-0038).
    ///
    /// Filtering is done by the grant passed to the api. If this were swapped, service accounts would appear
    /// in the integration list.
    #[test]
    fn each_kind_has_its_own_list_and_entry() {
        // The service account list is the account list (ADR-0065). Registration entry points are per kind.
        let tenant = WebTenant("t".to_string());
        assert!(ClientKind::ServiceAccount
            .list_href(&tenant)
            .ends_with("/admin/accounts?kind=service_account"));
        assert!(ClientKind::ServiceAccount
            .new_href(&tenant)
            .ends_with("/admin/service-accounts/new"));
        assert!(ClientKind::RelyingParty
            .new_href(&tenant)
            .ends_with("/admin/clients/new"));

        // A registered item's lineage is decided by the presence of client_credentials alone.
        let rp = client_view(&["authorization_code"], &["https://a.example.com/cb"]);
        let sa = client_view(&["client_credentials"], &[]);
        assert!(ClientKind::of(&rp) == ClientKind::RelyingParty);
        assert!(ClientKind::of(&sa) == ClientKind::ServiceAccount);
    }

    /// The purpose of the new registration form is decided by the entry point (ADR-0038). The form shows no choice.
    #[test]
    fn the_entry_point_decides_the_usage_of_a_new_client() {
        assert_eq!(ClientKind::RelyingParty.usage(), client_usage::USER_LOGIN);
        assert_eq!(ClientKind::ServiceAccount.usage(), client_usage::SYSTEM);
        // From the purpose carried in a hidden field, it can return to the same lineage (source of the return target and action).
        assert!(ClientKind::from_usage(client_usage::SYSTEM) == ClientKind::ServiceAccount);
        assert!(ClientKind::from_usage(client_usage::USER_LOGIN) == ClientKind::RelyingParty);
        // Unknown values fall back to integration (the side that keeps the redirect_uri field).
        assert!(ClientKind::from_usage("nonsense") == ClientKind::RelyingParty);
    }

    /// `allow_client_credentials` is uniquely determined by the purpose (ADR-0032 Revised).
    ///
    /// Before the grace clause was removed, it returned `None` (= leave alone) only for clients already saved in the
    /// "both" shape. The api now rejects that shape on both registration and update, so **it is decided by the screen's purpose
    /// alone**. If this broke, saving without changing the purpose would silently change the permission.
    #[test]
    fn the_usage_alone_decides_client_credentials() {
        assert!(!allow_client_credentials_update(client_usage::USER_LOGIN));
        assert!(allow_client_credentials_update(client_usage::SYSTEM));
    }

    fn client_view(grant_types: &[&str], redirect_uris: &[&str]) -> ClientView {
        ClientView {
            id: "id".into(),
            client_id: "abc123".into(),
            client_type: "confidential".into(),
            client_status: "ACTIVE".into(),
            app_name: "Legacy App".into(),
            redirect_uris: redirect_uris.iter().map(|s| s.to_string()).collect(),
            grant_types: grant_types.iter().map(|s| s.to_string()).collect(),
            response_types: vec!["code".into()],
            scopes: vec!["openid".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            jwks: None,
            created_at: "2026-07-06T00:00:00Z".into(),
            updated_at: "2026-07-06T00:00:00Z".into(),
        }
    }

    /// For system use the client_type select is not rendered, so it is confidential even if no value arrives.
    #[test]
    fn system_clients_are_always_confidential() {
        assert_eq!(client_type_for(client_usage::SYSTEM, ""), "confidential");
        assert_eq!(
            client_type_for(client_usage::SYSTEM, "public"),
            "confidential"
        );
        // For other purposes the chosen value is passed through as is.
        assert_eq!(
            client_type_for(client_usage::USER_LOGIN, "public"),
            "public"
        );
    }

    #[test]
    fn parse_uris_splits_and_drops_blanks() {
        let raw = "https://a.example.com/cb\n  https://b.example.com/cb \n\n";
        assert_eq!(
            parse_uris(raw),
            vec![
                "https://a.example.com/cb".to_string(),
                "https://b.example.com/cb".to_string()
            ]
        );
        assert!(parse_uris("   \n  ").is_empty());
    }

    /// `openid` has no field and is always attached. Making it removable would show an option that always yields
    /// a 400 the moment it is removed (`validate_scopes` requires it).
    #[test]
    fn openid_is_always_sent_and_the_rest_follow_the_checkboxes() {
        let on = || Some("on".to_string());
        assert_eq!(selected_scopes(&None, &None, &None), vec!["openid"]);
        assert_eq!(
            selected_scopes(&on(), &on(), &on()),
            vec!["openid", "profile", "email", "offline_access"]
        );
        assert_eq!(
            selected_scopes(&None, &on(), &None),
            vec!["openid", "email"]
        );
    }

    #[test]
    fn list_escapes_client_fields() {
        let messages = Messages::new(Locale::Ja);
        let client = ClientView {
            id: "id".into(),
            client_id: "abc123".into(),
            client_type: "public".into(),
            client_status: "ACTIVE".into(),
            app_name: "<script>Evil</script>".into(),
            redirect_uris: vec!["https://a.example.com/cb".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scopes: vec!["openid".into()],
            token_endpoint_auth_method: "none".into(),
            jwks: None,
            created_at: "2026-07-06T00:00:00Z".into(),
            updated_at: "2026-07-06T00:00:00Z".into(),
        };
        let tenant = WebTenant("00000000-0000-7000-8000-000000000000".to_string());
        let page = ClientListView {
            clients: vec![client],
            total: 1,
            limit: 50,
            offset: 0,
        };
        let html = render_list(
            &messages,
            &tenant,
            &AdminContext::for_test("admin-1", Some("Acme")),
            &page,
            0,
        );
        // Askama escapes HTML with numeric character references (`<` → `&#60;`). Verify no raw tags remain.
        assert!(html.contains("&#60;script&#62;Evil&#60;/script&#62;"));
        assert!(!html.contains("<script>Evil"));
    }

    // ── Admin permissions section (ADR-0037) ─────────────────────────────────────────────

    fn detail_html(
        grant_types: &[&str],
        held: &[&str],
        grantable: &[&str],
        load_failed: bool,
    ) -> String {
        let held: Vec<String> = held.iter().map(|s| s.to_string()).collect();
        let grantable: Vec<String> = grantable.iter().map(|s| s.to_string()).collect();
        render_detail(
            &Messages::new(Locale::Ja),
            &WebTenant("t".into()),
            &AdminContext::for_test("admin", Some("Root")),
            &client_view(grant_types, &[]),
            "csrf-token",
            &held,
            &grantable,
            load_failed,
            None,
        )
    }

    /// The admin permissions section is shown only for system clients (`client_credentials`),
    /// rendering held codes and the grant form.
    #[test]
    fn a_system_client_gets_the_management_permission_section() {
        let html = detail_html(
            &["client_credentials"],
            &["idp.users:read"],
            &["idp.audit:read"],
            false,
        );
        assert!(html.contains("idp.users:read"), "{html}");
        assert!(html.contains("permissions/revoke"), "{html}");
        assert!(html.contains("permissions/grant"), "{html}");
        assert!(html.contains("idp.audit:read"), "{html}");
    }

    /// Not shown for browser-login clients. They have no way to get an admin token, so it would show
    /// operations that have no effect even when applied.
    #[test]
    fn a_browser_client_does_not_get_the_section() {
        let html = detail_html(&["authorization_code"], &[], &["idp.audit:read"], false);
        assert!(!html.contains("permissions/grant"), "{html}");
        assert!(!html.contains("permissions/revoke"), "{html}");
    }

    /// However, if already held it is shown — otherwise there would be no path to revoke
    /// (they can remain after the purpose changed, etc.).
    #[test]
    fn a_browser_client_that_still_holds_codes_can_revoke_them() {
        let html = detail_html(&["authorization_code"], &["idp.users:read"], &[], false);
        assert!(html.contains("permissions/revoke"), "{html}");
        assert!(html.contains("idp.users:read"), "{html}");
    }

    /// Even when the revocation path is shown, the grant form is not. Browser-login clients
    /// cannot get admin tokens, so newly added permissions would never take effect (ADR-0037).
    #[test]
    fn a_browser_client_holding_codes_still_cannot_be_granted_more() {
        let html = detail_html(
            &["authorization_code"],
            &["idp.users:read"],
            &["idp.audit:read"],
            false,
        );
        assert!(html.contains("permissions/revoke"), "{html}");
        assert!(!html.contains("permissions/grant"), "{html}");
        assert!(!html.contains("idp.audit:read"), "{html}");
    }

    /// When fetching candidates fails, do not let it be mistaken for "no candidates".
    #[test]
    fn a_failed_candidate_load_is_reported_as_a_failure_not_as_an_empty_list() {
        let messages = Messages::new(Locale::Ja);
        let html = detail_html(&["client_credentials"], &[], &[], true);
        assert!(
            html.contains(&messages.get("admin-permissions-grant-load-failed")),
            "{html}"
        );
        assert!(
            !html.contains(&messages.get("admin-client-permissions-grant-none-left")),
            "{html}"
        );
        assert!(!html.contains("permissions/grant"), "{html}");
    }

    /// When no grantable codes remain, say so (do not show an empty select).
    #[test]
    fn nothing_left_to_grant_is_stated_plainly() {
        let messages = Messages::new(Locale::Ja);
        let html = detail_html(&["client_credentials"], &["idp.users:read"], &[], false);
        assert!(
            html.contains(&messages.get("admin-client-permissions-grant-none-left")),
            "{html}"
        );
        assert!(!html.contains("permissions/grant"), "{html}");
    }
}
