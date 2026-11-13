//! Account (people and service accounts) management screens (web. ADR-0065).
//!
//! - `GET /{tenant_id}/admin/accounts` —— a list combining people and service accounts
//! - `GET /{tenant_id}/admin/service-accounts/{client_id}` —— the screen for one service account
//!   (same skeleton as the person screen `/admin/members/{user_id}`)
//!
//! Admin notes and adding/removing "available apps" go through the shared processing here also for the person screen
//! ([`write_note`], [`change_assignment`]) — the entry points differ by kind, but there is one way of writing.
//!
//! The legacy lists (`/admin/members`, `/admin/service-accounts`) redirect to this list filtered by kind.

use super::locale;
use crate::admin_dto::AccountListView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::dto::{MemberActionForm, MemberNoteForm};
use crate::handlers::admin_clients_console::permission_error_key;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::admin_members_console::{error_key_for, notice_key_for};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::pagination::pager_links;
use crate::state::WebState;
use crate::templates::{render, AccountKindTab, AccountsList, ConsoleNotice, ServiceAccountDetail};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const ACCOUNTS_SEGMENT: &str = "/admin/accounts";
/// Kind values (same spelling as the api's `?kind=`).
const KIND_USER: &str = "user";
const KIND_SERVICE_ACCOUNT: &str = "service_account";

#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    /// `user` / `service_account`. Unspecified means "everything readable".
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notice: Option<String>,
}

/// Account list (`GET /{tenant_id}/admin/accounts`).
///
/// Filtering, paging and **deciding the readable kinds** are done by the api. web carries over the kind, search term and
/// page position, and only builds the kind options from `readable_kinds` in the response.
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(a) => a,
        AdminResolution::Reject(resp) => return resp,
    };
    let term = query.q.clone().unwrap_or_default().trim().to_string();
    // Unknown kinds are treated as "all" (do not stop someone who hand-edited the screen URL with a 400).
    let kind = match query.kind.as_deref() {
        Some(KIND_USER) => KIND_USER,
        Some(KIND_SERVICE_ACCOUNT) => KIND_SERVICE_ACCOUNT,
        _ => "",
    };
    let offset = query.offset.unwrap_or(0).max(0);
    let mut params = crate::pagination::page_query(offset);
    if !kind.is_empty() {
        params.push(("kind", kind.to_string()));
    }
    if !term.is_empty() {
        params.push(("q", term.clone()));
    }
    let result = state
        .api
        .list_accounts(&correlation.0, &tenant.0, &sso(&headers), &params)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(page) => Html(render_list(
            &messages,
            &tenant,
            &admin,
            &page,
            kind,
            &term,
            offset,
            query.error.as_deref().and_then(error_key_for),
            query.notice.as_deref().and_then(notice_key_for),
        ))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

/// Legacy member list (`GET /admin/members`). Redirects to the account list filtered to people.
pub async fn members_list(
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<ListQuery>,
) -> Response {
    found(&list_href(&tenant, KIND_USER, &query))
}

/// Legacy service account list (`GET /admin/service-accounts`). Redirects to the account list filtered to
/// service accounts.
pub async fn service_accounts_list(
    Extension(tenant): Extension<WebTenant>,
    Query(query): Query<ListQuery>,
) -> Response {
    found(&list_href(&tenant, KIND_SERVICE_ACCOUNT, &query))
}

/// URL of the list filtered by kind (search term and notices are carried over).
fn list_href(tenant: &WebTenant, kind: &str, query: &ListQuery) -> String {
    let mut href = format!("{}{ACCOUNTS_SEGMENT}?kind={kind}", tenant.prefix());
    for (key, value) in [
        ("q", query.q.as_deref()),
        ("error", query.error.as_deref()),
        ("notice", query.notice.as_deref()),
    ] {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            href.push_str(&format!("&{key}={}", encode(value)));
        }
    }
    href
}

#[derive(Debug, Default, Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notice: Option<String>,
}

/// Screen for one service account (`GET /{tenant_id}/admin/service-accounts/{client_id}`).
pub async fn service_account_detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Query(query): Query<DetailQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(a) => a,
        AdminResolution::Reject(resp) => return resp,
    };
    // ⚠ `Messages` is not `Send`, so do not hold it across an `await` (create it after the api calls).
    let sso = sso(&headers);
    let account = match state
        .api
        .get_service_account(&correlation.0, &tenant.0, &sso, &client_id)
        .await
    {
        Ok(account) => account,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return forbidden_response(&headers),
        // Other tenants, federation peers and deleted ones are not distinguished. Return to the list.
        Err(AdminApiError::NotFound) => {
            return found(&format!(
                "{}{ACCOUNTS_SEGMENT}?kind={KIND_SERVICE_ACCOUNT}&error=notfound",
                tenant.prefix()
            ))
        }
        Err(_) => {
            let messages = Messages::new(locale(&headers));
            return internal_error(&messages, &tenant, &admin);
        }
    };
    // Connection settings (auth method, kind) and admin permissions. If unreadable, fail the whole screen — confusing
    // an empty permission list with an unreadable one could lead to wrongly re-granting permissions that are already there (ADR-0037).
    let client = state
        .api
        .get_client(&correlation.0, &tenant.0, &sso, &client_id)
        .await;
    let permissions = state
        .api
        .list_client_permissions(&correlation.0, &tenant.0, &sso, &client_id)
        .await;
    let (client, permission_codes) = match (client, permissions) {
        (Ok(client), Ok(p)) => (client, p.permission_codes),
        (Err(AdminApiError::Forbidden), _) | (_, Err(AdminApiError::Forbidden)) => {
            return forbidden_response(&headers)
        }
        _ => {
            let messages = Messages::new(locale(&headers));
            return internal_error(&messages, &tenant, &admin);
        }
    };
    // Grant candidates. The screen is drawn even if they cannot be fetched (checking/revoking held permissions can continue).
    let (grantable, permissions_load_failed) = match state
        .api
        .client_grantable_permissions(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(a) => (
            a.codes
                .into_iter()
                .filter(|code| !permission_codes.contains(code))
                .collect::<Vec<_>>(),
            false,
        ),
        Err(e) => {
            tracing::warn!(error = %e, "failed to load client-grantable permission codes");
            (Vec::new(), true)
        }
    };
    // Available apps need `idp.applications:read`. Admins without it are not refused the whole screen; only the section is hidden.
    let applications = state
        .api
        .list_service_account_applications(&correlation.0, &tenant.0, &sso, &client_id)
        .await
        .ok();
    let messages = Messages::new(locale(&headers));
    let error_key = query.error.as_deref().and_then(|e| {
        // Results returning from granting/revoking permissions (`/admin/clients/{id}/permissions/*`) are also shown here.
        error_key_for(e).or_else(|| permission_error_key(e))
    });
    Html(render(&ServiceAccountDetail {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        account: &account,
        client: &client,
        applications: applications.as_ref(),
        permission_codes: &permission_codes,
        grantable_permissions: &grantable,
        permissions_load_failed,
        csrf: &console_csrf_from(&headers, state.config.csrf_secret()),
        error_key,
        notice_key: query.notice.as_deref().and_then(notice_key_for),
    }))
    .into_response()
}

/// Writes a service account's admin note (`POST .../service-accounts/{client_id}/note`).
pub async fn update_service_account_note(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<MemberNoteForm>,
) -> Response {
    write_note(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::ServiceAccount(&client_id),
        &form,
    )
    .await
}

/// Assigns this service account to an app
/// (`POST .../service-accounts/{client_id}/applications/{application_id}/assign`).
pub async fn assign_service_account_application(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id, application_id)): Path<(String, String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    change_assignment(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::ServiceAccount(&client_id),
        &application_id,
        &form,
        true,
    )
    .await
}

/// Removes this service account's assignment
/// (`POST .../service-accounts/{client_id}/applications/{application_id}/unassign`).
pub async fn unassign_service_account_application(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id, application_id)): Path<(String, String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    change_assignment(
        &state,
        &correlation,
        &tenant,
        &headers,
        AccountTarget::ServiceAccount(&client_id),
        &application_id,
        &form,
        false,
    )
    .await
}

/// The target of the operation (path values).
#[derive(Debug, Clone, Copy)]
pub(crate) enum AccountTarget<'a> {
    User(&'a str),
    ServiceAccount(&'a str),
}

impl AccountTarget<'_> {
    /// URL of the single-item screen (including the tenant). Return here after an operation.
    fn href(&self, tenant: &WebTenant) -> String {
        match self {
            Self::User(user_id) => format!("{}/admin/members/{user_id}", tenant.prefix()),
            Self::ServiceAccount(client_id) => {
                format!("{}/admin/service-accounts/{client_id}", tenant.prefix())
            }
        }
    }

    /// Where to return when not found (the list filtered by kind).
    fn not_found_href(&self, tenant: &WebTenant) -> String {
        let kind = match self {
            Self::User(_) => KIND_USER,
            Self::ServiceAccount(_) => KIND_SERVICE_ACCOUNT,
        };
        format!(
            "{}{ACCOUNTS_SEGMENT}?kind={kind}&error=notfound",
            tenant.prefix()
        )
    }
}

/// Writes an admin note (shared by people and service accounts. ADR-0063 / ADR-0065).
///
/// After writing, return to the same single-item screen (returning to the list would prevent re-reading right away).
pub(crate) async fn write_note(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    target: AccountTarget<'_>,
    form: &MemberNoteForm,
) -> Response {
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let back = target.href(tenant);
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{back}?error=csrf"));
    }
    let cleared = form.note.trim().is_empty();
    let sso = sso(headers);
    let result = match target {
        AccountTarget::User(user_id) => {
            state
                .api
                .update_member_note(&correlation.0, &tenant.0, &sso, user_id, &form.note)
                .await
        }
        AccountTarget::ServiceAccount(client_id) => {
            state
                .api
                .update_service_account_note(&correlation.0, &tenant.0, &sso, client_id, &form.note)
                .await
        }
    };
    match result {
        Ok(()) if cleared => found(&format!("{back}?notice=note-cleared")),
        Ok(()) => found(&format!("{back}?notice=note-saved")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{back}?error=forbidden-write")),
        Err(AdminApiError::NotFound) => found(&target.not_found_href(tenant)),
        // Too long (when sent with the screen's maxlength removed).
        Err(AdminApiError::Validation(_)) => found(&format!("{back}?error=note-too-long")),
        Err(_) => found(&format!("{back}?error=internal")),
    }
}

/// Adds/removes assignments to apps (shared by people and service accounts).
///
/// Calls the same API as the app details screen (`/admin/applications/{id}/assignments`). Only the entry point is on the
/// account side; the rules (being a member, being a service account, idempotency) exist only in one place in
/// the api.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn change_assignment(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    target: AccountTarget<'_>,
    application_id: &str,
    form: &MemberActionForm,
    assign: bool,
) -> Response {
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let back = target.href(tenant);
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{back}?error=csrf"));
    }
    let sso = sso(headers);
    let (kind, id) = match target {
        AccountTarget::User(user_id) => (KIND_USER, user_id),
        AccountTarget::ServiceAccount(client_id) => (KIND_SERVICE_ACCOUNT, client_id),
    };
    let result = match (assign, target) {
        (true, _) => state
            .api
            .assign_application_principal(&correlation.0, &tenant.0, &sso, application_id, kind, id)
            .await
            .map(|_| ()),
        (false, AccountTarget::User(user_id)) => {
            state
                .api
                .unassign_application_user(&correlation.0, &tenant.0, &sso, application_id, user_id)
                .await
        }
        (false, AccountTarget::ServiceAccount(client_id)) => {
            state
                .api
                .unassign_application_service_account(
                    &correlation.0,
                    &tenant.0,
                    &sso,
                    application_id,
                    client_id,
                )
                .await
        }
    };
    let notice = if assign {
        "application-assigned"
    } else {
        "application-unassigned"
    };
    match result {
        Ok(()) => found(&format!("{back}?notice={notice}")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{back}?error=forbidden-write")),
        Err(AdminApiError::NotFound) => found(&format!("{back}?error=application-notfound")),
        Err(_) => found(&format!("{back}?error=internal")),
    }
}

/// Renders the list (including the kind options and building the pager links).
#[allow(clippy::too_many_arguments)]
fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    page: &AccountListView,
    kind: &str,
    term: &str,
    offset: i64,
    error_key: Option<&str>,
    notice_key: Option<&str>,
) -> String {
    let base = format!("{}{ACCOUNTS_SEGMENT}", tenant.prefix());
    let links = pager_links(
        &base,
        &[("kind", kind), ("q", term)],
        offset,
        page.limit,
        page.total,
    );
    let readable = |k: &str| page.readable_kinds.iter().any(|r| r == k);
    // The kind options only make sense when two or more kinds are readable (the template decides by count).
    let mut kind_tabs = vec![AccountKindTab {
        label: "admin-accounts-kind-all",
        href: with_query(&base, &[("q", term)]),
        active: kind.is_empty(),
    }];
    for (value, label) in [
        (KIND_USER, "admin-accounts-kind-user"),
        (KIND_SERVICE_ACCOUNT, "admin-accounts-kind-service-account"),
    ] {
        if readable(value) {
            kind_tabs.push(AccountKindTab {
                label,
                href: with_query(&base, &[("kind", value), ("q", term)]),
                active: kind == value,
            });
        }
    }
    if kind_tabs.len() <= 2 {
        kind_tabs.clear();
    }
    render(&AccountsList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        accounts: &page.accounts,
        total: page.total,
        query: term,
        kind,
        kind_tabs,
        clear_href: with_query(&base, &[("kind", kind)]),
        can_read_users: readable(KIND_USER),
        can_read_service_accounts: readable(KIND_SERVICE_ACCOUNT),
        error_key,
        notice_key,
        prev_href: links.prev,
        next_href: links.next,
    })
}

/// Adds only non-empty values to the query.
fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    if query.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", query.join("&"))
    }
}

/// Encodes a query value (everything except alphanumerics and `-_.~` becomes %XX).
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::admin_dto::{
        AccountApplicationListView, AccountApplicationView, AccountNoteView, AccountView,
        ClientView, IdentityApplicationView, MemberView, ServiceAccountView,
    };
    use crate::i18n::Locale;

    fn tenant() -> WebTenant {
        WebTenant("00000000-0000-7000-8000-000000000000".to_string())
    }

    pub(crate) fn user_account(member: MemberView) -> AccountView {
        AccountView {
            kind: KIND_USER.into(),
            user: Some(member),
            service_account: None,
        }
    }

    fn service_account(name: &str) -> ServiceAccountView {
        ServiceAccountView {
            client_id: "c0ffee".into(),
            app_name: name.into(),
            status: "ACTIVE".into(),
            created_at: "2026-09-25T00:00:00Z".into(),
            identity_of: None,
            note: None,
        }
    }

    fn sa_account(sa: ServiceAccountView) -> AccountView {
        AccountView {
            kind: KIND_SERVICE_ACCOUNT.into(),
            user: None,
            service_account: Some(sa),
        }
    }

    fn render_with(
        accounts: Vec<AccountView>,
        readable: &[&str],
        kind: &str,
        notice_key: Option<&str>,
    ) -> String {
        let messages = Messages::new(Locale::Ja);
        let total = accounts.len() as i64;
        render_list(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &AccountListView {
                accounts,
                kinds: readable.iter().map(|k| k.to_string()).collect(),
                readable_kinds: readable.iter().map(|k| k.to_string()).collect(),
                total,
                limit: 50,
                offset: 0,
            },
            kind,
            "",
            0,
            None,
            notice_key,
        )
    }

    /// List for an admin who can read only people (used by the member screen tests).
    pub(crate) fn render_accounts(accounts: Vec<AccountView>, notice_key: Option<&str>) -> String {
        render_with(accounts, &[KIND_USER], "", notice_key)
    }

    #[test]
    fn a_service_account_row_leads_to_its_own_page_and_shows_its_client_id() {
        let mut sa = service_account("夜間同期");
        sa.note = Some(AccountNoteView {
            text: "wiki の同期\n詳しくは中で".into(),
            updated_at: "2026-09-25T00:00:00Z".into(),
        });
        let html = render_with(
            vec![sa_account(sa)],
            &[KIND_USER, KIND_SERVICE_ACCOUNT],
            "",
            None,
        );
        assert!(
            html.contains("/admin/service-accounts/c0ffee\">夜間同期</a>"),
            "{html}"
        );
        assert!(html.contains("<code>c0ffee</code>"), "{html}");
        assert!(html.contains("wiki の同期…"), "{html}");
        let messages = Messages::new(Locale::Ja);
        assert!(html.contains(&messages.get("admin-accounts-kind-service-account")));
    }

    #[test]
    fn a_disabled_service_account_is_badged() {
        let mut sa = service_account("止めた");
        sa.status = "DISABLED".into();
        let html = render_with(vec![sa_account(sa)], &[KIND_SERVICE_ACCOUNT], "", None);
        let messages = Messages::new(Locale::Ja);
        assert!(html.contains(&format!(
            "text-bg-danger\">{}",
            messages.get("admin-members-user-status-disabled")
        )));
    }

    /// Kind options are shown only when two kinds are readable.
    #[test]
    fn kind_tabs_appear_only_when_there_is_a_choice() {
        let messages = Messages::new(Locale::Ja);
        let both = render_with(Vec::new(), &[KIND_USER, KIND_SERVICE_ACCOUNT], "", None);
        assert!(
            both.contains(&messages.get("admin-accounts-kind-all")),
            "{both}"
        );
        assert!(
            both.contains("/admin/accounts?kind=service_account\""),
            "{both}"
        );
        assert!(both.contains("/admin/service-accounts/new"), "{both}");
        let one = render_with(Vec::new(), &[KIND_USER], "", None);
        assert!(!one.contains("?kind=service_account"), "{one}");
        assert!(
            !one.contains("/admin/service-accounts/new"),
            "do not offer service account registration to an admin who can read only people: {one}"
        );
    }

    /// The search box filters just by typing (`assets/live-search.js`). It renders the region to replace and the
    /// "clear" hidden when the term is empty. The button stays so it can be submitted without the script.
    #[test]
    fn the_search_box_filters_as_you_type() {
        let html = render_with(Vec::new(), &[KIND_USER, KIND_SERVICE_ACCOUNT], "", None);
        assert!(html.contains("data-live-search>"), "{html}");
        assert!(
            html.contains("data-live-search-region=\"results\""),
            "{html}"
        );
        assert!(html.contains("data-live-search-region=\"kinds\""), "{html}");
        assert!(html.contains("/assets/live-search.js?v="), "{html}");
        assert!(html.contains("data-live-search-clear hidden"), "{html}");
        assert!(html.contains("type=\"submit\""), "{html}");
    }

    #[test]
    fn old_lists_are_forwarded_to_the_filtered_account_list() {
        let q = ListQuery {
            q: Some("a b".into()),
            notice: Some("note-saved".into()),
            ..ListQuery::default()
        };
        assert_eq!(
            list_href(&tenant(), KIND_USER, &q),
            "/00000000-0000-7000-8000-000000000000/admin/accounts?kind=user&q=a%20b&notice=note-saved"
        );
    }

    fn client_view() -> ClientView {
        serde_json::from_value(serde_json::json!({
            "id": "0197-row",
            "client_id": "c0ffee",
            "client_type": "confidential",
            "client_status": "ACTIVE",
            "app_name": "夜間同期",
            "redirect_uris": [],
            "grant_types": ["client_credentials"],
            "response_types": [],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "private_key_jwt",
            "created_at": "2026-09-25T00:00:00Z",
            "updated_at": "2026-09-25T00:00:00Z",
        }))
        .expect("client view")
    }

    fn render_detail(
        account: &ServiceAccountView,
        applications: Option<&AccountApplicationListView>,
    ) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&ServiceAccountDetail {
            messages: &messages,
            tenant: &tenant().prefix(),
            admin: Some(AdminContext::for_test("admin-1", Some("Acme")).chrome()),
            account,
            client: &client_view(),
            applications,
            permission_codes: &["idp.members:read".to_string()],
            grantable_permissions: &[],
            permissions_load_failed: false,
            csrf: "csrf123",
            error_key: None,
            notice_key: None,
        })
    }

    /// Same skeleton as the person screen: note section, identity, admin permissions, edit and danger zone are all there.
    #[test]
    fn the_detail_has_the_same_skeleton_as_a_member() {
        let mut sa = service_account("夜間同期");
        sa.identity_of = Some(IdentityApplicationView {
            application_id: "app-1".into(),
            display_name: "wiki".into(),
        });
        let html = render_detail(&sa, None);
        let base = "/00000000-0000-7000-8000-000000000000/admin/service-accounts/c0ffee";
        assert!(html.contains(&format!("action=\"{base}/note\"")), "{html}");
        assert!(html.contains("maxlength=\"2000\""), "{html}");
        assert!(
            html.contains("/admin/applications/app-1\">wiki</a>"),
            "{html}"
        );
        assert!(html.contains("idp.members:read</code>"), "{html}");
        assert!(html.contains("/admin/clients/c0ffee/edit"), "{html}");
        assert!(
            html.contains("/admin/clients/c0ffee/rotate-secret"),
            "{html}"
        );
        assert!(html.contains("/admin/clients/c0ffee/delete"), "{html}");
    }

    /// The destinations of the shared note/app sections are built by struct methods (the template's static check
    /// cannot follow them). Instead, verify here that the built destinations are web routes.
    #[test]
    fn card_actions_are_routes_this_service_serves() {
        let routes = crate::router::declared_route_paths();
        let messages = Messages::new(Locale::Ja);
        let mut sa = service_account("x");
        sa.client_id = "{client_id}".into();
        let client = client_view();
        let sa_page = ServiceAccountDetail {
            messages: &messages,
            tenant: "",
            admin: None,
            account: &sa,
            client: &client,
            applications: None,
            permission_codes: &[],
            grantable_permissions: &[],
            permissions_load_failed: false,
            csrf: "",
            error_key: None,
            notice_key: None,
        };
        let mut member: MemberView = serde_json::from_value(serde_json::json!({
            "user_id": "{user_id}", "membership_type": "HOME", "status": "ACTIVE"
        }))
        .expect("member");
        member.note = None;
        let member_page = crate::templates::MemberDetail {
            messages: &messages,
            tenant: "",
            admin: None,
            member: &member,
            applications: None,
            active_tokens: None,
            csrf: "",
            error_key: None,
            notice_key: None,
        };
        for action in [
            sa_page.note_action(),
            sa_page.assignment_action("{application_id}", "assign"),
            sa_page.assignment_action("{application_id}", "unassign"),
            member_page.note_action(),
            member_page.assignment_action("{application_id}", "assign"),
            member_page.assignment_action("{application_id}", "unassign"),
        ] {
            let path = crate::router::collapse_params(&action);
            assert!(routes.contains(&path), "{action} is not a web route");
        }
    }

    /// ⚠ Service accounts are not included in "everyone" apps — the add/remove controls are shown regardless of mode.
    #[test]
    fn service_accounts_can_be_assigned_even_to_everyone_applications() {
        let apps = AccountApplicationListView {
            applications: vec![AccountApplicationView {
                application_id: "everyone".into(),
                display_name: "全員のアプリ".into(),
                status: "ACTIVE".into(),
                assignment_mode: "EVERYONE".into(),
                access: "not_assigned".into(),
                assigned_at: None,
            }],
            enforcement: "record_only".into(),
        };
        let html = render_detail(&service_account("夜間同期"), Some(&apps));
        assert!(
            html.contains("/admin/service-accounts/c0ffee/applications/everyone/assign"),
            "{html}"
        );
        let messages = Messages::new(Locale::Ja);
        assert!(html.contains(&messages.get("admin-service-account-applications-mode-everyone")));
        assert!(
            !html.contains(&messages.get("admin-member-applications-record-only")),
            "staged rollout of people's login is irrelevant to service accounts: {html}"
        );
    }
}
