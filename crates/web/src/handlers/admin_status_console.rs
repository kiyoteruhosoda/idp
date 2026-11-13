//! Status screens (web. A3, ADR-0007 §4). Audit log list, error/warning log list, client status list.
//!
//! Calls the api's JSON admin APIs (`GET /admin/audit-logs`, `GET /admin/logs`, `GET /admin/clients/status`) by forwarding
//! the admin's SSO cookie and renders the results with Askama templates (`{{ }}` auto-escapes HTML). Read-only,
//! so no CSRF. For a malformed period (from/to) the api returns 400, which web maps to a date error display.

use super::locale;
use crate::admin_dto::AuditLogView;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, ApplicationLogs, AuditLogs, ClientStatus, ConsoleNotice, VersionTemplate,
};
use crate::tenant::WebTenant;
use assay_contracts::admin::ClientStatusResponse;
use assay_contracts::application_log::ApplicationLogEntryResponse;
use assay_contracts::version::{BuildTimeVersionInfoProvider, VersionInfoProvider};
use axum::extract::{Extension, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

const AUDIT_SEGMENT: &str = "/admin/audit-logs";
const APPLICATION_LOG_SEGMENT: &str = "/admin/logs";
/// The api's default page size (keep equal to `audit_query::DEFAULT_LIMIT`; used for the pager's "has next" check).
const DEFAULT_LIMIT: i64 = 50;

// ── Audit log list ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct AuditForm {
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
}

pub async fn audit_logs(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(form): Query<AuditForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let offset = form.offset.unwrap_or(0).max(0);

    // Turn filters into (key, value) pairs (empty values are not sent). offset is always sent.
    let mut query: Vec<(&str, String)> = Vec::new();
    let mut push = |k: &'static str, v: &Option<String>| {
        if let Some(v) = v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            query.push((k, v.to_string()));
        }
    };
    push("event_type", &form.event_type);
    push("result", &form.result);
    push("client_id", &form.client_id);
    push("correlation_id", &form.correlation_id);
    push("from", &form.from);
    push("to", &form.to);
    query.push(("offset", offset.to_string()));

    let result = state
        .api
        .search_audit_logs(&correlation.0, &tenant.0, &sso(&headers), &query)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(entries) => Html(render_audit(
            &messages, &tenant, &admin, &form, offset, false, &entries,
        ))
        .into_response(),
        // Malformed from/to (api 400) → date error display, empty list.
        Err(AdminApiError::Validation(_)) => Html(render_audit(
            &messages,
            &tenant,
            &admin,
            &form,
            offset,
            true,
            &[],
        ))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

// ── Error/warning log list ──────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct ApplicationLogForm {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Error/warning log screen (`log` table). The api requires `idp.system.admin`, so a tenant
/// admin gets the 403 screen (cross-tenant operational information; see the api handler's comment).
pub async fn application_logs(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(form): Query<ApplicationLogForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let offset = form.offset.unwrap_or(0).max(0);

    let mut query: Vec<(&str, String)> = Vec::new();
    let mut push = |k: &'static str, v: &Option<String>| {
        if let Some(v) = v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            query.push((k, v.to_string()));
        }
    };
    push("level", &form.level);
    push("service", &form.service);
    push("target", &form.target);
    push("correlation_id", &form.correlation_id);
    push("from", &form.from);
    push("to", &form.to);
    query.push(("offset", offset.to_string()));

    let result = state
        .api
        .search_application_logs(&correlation.0, &tenant.0, &sso(&headers), &query)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(entries) => Html(render_application_logs(
            &messages, &tenant, &admin, &form, offset, false, &entries,
        ))
        .into_response(),
        // Malformed from/to (api 400) → date error display, empty list.
        Err(AdminApiError::Validation(_)) => Html(render_application_logs(
            &messages,
            &tenant,
            &admin,
            &form,
            offset,
            true,
            &[],
        ))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

// ── Client status list ──────────────────────────────────────────────────────

pub async fn client_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let result = state
        .api
        .list_client_status(&correlation.0, &tenant.0, &sso(&headers))
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(views) => Html(render_status(&messages, &tenant, &admin, &views)).into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

fn sso(headers: &HeaderMap) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

// ── Rendering ──────────────────────────────────────────────────────────────

fn render_audit(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    form: &AuditForm,
    offset: i64,
    date_error: bool,
    entries: &[AuditLogView],
) -> String {
    let (prev_href, next_href) = pager_links(tenant, form, offset, entries.len());
    render(&AuditLogs {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        date_error,
        event_type: form.event_type.as_deref().unwrap_or(""),
        result: form.result.as_deref().unwrap_or(""),
        client_id: form.client_id.as_deref().unwrap_or(""),
        correlation_id: form.correlation_id.as_deref().unwrap_or(""),
        from: form.from.as_deref().unwrap_or(""),
        to: form.to.as_deref().unwrap_or(""),
        entries,
        prev_href,
        next_href,
    })
}

/// The pager's prev/next links (URLs with query string). `None` when not applicable.
fn pager_links(
    tenant: &WebTenant,
    form: &AuditForm,
    offset: i64,
    page_len: usize,
) -> (Option<String>, Option<String>) {
    let prev =
        (offset > 0).then(|| audit_query_string(tenant, form, (offset - DEFAULT_LIMIT).max(0)));
    let next = (page_len as i64 == DEFAULT_LIMIT)
        .then(|| audit_query_string(tenant, form, offset + DEFAULT_LIMIT));
    (prev, next)
}

fn audit_query_string(tenant: &WebTenant, form: &AuditForm, offset: i64) -> String {
    let mut params: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: &Option<String>| {
        if let Some(v) = v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            params.push((k.to_string(), v.to_string()));
        }
    };
    push("event_type", &form.event_type);
    push("result", &form.result);
    push("client_id", &form.client_id);
    push("correlation_id", &form.correlation_id);
    push("from", &form.from);
    push("to", &form.to);
    params.push(("offset".to_string(), offset.to_string()));
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}{AUDIT_SEGMENT}?{query}", tenant.prefix())
}

fn render_application_logs(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    form: &ApplicationLogForm,
    offset: i64,
    date_error: bool,
    entries: &[ApplicationLogEntryResponse],
) -> String {
    let (prev_href, next_href) = application_log_pager_links(tenant, form, offset, entries.len());
    render(&ApplicationLogs {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        date_error,
        level: form.level.as_deref().unwrap_or(""),
        service: form.service.as_deref().unwrap_or(""),
        target: form.target.as_deref().unwrap_or(""),
        correlation_id: form.correlation_id.as_deref().unwrap_or(""),
        from: form.from.as_deref().unwrap_or(""),
        to: form.to.as_deref().unwrap_or(""),
        entries,
        prev_href,
        next_href,
    })
}

fn application_log_pager_links(
    tenant: &WebTenant,
    form: &ApplicationLogForm,
    offset: i64,
    page_len: usize,
) -> (Option<String>, Option<String>) {
    let prev = (offset > 0)
        .then(|| application_log_query_string(tenant, form, (offset - DEFAULT_LIMIT).max(0)));
    let next = (page_len as i64 == DEFAULT_LIMIT)
        .then(|| application_log_query_string(tenant, form, offset + DEFAULT_LIMIT));
    (prev, next)
}

fn application_log_query_string(
    tenant: &WebTenant,
    form: &ApplicationLogForm,
    offset: i64,
) -> String {
    let mut params: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: &Option<String>| {
        if let Some(v) = v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            params.push((k.to_string(), v.to_string()));
        }
    };
    push("level", &form.level);
    push("service", &form.service);
    push("target", &form.target);
    push("correlation_id", &form.correlation_id);
    push("from", &form.from);
    push("to", &form.to);
    params.push(("offset".to_string(), offset.to_string()));
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}{APPLICATION_LOG_SEGMENT}?{query}", tenant.prefix())
}

fn render_status(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    views: &[ClientStatusResponse],
) -> String {
    render(&ClientStatus {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        views,
    })
}

// ── Version information ────────────────────────────────────────────────────────────

/// Shows the running build and the migrations applied to the DB (ADR-0034).
///
/// **Placed inside the admin console.** Knowing the running commit lets outsiders judge which known bugs are
/// not yet fixed, so it is not exposed on an unauthenticated surface. On the other hand, "admins who cannot see the
/// DB directly can check the migration state" is the very purpose of this screen, so signed-in users see it.
///
/// When the api is unreachable, the schema field falls back to "unavailable" (fail-soft). web itself knows
/// the running build, so the version is readable even if the api is down.
pub async fn version(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let schema = state.api.fetch_schema_version().await;
    let messages = Messages::new(locale(&headers));
    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Html(render(&VersionTemplate {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        info: provider.version_info(),
        schema,
    }))
    .into_response()
}

/// Returns only the running build's label (`GET /{tenant_id}/admin/version/current`).
///
/// Endpoint letting an open screen notice that a new version has been deployed. The shared layout keeps
/// the build at render time in `data-build`, and `assets/console.js` compares it with this value and, if different,
/// shows "a new version is available".
///
/// ⚠ **Placed inside the admin console** (ADR-0034; the running commit is not exposed on an unauthenticated surface).
/// If not signed in, a 302 to the login screen is returned, and the script does not follow it and does nothing.
/// ⚠ The whoami looked up here does not extend the SSO session's expiry (only authorization requests do).
/// Even if an open screen keeps polling, "sign out after inactivity" still works.
pub async fn current_build(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    if let AdminResolution::Reject(resp) =
        resolve_admin(&state, &correlation, &tenant, &headers).await
    {
        return resp;
    }
    (
        [
            (CONTENT_TYPE, "text/plain; charset=utf-8"),
            // The comparison target is the build of "the process that just answered", so do not cache it.
            (CACHE_CONTROL, "no-store"),
        ],
        crate::templates::footer_version(),
    )
        .into_response()
}

// ── Shared helpers ──────────────────────────────────────────────────────────────

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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
mod tests {
    use super::*;
    use crate::i18n::Locale;

    fn tenant() -> WebTenant {
        WebTenant("00000000-0000-7000-8000-000000000000".to_string())
    }

    fn entry(event: &str, result: &str, reason: Option<&str>) -> AuditLogView {
        AuditLogView {
            id: 1,
            event_type: event.into(),
            occurred_at: "2026-07-06T00:00:00Z".into(),
            user_id: None,
            client_id: Some("<client>".into()),
            ip_address: Some("203.0.113.5".into()),
            user_agent: None,
            result: result.into(),
            reason: reason.map(str::to_string),
            correlation_id: "corr-1".into(),
        }
    }

    #[test]
    fn audit_row_escapes_and_marks_failures() {
        let messages = Messages::new(Locale::Ja);
        let html = render_audit(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &AuditForm::default(),
            0,
            false,
            &[entry("login.failed", "failure", Some("<bad>"))],
        );
        // Askama escapes HTML with numeric character references (`<` → `&#60;`). Verify no raw tags remain.
        assert!(html.contains("&#60;client&#62;"));
        assert!(html.contains("&#60;bad&#62;"));
        assert!(html.contains("result-failure"));
        assert!(!html.contains("<client>"));
    }

    #[test]
    fn audit_shows_datetime_error_banner() {
        let messages = Messages::new(Locale::Ja);
        let html = render_audit(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &AuditForm::default(),
            0,
            true,
            &[],
        );
        assert!(html.contains("role=\"alert\""));
    }

    #[test]
    fn query_string_preserves_filters_and_encodes() {
        let form = AuditForm {
            result: Some("failure".into()),
            client_id: Some("a b".into()),
            ..AuditForm::default()
        };
        let url = audit_query_string(&tenant(), &form, 50);
        assert!(url.contains("result=failure"));
        assert!(url.contains("client_id=a%20b"));
        assert!(url.ends_with("offset=50"));
    }

    #[test]
    fn status_table_renders_last_used_and_dash() {
        let messages = Messages::new(Locale::Ja);
        let views = vec![
            ClientStatusResponse {
                client_id: "used".into(),
                app_name: "<Used>".into(),
                status: "ACTIVE".into(),
                scopes: vec!["openid".into(), "profile".into()],
                last_used_at: Some("2026-07-06T00:00:00Z".into()),
            },
            ClientStatusResponse {
                client_id: "fresh".into(),
                app_name: "Fresh".into(),
                status: "DISABLED".into(),
                scopes: vec!["openid".into()],
                last_used_at: None,
            },
        ];
        let html = render_status(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &views,
        );
        // Askama escapes HTML with numeric character references (`<` → `&#60;`).
        assert!(html.contains("&#60;Used&#62;"));
        assert!(html.contains("DISABLED"));
        assert!(html.contains("openid profile"));
        assert!(html.contains(">-</td>"));
    }

    fn log_entry(
        level: &str,
        service: &str,
        traceback: Option<&str>,
    ) -> ApplicationLogEntryResponse {
        ApplicationLogEntryResponse {
            id: 1,
            occurred_at: "2026-07-27T00:00:00Z".into(),
            level: level.into(),
            service: service.into(),
            target: "assay_api::presentation::token".into(),
            message: "<script>alert(1)</script>".into(),
            correlation_id: Some("corr-1".into()),
            tenant_id: None,
            traceback: traceback.map(str::to_string),
        }
    }

    #[test]
    fn application_log_rows_escape_and_distinguish_levels() {
        let messages = Messages::new(Locale::Ja);
        let html = render_application_logs(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &ApplicationLogForm::default(),
            0,
            false,
            &[
                log_entry("ERROR", "api", Some("caused by: <timeout>")),
                log_entry("WARN", "web", None),
            ],
        );
        // Askama escapes HTML with numeric character references (`<` → `&#60;`). No raw tags must remain.
        assert!(html.contains("&#60;script&#62;"));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&#60;timeout&#62;"));
        // Badges are colored per level (so errors stand out in the list).
        assert!(html.contains("level-error"));
        assert!(html.contains("level-warn"));
        // Only rows with a traceback show collapsible details.
        assert_eq!(html.matches("<details").count(), 1);
    }

    #[test]
    fn application_log_shows_datetime_error_banner() {
        let messages = Messages::new(Locale::Ja);
        let html = render_application_logs(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &ApplicationLogForm::default(),
            0,
            true,
            &[],
        );
        assert!(html.contains("role=\"alert\""));
    }

    #[test]
    fn application_log_query_string_preserves_filters_and_encodes() {
        let form = ApplicationLogForm {
            level: Some("ERROR".into()),
            target: Some("assay_api::a b".into()),
            ..ApplicationLogForm::default()
        };
        let url = application_log_query_string(&tenant(), &form, 50);
        assert!(url.contains("/admin/logs?"));
        assert!(url.contains("level=ERROR"));
        // `_` is an unreserved character so it stays as is; `:` and spaces are percent-encoded.
        assert!(url.contains("target=assay_api%3A%3Aa%20b"));
        assert!(url.ends_with("offset=50"));
    }
}
