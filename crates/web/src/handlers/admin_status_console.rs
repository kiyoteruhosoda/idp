//! 状況確認画面（web。A3・ADR-0007 §4）。監査／ログインログ一覧とクライアント状況一覧。
//!
//! api の JSON 管理 API（`GET /admin/audit-logs`・`GET /admin/clients/status`）を管理者の SSO Cookie
//! 転送で呼び、結果を HTML に描画する。読み取り専用のため CSRF は無い。文字列は [`escape`] を通す。
//! 期間（from/to）の形式不正は api が 400 を返すため、web はそれを日時エラー表示へ写す。

use crate::admin_dto::AuditLogView;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, render_layout, resolve_admin, AdminResolution,
};
use crate::html::escape;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::admin::ClientStatusResponse;
use serde::Deserialize;

const AUDIT_PATH: &str = "/admin/console/audit-logs";
/// api の既定ページサイズ（`audit_query::DEFAULT_LIMIT` と一致させる。ページャの「次あり」判定に使う）。
const DEFAULT_LIMIT: i64 = 50;

// ── 監査ログ一覧 ──────────────────────────────────────────────────────────────

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
    headers: HeaderMap,
    Query(form): Query<AuditForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let offset = form.offset.unwrap_or(0).max(0);

    // フィルタを (key, value) の並びへ（空値は送らない）。offset は常に送る。
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
        .search_audit_logs(&correlation.0, &sso(&headers), &query)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(entries) => {
            Html(render_audit(&messages, &admin, &form, offset, false, &entries)).into_response()
        }
        // from/to の形式不正（api が 400）→ 日時エラー表示・空一覧。
        Err(AdminApiError::Validation(_)) => {
            Html(render_audit(&messages, &admin, &form, offset, true, &[])).into_response()
        }
        Err(AdminApiError::Unauthorized) => redirect_to_login(),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &admin),
    }
}

// ── クライアント状況一覧 ──────────────────────────────────────────────────────

pub async fn client_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let result = state
        .api
        .list_client_status(&correlation.0, &sso(&headers))
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(views) => Html(render_status(&messages, &admin, &views)).into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &admin),
    }
}

fn sso(headers: &HeaderMap) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_audit(
    messages: &Messages,
    admin: &str,
    form: &AuditForm,
    offset: i64,
    date_error: bool,
    entries: &[AuditLogView],
) -> String {
    let error_html = if date_error {
        format!(
            "<p class=\"error\" role=\"alert\">{}</p>",
            escape(&messages.get("admin-audit-error-datetime"))
        )
    } else {
        String::new()
    };

    let table = if entries.is_empty() {
        format!("<p>{}</p>", escape(&messages.get("admin-audit-none")))
    } else {
        let rows: String = entries.iter().map(render_audit_row).collect();
        format!(
            "<table>\n<thead><tr>\
             <th>{time}</th><th>{event}</th><th>{result}</th><th>{client}</th>\
             <th>{corr}</th><th>{ip}</th><th>{reason}</th></tr></thead>\n\
             <tbody>{rows}</tbody></table>",
            time = escape(&messages.get("admin-audit-col-time")),
            event = escape(&messages.get("admin-audit-col-event")),
            result = escape(&messages.get("admin-audit-col-result")),
            client = escape(&messages.get("admin-audit-col-client")),
            corr = escape(&messages.get("admin-audit-col-correlation")),
            ip = escape(&messages.get("admin-audit-col-ip")),
            reason = escape(&messages.get("admin-audit-col-reason")),
        )
    };

    let content = format!(
        "<h2>{title}</h2>\n{error_html}\n{form_html}\n{table}\n{pager}\n\
         <p><a href=\"/admin/console\">{home}</a></p>",
        title = escape(&messages.get("admin-audit-title")),
        form_html = render_audit_form(messages, form),
        pager = render_pager(messages, form, offset, entries.len()),
        home = escape(&messages.get("admin-nav-home")),
    );
    render_layout(messages, Some(admin), &content)
}

fn render_audit_row(e: &AuditLogView) -> String {
    let result_class = if e.result == "failure" {
        " class=\"result-failure\""
    } else {
        ""
    };
    format!(
        "<tr><td>{time}</td><td><code>{event}</code></td><td{rclass}>{result}</td>\
         <td>{client}</td><td><code>{corr}</code></td><td>{ip}</td><td>{reason}</td></tr>",
        time = escape(&e.occurred_at),
        event = escape(&e.event_type),
        rclass = result_class,
        result = escape(&e.result),
        client = escape(e.client_id.as_deref().unwrap_or("-")),
        corr = escape(&e.correlation_id),
        ip = escape(e.ip_address.as_deref().unwrap_or("-")),
        reason = escape(e.reason.as_deref().unwrap_or("-")),
    )
}

fn render_audit_form(messages: &Messages, form: &AuditForm) -> String {
    let v = |o: &Option<String>| escape(o.as_deref().unwrap_or(""));
    let result = form.result.as_deref().unwrap_or("");
    format!(
        "<form method=\"get\" action=\"{path}\">\n\
         <p><label>{event_label} <input type=\"text\" name=\"event_type\" value=\"{event}\"></label>\n\
         <label>{result_label} <select name=\"result\">\
         <option value=\"\"{all_sel}>{result_all}</option>\
         <option value=\"success\"{ok_sel}>success</option>\
         <option value=\"failure\"{fail_sel}>failure</option></select></label></p>\n\
         <p><label>{client_label} <input type=\"text\" name=\"client_id\" value=\"{client}\"></label>\n\
         <label>{corr_label} <input type=\"text\" name=\"correlation_id\" value=\"{corr}\"></label></p>\n\
         <p><label>{from_label} <input type=\"text\" name=\"from\" value=\"{from}\" placeholder=\"2026-07-06T00:00:00Z\"></label>\n\
         <label>{to_label} <input type=\"text\" name=\"to\" value=\"{to}\" placeholder=\"2026-07-06T23:59:59Z\"></label>\
         <small>{dt_hint}</small></p>\n\
         <p><button type=\"submit\">{search}</button> <a href=\"{path}\">{reset}</a></p>\n\
         </form>",
        path = AUDIT_PATH,
        event_label = escape(&messages.get("admin-audit-filter-event")),
        event = v(&form.event_type),
        result_label = escape(&messages.get("admin-audit-filter-result")),
        result_all = escape(&messages.get("admin-audit-filter-result-all")),
        all_sel = selected(result.is_empty()),
        ok_sel = selected(result == "success"),
        fail_sel = selected(result == "failure"),
        client_label = escape(&messages.get("admin-audit-filter-client")),
        client = v(&form.client_id),
        corr_label = escape(&messages.get("admin-audit-filter-correlation")),
        corr = v(&form.correlation_id),
        from_label = escape(&messages.get("admin-audit-filter-from")),
        from = v(&form.from),
        to_label = escape(&messages.get("admin-audit-filter-to")),
        to = v(&form.to),
        dt_hint = escape(&messages.get("admin-audit-filter-datetime-hint")),
        search = escape(&messages.get("admin-audit-search")),
        reset = escape(&messages.get("admin-audit-reset")),
    )
}

fn render_pager(messages: &Messages, form: &AuditForm, offset: i64, page_len: usize) -> String {
    let mut links = Vec::new();
    if offset > 0 {
        let prev = (offset - DEFAULT_LIMIT).max(0);
        links.push(format!(
            "<a href=\"{}\">{}</a>",
            audit_query_string(form, prev),
            escape(&messages.get("admin-audit-prev"))
        ));
    }
    if page_len as i64 == DEFAULT_LIMIT {
        links.push(format!(
            "<a href=\"{}\">{}</a>",
            audit_query_string(form, offset + DEFAULT_LIMIT),
            escape(&messages.get("admin-audit-next"))
        ));
    }
    if links.is_empty() {
        String::new()
    } else {
        format!("<p class=\"pager\">{}</p>", links.join(" | "))
    }
}

fn audit_query_string(form: &AuditForm, offset: i64) -> String {
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
    format!("{AUDIT_PATH}?{query}")
}

fn render_status(messages: &Messages, admin: &str, views: &[ClientStatusResponse]) -> String {
    let body = if views.is_empty() {
        format!("<p>{}</p>", escape(&messages.get("admin-status-none")))
    } else {
        let rows: String = views
            .iter()
            .map(|v| {
                format!(
                    "<tr><td>{name}</td><td><code>{id}</code></td><td>{status}</td>\
                     <td>{scopes}</td><td>{last_used}</td></tr>",
                    name = escape(&v.app_name),
                    id = escape(&v.client_id),
                    status = escape(&v.status),
                    scopes = escape(&v.scopes.join(" ")),
                    last_used = escape(v.last_used_at.as_deref().unwrap_or("-")),
                )
            })
            .collect();
        format!(
            "<table>\n<thead><tr>\
             <th>{name}</th><th>{id}</th><th>{status}</th><th>{scopes}</th><th>{last_used}</th></tr></thead>\n\
             <tbody>{rows}</tbody></table>",
            name = escape(&messages.get("admin-status-col-name")),
            id = escape(&messages.get("admin-status-col-id")),
            status = escape(&messages.get("admin-status-col-status")),
            scopes = escape(&messages.get("admin-status-col-scopes")),
            last_used = escape(&messages.get("admin-status-col-last-used")),
        )
    };
    let content = format!(
        "<h2>{title}</h2>\n<p>{intro}</p>\n{body}\n<p><a href=\"/admin/console\">{home}</a></p>",
        title = escape(&messages.get("admin-status-title")),
        intro = escape(&messages.get("admin-status-intro")),
        home = escape(&messages.get("admin-nav-home")),
    );
    render_layout(messages, Some(admin), &content)
}

// ── 共通ヘルパー ──────────────────────────────────────────────────────────────

fn selected(on: bool) -> &'static str {
    if on {
        " selected"
    } else {
        ""
    }
}

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

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn internal_error(messages: &Messages, admin: &str) -> Response {
    let content = format!(
        "<p class=\"error\" role=\"alert\">{}</p>",
        escape(&messages.get("admin-error-internal"))
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render_layout(messages, Some(admin), &content)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let messages = Messages::new(Locale::En);
        let html = render_audit(
            &messages,
            "admin-1",
            &AuditForm::default(),
            0,
            false,
            &[entry("login.failed", "failure", Some("<bad>"))],
        );
        assert!(html.contains("&lt;client&gt;"));
        assert!(html.contains("&lt;bad&gt;"));
        assert!(html.contains("result-failure"));
        assert!(!html.contains("<client>"));
    }

    #[test]
    fn audit_shows_datetime_error_banner() {
        let messages = Messages::new(Locale::En);
        let html = render_audit(&messages, "admin-1", &AuditForm::default(), 0, true, &[]);
        assert!(html.contains("role=\"alert\""));
    }

    #[test]
    fn query_string_preserves_filters_and_encodes() {
        let form = AuditForm {
            result: Some("failure".into()),
            client_id: Some("a b".into()),
            ..AuditForm::default()
        };
        let url = audit_query_string(&form, 50);
        assert!(url.contains("result=failure"));
        assert!(url.contains("client_id=a%20b"));
        assert!(url.ends_with("offset=50"));
    }

    #[test]
    fn status_table_renders_last_used_and_dash() {
        let messages = Messages::new(Locale::En);
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
        let html = render_status(&messages, "admin-1", &views);
        assert!(html.contains("&lt;Used&gt;"));
        assert!(html.contains("DISABLED"));
        assert!(html.contains("openid profile"));
        assert!(html.contains("<td>-</td>"));
    }
}
