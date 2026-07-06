//! 状況確認画面（A3）のサーバレンダリング。監査／ログインログ一覧とクライアント状況一覧を提供する。
//!
//! JSON 管理 API（`GET /admin/audit-logs`、OpenAPI の正典）とは経路を分け、ブラウザ向けに
//! `/admin/console/audit-logs`・`/admin/console/status` で提供する。認可は画面用 extractor
//! [`AdminHtmlSession`]。データ取得は API と同じ [`AuditQueryService`]／[`ClientStatusService`] を通す。
//!
//! - `GET /admin/console/audit-logs`: `event_type`/`result`（エラー絞り込みが主眼）/`client_id`/
//!   `correlation_id`/期間で AND 絞り込みし、新しい順に表示（`offset` 前後ページ）。
//! - `GET /admin/console/status`: 各クライアントの状態・scope・最終利用時刻の一覧。
//!
//! 読み取り専用のため状態変更フォーム（CSRF）は無い。利用者・クライアント由来の文字列を HTML へ
//! 差し込む箇所はすべて [`html::escape`] を通す。

use crate::application::audit_query::{AuditQueryParams, DEFAULT_LIMIT};
use crate::application::client_status::ClientStatusView;
use crate::domain::audit::AuditLogEntry;
use crate::presentation::admin::AdminHtmlSession;
use crate::presentation::handlers::admin_console::render_layout;
use crate::presentation::html::escape;
use crate::presentation::i18n::{Locale, Messages};
use crate::presentation::state::AppState;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

const AUDIT_PATH: &str = "/admin/console/audit-logs";

// ── 監査ログ一覧（GET /admin/console/audit-logs） ─────────────────────────────

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
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(form): Query<AuditForm>,
) -> Response {
    // 期間はここで RFC3339 として解釈する（await を含まない）。不正なら検索せずエラー表示する。
    let from = parse_rfc3339(form.from.as_deref());
    let to = parse_rfc3339(form.to.as_deref());
    let offset = form.offset.unwrap_or(0).max(0);

    let search = match (&from, &to) {
        (Err(_), _) | (_, Err(_)) => None,
        (Ok(from), Ok(to)) => {
            let params = AuditQueryParams {
                event_type: form.event_type.clone(),
                result: form.result.clone(),
                client_id: form.client_id.clone(),
                correlation_id: form.correlation_id.clone(),
                from: *from,
                to: *to,
                limit: Some(DEFAULT_LIMIT),
                offset: Some(offset),
            };
            Some(state.audit_query.search(params).await)
        }
    };

    // `Messages`（FluentBundle）は Send でないため await 後に生成する（login.rs と同じ理由）。
    let messages = Messages::new(locale(&headers));
    let date_error = from.is_err() || to.is_err();
    match search {
        Some(Err(e)) => internal_error(&messages, &admin, &e.to_string()),
        Some(Ok(entries)) => Html(render_audit(
            &messages, &admin, &form, offset, date_error, &entries,
        ))
        .into_response(),
        None => Html(render_audit(
            &messages,
            &admin,
            &form,
            offset,
            date_error,
            &[],
        ))
        .into_response(),
    }
}

// ── クライアント状況一覧（GET /admin/console/status） ─────────────────────────

pub async fn client_status(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let result = state.clients_status.list().await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(views) => Html(render_status(&messages, &admin, &views)).into_response(),
        Err(e) => internal_error(&messages, &admin, &e.to_string()),
    }
}

// ── 入力パース ────────────────────────────────────────────────────────────────

/// RFC3339 の日時をパースする。空・未指定は `Ok(None)`、形式不正は `Err`（画面でエラー表示）。
fn parse_rfc3339(value: Option<&str>) -> Result<Option<DateTime<Utc>>, ()> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| ())
}

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_audit(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    form: &AuditForm,
    offset: i64,
    date_error: bool,
    entries: &[AuditLogEntry],
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

fn render_audit_row(e: &AuditLogEntry) -> String {
    let result_class = if e.result == "failure" {
        " class=\"result-failure\""
    } else {
        ""
    };
    format!(
        "<tr><td>{time}</td><td><code>{event}</code></td><td{rclass}>{result}</td>\
         <td>{client}</td><td><code>{corr}</code></td><td>{ip}</td><td>{reason}</td></tr>",
        time = escape(&e.occurred_at.to_rfc3339()),
        event = escape(&e.event_type),
        rclass = result_class,
        result = escape(&e.result),
        client = escape(e.client_id.as_deref().unwrap_or("-")),
        corr = escape(&e.correlation_id),
        ip = escape(e.ip_address.as_deref().unwrap_or("-")),
        reason = escape(e.reason.as_deref().unwrap_or("-")),
    )
}

/// 監査ログの絞り込みフォーム（GET）。`result` は選択、その他はテキスト入力。
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

/// 前後ページのリンク。`offset` を ±`DEFAULT_LIMIT` する。フィルタ条件は引き継ぐ。
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
    // ちょうど 1 ページ分返っていれば次ページがあり得る。
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

/// 現在のフィルタ条件を保ったまま `offset` だけ差し替えたクエリ文字列付き URL を作る。
/// 値はすべて URL エンコードする。
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

fn render_status(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    views: &[ClientStatusView],
) -> String {
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
                    status = escape(v.status.as_str()),
                    scopes = escape(&v.scopes.join(" ")),
                    last_used = escape(
                        &v.last_used_at
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_else(|| "-".to_string())
                    ),
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

/// クエリ値の最小 URL エンコード（英数・`-._~` 以外を %XX にする）。
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

fn internal_error(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    error: &str,
) -> Response {
    tracing::error!(error = %error, "admin status console failed");
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
    use crate::domain::values::ClientStatus;

    fn admin() -> crate::application::admin_access::AuthorizedAdmin {
        crate::application::admin_access::AuthorizedAdmin {
            user_id: uuid::Uuid::new_v4(),
        }
    }

    fn entry(event_type: &str, result: &str, reason: Option<&str>) -> AuditLogEntry {
        AuditLogEntry {
            id: 1,
            event_type: event_type.to_string(),
            occurred_at: Utc::now(),
            user_id: None,
            client_id: Some("<client>".to_string()),
            ip_address: Some("203.0.113.5".to_string()),
            user_agent: None,
            result: result.to_string(),
            reason: reason.map(str::to_string),
            correlation_id: "corr-1".to_string(),
        }
    }

    #[test]
    fn audit_row_escapes_and_marks_failures() {
        let messages = Messages::new(Locale::En);
        let e = entry("login.failed", "failure", Some("<bad>"));
        let html = render_audit(&messages, &admin(), &AuditForm::default(), 0, false, &[e]);
        assert!(html.contains("&lt;client&gt;"), "client id escaped");
        assert!(html.contains("&lt;bad&gt;"), "reason escaped");
        assert!(html.contains("result-failure"), "failure row marked");
        assert!(!html.contains("<client>"));
    }

    #[test]
    fn audit_shows_none_and_datetime_error() {
        let messages = Messages::new(Locale::En);
        let html = render_audit(&messages, &admin(), &AuditForm::default(), 0, true, &[]);
        assert!(html.contains("role=\"alert\""), "datetime error banner");
        assert!(html.contains("No audit"), "empty message");
    }

    #[test]
    fn pager_shows_next_only_on_full_page() {
        let messages = Messages::new(Locale::En);
        // 満たないページ・offset 0 → リンク無し。
        let none = render_pager(&messages, &AuditForm::default(), 0, 3);
        assert!(none.is_empty());
        // フルページ → 次あり。
        let full: Vec<AuditLogEntry> = (0..DEFAULT_LIMIT)
            .map(|_| entry("token.issued", "success", None))
            .collect();
        let html = render_audit(&messages, &admin(), &AuditForm::default(), 0, false, &full);
        assert!(html.contains(&format!("offset={}", DEFAULT_LIMIT)));
    }

    #[test]
    fn query_string_preserves_filters_and_encodes() {
        let form = AuditForm {
            result: Some("failure".to_string()),
            client_id: Some("a b".to_string()),
            ..AuditForm::default()
        };
        let url = audit_query_string(&form, 50);
        assert!(url.contains("result=failure"));
        assert!(url.contains("client_id=a%20b"), "space encoded");
        assert!(url.ends_with("offset=50"));
    }

    #[test]
    fn status_table_renders_last_used_and_dash_for_unused() {
        let messages = Messages::new(Locale::En);
        let views = vec![
            ClientStatusView {
                client_id: "used".to_string(),
                app_name: "<Used>".to_string(),
                status: ClientStatus::Active,
                scopes: vec!["openid".to_string(), "profile".to_string()],
                last_used_at: Some(Utc::now()),
            },
            ClientStatusView {
                client_id: "fresh".to_string(),
                app_name: "Fresh".to_string(),
                status: ClientStatus::Disabled,
                scopes: vec!["openid".to_string()],
                last_used_at: None,
            },
        ];
        let html = render_status(&messages, &admin(), &views);
        assert!(html.contains("&lt;Used&gt;"), "app name escaped");
        assert!(html.contains("DISABLED"));
        assert!(html.contains("openid profile"));
        assert!(html.contains("<td>-</td>"), "unused shows dash");
    }
}
