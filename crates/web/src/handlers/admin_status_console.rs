//! 状況確認画面（web。A3・ADR-0007 §4）。監査ログ一覧・エラー警告ログ一覧・クライアント状況一覧。
//!
//! api の JSON 管理 API（`GET /admin/audit-logs`・`GET /admin/logs`・`GET /admin/clients/status`）を管理者の SSO Cookie
//! 転送で呼び、結果を Askama テンプレートに描画する（`{{ }}` は自動 HTML エスケープ）。読み取り専用の
//! ため CSRF は無い。期間（from/to）の形式不正は api が 400 を返すため、web はそれを日時エラー表示へ写す。

use super::locale;
use crate::admin_dto::AuditLogView;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ApplicationLogs, AuditLogs, ClientStatus, ConsoleNotice};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::admin::ClientStatusResponse;
use idp_contracts::application_log::ApplicationLogEntryResponse;
use serde::Deserialize;

const AUDIT_SEGMENT: &str = "/admin/audit-logs";
const APPLICATION_LOG_SEGMENT: &str = "/admin/logs";
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
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(form): Query<AuditForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
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
        .search_audit_logs(&correlation.0, &tenant.0, &sso(&headers), &query)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(entries) => Html(render_audit(
            &messages, &tenant, &admin, &form, offset, false, &entries,
        ))
        .into_response(),
        // from/to の形式不正（api が 400）→ 日時エラー表示・空一覧。
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

// ── エラー・警告ログ一覧 ──────────────────────────────────────────────────────

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

/// エラー・警告ログ画面（`log` テーブル）。api 側は `idp.system.admin` を要求するため、テナント
/// 管理者が開くと 403 画面になる（テナント横断の運用情報のため。api の handler コメント参照）。
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
        // from/to の形式不正（api が 400）→ 日時エラー表示・空一覧。
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

// ── クライアント状況一覧 ──────────────────────────────────────────────────────

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

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_audit(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    form: &AuditForm,
    offset: i64,
    date_error: bool,
    entries: &[AuditLogView],
) -> String {
    let (prev_href, next_href) = pager_links(tenant, form, offset, entries.len());
    render(&AuditLogs {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
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

/// ページャの前後リンク（クエリ文字列付き URL）。該当がなければ `None`。
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
    admin: &str,
    form: &ApplicationLogForm,
    offset: i64,
    date_error: bool,
    entries: &[ApplicationLogEntryResponse],
) -> String {
    let (prev_href, next_href) = application_log_pager_links(tenant, form, offset, entries.len());
    render(&ApplicationLogs {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
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
    admin: &str,
    views: &[ClientStatusResponse],
) -> String {
    render(&ClientStatus {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        views,
    })
}

// ── 共通ヘルパー ──────────────────────────────────────────────────────────────

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

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &str) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
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
            "admin-1",
            &AuditForm::default(),
            0,
            false,
            &[entry("login.failed", "failure", Some("<bad>"))],
        );
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。生タグが残らないことを確認する。
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
            "admin-1",
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
        let html = render_status(&messages, &tenant(), "admin-1", &views);
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。
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
            target: "idp_api::presentation::token".into(),
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
            "admin-1",
            &ApplicationLogForm::default(),
            0,
            false,
            &[
                log_entry("ERROR", "api", Some("caused by: <timeout>")),
                log_entry("WARN", "web", None),
            ],
        );
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。生タグが残らないこと。
        assert!(html.contains("&#60;script&#62;"));
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&#60;timeout&#62;"));
        // レベルごとにバッジを塗り分ける（一覧でエラーを拾いやすくするため）。
        assert!(html.contains("level-error"));
        assert!(html.contains("level-warn"));
        // traceback がある行だけ詳細を折りたたんで出す。
        assert_eq!(html.matches("<details").count(), 1);
    }

    #[test]
    fn application_log_shows_datetime_error_banner() {
        let messages = Messages::new(Locale::Ja);
        let html = render_application_logs(
            &messages,
            &tenant(),
            "admin-1",
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
            target: Some("idp_api::a b".into()),
            ..ApplicationLogForm::default()
        };
        let url = application_log_query_string(&tenant(), &form, 50);
        assert!(url.contains("/admin/logs?"));
        assert!(url.contains("level=ERROR"));
        // `_` は非予約文字なのでそのまま、`:` と空白はパーセントエンコードされる。
        assert!(url.contains("target=idp_api%3A%3Aa%20b"));
        assert!(url.ends_with("offset=50"));
    }
}
