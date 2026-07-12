//! 招待承諾画面（web。`/{tenant_id}/invitations/accept`。ADR-0009 §3・MT17）。
//!
//! 被招待者が招待メールのリンク（`?token=...`）から開く。承諾には**所属元テナントでログイン済み**の
//! SSO セッションが必要（本人性はトークンの所持 + ログイン済みセッション。§3）。未ログインなら
//! 「所属元テナントでログインしてから開き直す」案内を表示する（被招待者の所属元テナントは本画面では
//! 分からないため、ログイン画面へのリダイレクトはしない）。承諾の実体は api の
//! `POST /{tenant_id}/invitations/accept` へ SSO Cookie を転送して委ねる。

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, InvitationAccept};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AcceptQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcceptForm {
    pub token: String,
    pub csrf_token: String,
}

/// 承諾ページ（`GET /{tenant_id}/invitations/accept?token=...`）。ログイン済みなら確認フォーム、
/// 未ログインなら案内のみ表示する。
pub async fn page(
    State(_state): State<WebState>,
    Extension(_tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AcceptQuery>,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return bad_request(render_page(&messages, false, "", "", None));
    }
    match cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        Some(sso) => {
            let csrf = console_csrf_token(&sso);
            Html(render_page(&messages, true, &token, &csrf, None)).into_response()
        }
        None => Html(render_page(&messages, false, &token, "", None)).into_response(),
    }
}

/// 承諾の実行（`POST /{tenant_id}/invitations/accept`）。
/// （`Messages` は `Send` でないため、api 呼び出しの await を跨がないよう分岐ごとに生成する。）
pub async fn submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AcceptForm>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return Html(render_page(&messages, false, &form.token, "", None)).into_response();
    };
    let csrf = console_csrf_token(&sso);
    if csrf != form.csrf_token {
        let messages = Messages::new(locale(&headers));
        return bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .accept_invitation(&correlation.0, &tenant.0, &sso, &form.token)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(()) => Html(render(&InvitationAccept {
            messages: &messages,
            show_form: false,
            token: "",
            csrf: "",
            success: true,
            error_key: None,
        }))
        .into_response(),
        // SSO 期限切れ等 → ログインし直しの案内（フォームは出さない）。
        Err(AdminApiError::Unauthorized) => {
            Html(render_page(&messages, false, &form.token, "", None)).into_response()
        }
        // 別ユーザーのセッションで承諾しようとした。
        Err(AdminApiError::Forbidden) => bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("invitation-accept-error-forbidden"),
        )),
        // トークン無効・期限切れ・別テナントの招待。
        Err(AdminApiError::Validation(_)) | Err(AdminApiError::Conflict(_)) => {
            bad_request(render_page(
                &messages,
                true,
                &form.token,
                &csrf,
                Some("invitation-accept-error-invalid"),
            ))
        }
        Err(_) => bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("admin-error-internal"),
        )),
    }
}

fn render_page(
    messages: &Messages,
    show_form: bool,
    token: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&InvitationAccept {
        messages,
        show_form,
        token,
        csrf,
        success: false,
        error_key,
    })
}

fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = cookies::get(headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Locale::resolve(None, cookie_lang.as_deref(), accept)
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
