//! 署名鍵管理コンソール画面（`/admin/console/signing-keys`、K1）。
//!
//! 鍵一覧表示・新規生成フォーム・退役・削除操作を提供する。
//! 操作の実体は api の `/admin/signing-keys/*` に SSO Cookie 転送で委譲する。

use crate::admin_dto::SigningKeyView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, SigningKeysList};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

/// 署名鍵一覧（`GET /admin/console/signing-keys`）。
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &headers);
    let sso = sso(&headers);
    let result = state.api.list_signing_keys(&correlation.0, &sso).await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    match result {
        Ok(keys) => Html(render_list(&messages, &admin, &keys, &csrf, None)).into_response(),
        Err(e) => map_error(&messages, &admin, &headers, e),
    }
}

#[derive(Deserialize)]
pub struct GenerateKeyForm {
    pub algorithm: String,
    pub csrf_token: String,
}

/// 新規署名鍵を生成する（`POST /admin/console/signing-keys/generate`）。
pub async fn generate(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<GenerateKeyForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &headers);
    let sso = sso(&headers);

    if !csrf_valid(&headers, &form.csrf_token) {
        // Messages は await の後に作る（non-Send のため await をまたがない）。
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers);
        return bad_request(render_list(
            &messages,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .generate_signing_key(&correlation.0, &sso, &form.algorithm)
        .await;
    match result {
        Ok(_) => axum::response::Redirect::to("/admin/console/signing-keys").into_response(),
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = csrf_from(&headers);
            bad_request(render_list(&messages, &admin, &keys, &csrf, Some(&m)))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &admin, &headers, e)
        }
    }
}

#[derive(Deserialize)]
pub struct KidForm {
    pub kid: String,
    pub csrf_token: String,
}

/// 署名鍵を退役させる（`POST /admin/console/signing-keys/retire`）。
pub async fn retire(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<KidForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &headers);
    let sso = sso(&headers);

    if !csrf_valid(&headers, &form.csrf_token) {
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers);
        return bad_request(render_list(
            &messages,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .retire_signing_key(&correlation.0, &sso, &form.kid)
        .await;
    match result {
        Ok(_) => axum::response::Redirect::to("/admin/console/signing-keys").into_response(),
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &admin)
        }
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = csrf_from(&headers);
            bad_request(render_list(&messages, &admin, &keys, &csrf, Some(&m)))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &admin, &headers, e)
        }
    }
}

/// 署名鍵を削除する（`POST /admin/console/signing-keys/delete`）。RETIRED のみ可。
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<KidForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &headers);
    let sso = sso(&headers);

    if !csrf_valid(&headers, &form.csrf_token) {
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers);
        return bad_request(render_list(
            &messages,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .delete_signing_key(&correlation.0, &sso, &form.kid)
        .await;
    match result {
        Ok(_) => axum::response::Redirect::to("/admin/console/signing-keys").into_response(),
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &admin)
        }
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = csrf_from(&headers);
            bad_request(render_list(&messages, &admin, &keys, &csrf, Some(&m)))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &admin, &headers, e)
        }
    }
}

// ── ヘルパー ─────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s) == submitted)
        .unwrap_or(false)
}

fn locale(headers: &HeaderMap) -> Locale {
    use axum::http::header;
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn render_list(
    messages: &Messages,
    admin: &str,
    keys: &[SigningKeyView],
    csrf: &str,
    error: Option<&str>,
) -> String {
    render(&SigningKeysList {
        messages,
        admin: Some(admin),
        keys,
        csrf,
        error,
    })
}

fn not_found(messages: &Messages, admin: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render(&ConsoleNotice {
            messages,
            admin: Some(admin),
            heading: Some("admin-signing-keys-not-found-title"),
            message: "admin-signing-keys-not-found-message",
            is_error: true,
            back_href: Some("/admin/console/signing-keys"),
            back_label: "admin-nav-home",
        })),
    )
        .into_response()
}

fn map_error(messages: &Messages, admin: &str, headers: &HeaderMap, e: AdminApiError) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(),
        AdminApiError::Forbidden => forbidden_response(headers),
        _ => internal_error(messages, admin),
    }
}

fn internal_error(messages: &Messages, admin: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render(&ConsoleNotice {
            messages,
            admin: Some(admin),
            heading: None,
            message: "admin-error-internal",
            is_error: true,
            back_href: Some("/admin/console/signing-keys"),
            back_label: "admin-nav-home",
        })),
    )
        .into_response()
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

