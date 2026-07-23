//! テナントメンバー（HOME/GUEST）管理画面（web。ADR-0009 §3・§6・MT13）。
//!
//! メンバー管理の起点となるハブ画面。api の JSON 管理 API を管理者の SSO Cookie 転送で呼ぶ。
//! ゲストはメンバーシップの解除のみでき（HOME は api 側が 403 を返す）、所属元（HOME）の利用者には
//! 無効化・有効化・パスワード再発行・削除を提供する（対象が所属元でない場合は api 側が 404 を返す）。

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::dto::{MemberActionForm, MemberStatusForm};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, MembersList, PasswordResetResult};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const MEMBERS_SEGMENT: &str = "/admin/members";

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// メンバー一覧の絞り込み語（メールアドレス・氏名の部分一致。大文字小文字を無視）。
    #[serde(default)]
    pub q: Option<String>,
}

/// メンバー一覧（`GET /{tenant_id}/admin/members`）。
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
    let result = state
        .api
        .list_members(&correlation.0, &tenant.0, &sso(&headers))
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    let error_key = query.error.as_deref().and_then(error_key_for);
    let term = query.q.unwrap_or_default();
    match result {
        Ok(all) => {
            let members = filter_members(&all, &term);
            Html(render(&MembersList {
                messages: &messages,
                tenant: &tenant.prefix(),
                admin: Some(&admin),
                members: &members,
                query: term.trim(),
                csrf: &csrf,
                error_key,
            }))
            .into_response()
        }
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(_) => internal_error(&messages, &tenant, &admin),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub csrf_token: String,
}

/// ゲストメンバーシップの解除（`POST /{tenant_id}/admin/members/{user_id}/revoke`）。
pub async fn revoke(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<RevokeForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .revoke_member(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// 利用者の無効化・有効化（`POST /{tenant_id}/admin/members/{user_id}/status`）。
/// 所属元（HOME）が当該テナントの利用者のみ。自分自身は変更できない（api 側が 403 を返す）。
pub async fn set_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberStatusForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .update_user_status(
            &correlation.0,
            &tenant.0,
            &sso(&headers),
            &user_id,
            form.status.trim(),
        )
        .await;
    match result {
        Ok(_) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=user-notfound")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=internal")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// 利用者のパスワード再発行（`POST /{tenant_id}/admin/members/{user_id}/reset-password`）。
/// 成功時は生成パスワードを一度だけ表示する。
pub async fn reset_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let reset = match state
        .api
        .reset_user_password(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => return found(&format!("{base}?error=user-notfound")),
        Err(_) => return found(&format!("{base}?error=internal")),
    };
    let messages = Messages::new(locale(&headers));
    let subject = if form.email.trim().is_empty() {
        user_id.clone()
    } else {
        form.email.trim().to_string()
    };
    Html(render(&PasswordResetResult {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(&admin),
        subject: &subject,
        generated_password: &reset.generated_password,
        back_href: &base,
        back_label_key: "admin-members-back",
    }))
    .into_response()
}

/// 利用者の削除（`POST /{tenant_id}/admin/members/{user_id}/delete`）。
/// 所属元（HOME）が当該テナントの利用者のみ。自分自身は削除できない。
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<MemberActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{MEMBERS_SEGMENT}", tenant.prefix());
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let result = state
        .api
        .delete_user(&correlation.0, &tenant.0, &sso(&headers), &user_id)
        .await;
    match result {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=self")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=user-notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// メンバー一覧を絞り込み語で部分一致フィルタする（メールアドレス・氏名。大文字小文字を無視）。
/// 空語のときは全件返す。一覧は api が全件返すため、絞り込みは web 側で行う（api 変更は不要）。
fn filter_members(
    members: &[crate::admin_dto::MemberView],
    term: &str,
) -> Vec<crate::admin_dto::MemberView> {
    let needle = term.trim().to_lowercase();
    if needle.is_empty() {
        return members.to_vec();
    }
    members
        .iter()
        .filter(|m| {
            let email = m.email.as_deref().unwrap_or_default().to_lowercase();
            let name = m.name.as_deref().unwrap_or_default().to_lowercase();
            email.contains(&needle) || name.contains(&needle)
        })
        .cloned()
        .collect()
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-members-error-home"),
        "notfound" => Some("admin-members-error-notfound"),
        "self" => Some("admin-members-error-self"),
        "user-notfound" => Some("admin-members-error-user-notfound"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key) == submitted)
        .unwrap_or(false)
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
