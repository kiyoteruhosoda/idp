//! アプリの管理コンソール画面（`/{tenant_id}/admin/applications`。ADR-0054）。
//!
//! 一覧・登録・設定変更・認証方法（binding）の付け外し・利用者の割り当てを提供する。操作の実体は
//! api の `/admin/applications/*` に SSO Cookie 転送で委譲する（web は sqlx に触らない。ADR-0007）。
//!
//! ⚠ **この画面が締め出しの復旧経路である**（ADR-0054 の決定 4 の手順 4）。割り当てを足す操作が
//! 数秒で終わること ——一覧から 1 件開いて、利用者 ID を貼って送る——を、切り替えの前に確かめる。

use super::locale;
use crate::admin_dto::ApplicationCurrentUserView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ApplicationDetail, ApplicationsList, ConsoleNotice};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const APPLICATIONS_SEGMENT: &str = "/admin/applications";

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

/// アプリの一覧（`GET /{tenant_id}/admin/applications`）。
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    let result = state
        .api
        .list_applications(&correlation.0, &tenant.0, &sso)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(list) => Html(render(&ApplicationsList {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            applications: &list.applications,
            record_only: list.is_record_only(),
            csrf: &csrf,
            error: None,
        }))
        .into_response(),
        Err(e) => map_error(&messages, &tenant, &admin, &headers, e),
    }
}

/// アプリ 1 件の画面（`GET /{tenant_id}/admin/applications/{application_id}`）。
pub async fn detail(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    render_detail(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        None,
    )
    .await
}

#[derive(Deserialize)]
pub struct CreateApplicationForm {
    pub display_name: String,
    pub assignment_mode: String,
    /// チェックボックスは**チェックされたときだけ**送られる。未指定 = 割り当てない。
    #[serde(default)]
    pub assign_creator: Option<String>,
    pub csrf_token: String,
}

/// アプリを登録する（`POST /{tenant_id}/admin/applications/create`）。
pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<CreateApplicationForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return reload_list_with_error(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &sso,
            "admin-error-csrf",
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_application(
            &correlation.0,
            &tenant.0,
            &sso,
            form.display_name.trim(),
            form.assignment_mode.trim(),
            form.assign_creator.is_some(),
        )
        .await;
    match result {
        // 作った直後の画面へ送る。⚠ **一覧へ戻さない** ——「個別」で作った直後は、名簿と
        // 認証方法がどちらも空で、そこから続けて設定する必要がある。
        Ok(application) => redirect_detail(&tenant, &application.id),
        Err(AdminApiError::Validation(m) | AdminApiError::Conflict(m)) => {
            reload_list_with_error(&state, &correlation, &tenant, &admin, &headers, &sso, &m).await
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateApplicationForm {
    pub display_name: String,
    pub status: String,
    pub assignment_mode: String,
    pub csrf_token: String,
}

/// アプリの設定を変える（`POST /{tenant_id}/admin/applications/{id}/update`）。
pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<UpdateApplicationForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .update_application(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.display_name.trim(),
            form.status.trim(),
            form.assignment_mode.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

#[derive(Deserialize)]
pub struct BindForm {
    /// `oidc` / `saml`。
    pub protocol: String,
    /// OIDC なら `client_id`、SAML なら SP の内部 ID。
    pub target: String,
    pub csrf_token: String,
}

/// 認証方法を繋ぐ（`POST /{tenant_id}/admin/applications/{id}/bind`）。
pub async fn bind(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<BindForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let target = form.target.trim();
    let (client_id, service_provider_id) = if form.protocol.trim() == "saml" {
        (None, Some(target))
    } else {
        (Some(target), None)
    };
    let result = state
        .api
        .for_locale(locale(&headers))
        .add_application_binding(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            client_id,
            service_provider_id,
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

#[derive(Deserialize)]
pub struct BindingIdForm {
    pub binding_id: String,
    pub csrf_token: String,
}

/// 認証方法を外す（`POST /{tenant_id}/admin/applications/{id}/unbind`）。
pub async fn unbind(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<BindingIdForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .remove_application_binding(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.binding_id.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result,
    )
    .await
}

#[derive(Deserialize)]
pub struct UserIdForm {
    pub user_id: String,
    pub csrf_token: String,
}

/// 利用者を割り当てる（`POST /{tenant_id}/admin/applications/{id}/assign`）。
pub async fn assign(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<UserIdForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .assign_application_user(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.user_id.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result.map(|_| ()),
    )
    .await
}

/// 割り当てを外す（`POST /{tenant_id}/admin/applications/{id}/unassign`）。
pub async fn unassign(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, application_id)): Path<(String, String)>,
    Form(form): Form<UserIdForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return render_detail(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &application_id,
            Some("admin-error-csrf"),
        )
        .await;
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .unassign_application_user(
            &correlation.0,
            &tenant.0,
            &sso,
            &application_id,
            form.user_id.trim(),
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &application_id,
        result,
    )
    .await
}

// ── ヘルパー ─────────────────────────────────────────────────────────────────

async fn finish(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    application_id: &str,
    result: Result<(), AdminApiError>,
) -> Response {
    match result {
        // PRG。詳細を引き直して描くので、再読み込みで同じ操作が飛ばない。
        Ok(()) => redirect_detail(tenant, application_id),
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(headers));
            not_found(&messages, tenant, admin)
        }
        // 入力の誤り（400 / 409）は api の文言をそのまま出す。web 側で判定を書き写すと、
        // 規則が 2 か所に分かれて必ず片方が古くなる。
        Err(AdminApiError::Validation(m) | AdminApiError::Conflict(m)) => {
            render_detail(
                state,
                correlation,
                tenant,
                admin,
                headers,
                application_id,
                Some(&m),
            )
            .await
        }
        Err(e) => {
            let messages = Messages::new(locale(headers));
            map_error(&messages, tenant, admin, headers, e)
        }
    }
}

/// 詳細を引き直して描く（必要ならエラー付き）。
async fn render_detail(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    application_id: &str,
    error: Option<&str>,
) -> Response {
    let sso = sso(headers);
    let detail = match state
        .api
        .get_application(&correlation.0, &tenant.0, &sso, application_id)
        .await
    {
        Ok(detail) => detail,
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(headers));
            return not_found(&messages, tenant, admin);
        }
        Err(e) => {
            let messages = Messages::new(locale(headers));
            return map_error(&messages, tenant, admin, headers, e);
        }
    };
    // 「全員」のときだけ、いま入れている人を引く（写し元。ADR-0054 の決定 3）。
    // ⚠ ここで失敗しても画面は出す ——設定を直せなくなる方が困る。
    let current = if detail.application.is_individual() {
        None
    } else {
        state
            .api
            .application_current_users(&correlation.0, &tenant.0, &sso, application_id)
            .await
            .ok()
    };
    // いまの判定の段階は一覧の応答にしか載らない。⚠ 失敗しても画面は出す（既定は安全側の
    // 「記録するだけ」に倒す ——効いていないものを「効いている」と言わない）。
    let record_only = state
        .api
        .list_applications(&correlation.0, &tenant.0, &sso)
        .await
        .map(|list| list.is_record_only())
        .unwrap_or(true);

    // Messages は await の後に作る（non-Send のため await をまたがない）。
    let messages = Messages::new(locale(headers));
    let csrf = csrf_from(headers, state.config.csrf_secret());
    // 「個別」のアプリでは写し元が要らないので、空で描く（画面側が出し分ける）。
    let no_users: Vec<ApplicationCurrentUserView> = Vec::new();
    let body = render(&ApplicationDetail {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        application: &detail.application,
        assigned: &detail.assigned,
        current_users: current
            .as_ref()
            .map(|c| c.users.as_slice())
            .unwrap_or(&no_users),
        current_users_truncated: current.as_ref().map(|c| c.truncated).unwrap_or(false),
        current_users_total: current.as_ref().map(|c| c.total).unwrap_or(0),
        record_only,
        csrf: &csrf,
        error,
    });
    match error {
        Some(_) => (StatusCode::BAD_REQUEST, Html(body)).into_response(),
        None => Html(body).into_response(),
    }
}

/// 一覧を引き直してエラー付きで描き直す（PRG に倒さないのは、理由を出すため）。
async fn reload_list_with_error(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    sso: &str,
    error: &str,
) -> Response {
    let list = state
        .api
        .list_applications(&correlation.0, &tenant.0, sso)
        .await;
    let (applications, record_only) = match list {
        Ok(list) => {
            let record_only = list.is_record_only();
            (list.applications, record_only)
        }
        Err(_) => (Vec::new(), true),
    };
    let messages = Messages::new(locale(headers));
    let csrf = csrf_from(headers, state.config.csrf_secret());
    (
        StatusCode::BAD_REQUEST,
        Html(render(&ApplicationsList {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            applications: &applications,
            record_only,
            csrf: &csrf,
            error: Some(error),
        })),
    )
        .into_response()
}

fn redirect_detail(tenant: &WebTenant, application_id: &str) -> Response {
    axum::response::Redirect::to(&format!(
        "{}{APPLICATIONS_SEGMENT}/{application_id}",
        tenant.prefix()
    ))
    .into_response()
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

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: None,
            message: "api-application-not-found",
            is_error: true,
            back_href: Some(&format!("{}{APPLICATIONS_SEGMENT}", tenant.prefix())),
            back_label: "admin-applications-back",
        })),
    )
        .into_response()
}

fn map_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        _ => internal_error(messages, tenant, admin),
    }
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: None,
            message: "admin-error-internal",
            is_error: true,
            back_href: Some(&format!("{}{APPLICATIONS_SEGMENT}", tenant.prefix())),
            back_label: "admin-applications-back",
        })),
    )
        .into_response()
}
