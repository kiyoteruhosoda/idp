//! クライアント（RP）管理のサーバレンダリング画面（web。ADR-0007 §4）。
//!
//! api の JSON 管理 API（`/admin/clients*`、`RequirePerms<IdpAdmin>`）を管理者の SSO Cookie 転送で呼び、
//! 結果を HTML に描画する。認可・データ操作・監査は api 側。web は画面と CSRF（`console_csrf_token`）のみ。
//! HTML の描画は Askama テンプレート（`templates/console/`）で行い、利用者入力は自動エスケープされる。
//! `client_secret` は作成・再発行時にその画面でのみ平文表示する。

use super::locale;
use crate::admin_dto::{ClientCreatedView, ClientListView, ClientView};
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
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

/// 各ハンドラ冒頭の共通前処理: 管理者を解決し、user_id を返すか誘導 Response を返す。
macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

// ── 一覧 ──────────────────────────────────────────────────────────────────────

/// クライアント一覧（`GET /{tenant_id}/admin/clients`）。
///
/// ページングは api（DB）側で行う（G7）。web はページ位置をクエリで引き継ぎ、応答の `total` から
/// ページャの前後リンクを組み立てるだけで、全件を受け取らない。
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let offset = query.offset.unwrap_or(0).max(0);
    let result = state
        .api
        .list_clients(
            &correlation.0,
            &tenant.0,
            &sso(&headers),
            &crate::pagination::page_query(offset),
        )
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(page) => Html(render_list(&messages, &tenant, &admin, &page, offset)).into_response(),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

/// クライアント一覧のクエリ。ページ位置のみを引き継ぐ（絞り込みは無い）。
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub offset: Option<i64>,
}

// ── 新規登録フォーム ──────────────────────────────────────────────────────────

pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    Html(render_new_form(
        &messages,
        &tenant,
        &admin,
        &csrf,
        &ClientFormValues::default_new(),
        None,
    ))
    .into_response()
}

// ── 新規登録の実行 ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct NewClientForm {
    pub app_name: String,
    /// クライアント種別。システム用では入力欄を隠すため、送られてこなくても受け取れるようにする
    /// （`client_type_for` が confidential へ寄せる。ADR-0032）。
    #[serde(default)]
    pub client_type: String,
    pub redirect_uris: String,
    /// scope はチェックボックスで受ける（受け付ける値が OIDC の 4 つに限られるため）。
    /// チェックは「入れたときだけ送られる」ので `Option` で受ける。`openid` は必須なので
    /// 入力欄を持たず、`selected_scopes` が必ず付ける。
    #[serde(default)]
    pub scope_profile: Option<String>,
    #[serde(default)]
    pub scope_email: Option<String>,
    #[serde(default)]
    pub scope_offline_access: Option<String>,
    /// クライアントの用途（`client_usage`。ADR-0032）。api はこの値を持たないので、web が
    /// `redirect_uris` の有無と `allow_client_credentials` へ翻訳して送る。
    pub usage: String,
    /// クライアント認証方式（G3）。select は confidential のときだけ描画されるため任意で受ける。
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// `private_key_jwt` の検証鍵（JWK Set の JSON。ADR-0030）。同じく confidential のときだけ描画される。
    #[serde(default)]
    pub jwks: Option<String>,
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
    };

    // Messages（FluentBundle）は Send でないため、api の await をまたいで保持しない（login.rs と同じ理由）。
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
        return bad_request_form(render_new_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &values,
            Some("admin-error-csrf"),
        ));
    }

    // システム用では client_type の select を描画しないので、値が来なくても confidential
    // として送る（public では `client_credentials` も `private_key_jwt` も成立しない）。
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
        // 新規フォームは public を選んでいる間も方式・検証鍵の欄を DOM に残す（隠すだけ）。
        // 隠れた欄も値は送信されるので、public では検証鍵を落としてから api へ渡す —— public に
        // 鍵を送ると「この方式では登録できない」で拒まれる。方式のほうは api が public では
        // 読まない（常に `none`）ため、そのまま渡してよい。
        "token_endpoint_auth_method": form.token_endpoint_auth_method,
        "jwks": jwks_for_new_client(&client_type, &form.token_endpoint_auth_method, &form.jwks),
    });
    // api のバリデーション/競合メッセージをこの画面へ出すため、決定言語を引き継ぐ（MT20）。
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_client(&correlation.0, &tenant.0, &sso(&headers), body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
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

// ── 詳細 ──────────────────────────────────────────────────────────────────────

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
    // `Messages`（fluent バンドル）は Send ではないので、**すべての await を終えてから**組み立てる。
    // await を跨いで持つとハンドラの future が Send でなくなり、axum の `Handler` を満たさない。
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

    // 管理権限（ADR-0037）。保有コードの取得に失敗したら画面ごと失敗させる —— 一覧が空なのか
    // 読めなかったのかを取り違えると、「付いているはずの権限が無い」と誤って再付与しかねない。
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
    // 付与候補は「クライアントへ付与できるコード」（絞り込みは api 側。ADR-0037）。付与フォームを
    // 出すのはシステム用クライアントだけなので、それ以外では候補を引かない（効かない付与を
    // 見せないだけでなく、管理トークン交換 1 往復を丸ごと省ける）。取得に失敗しても画面は描く
    // （保有権限の確認・剥奪は続けられる）。
    let (grantable_source, permissions_load_failed) = if is_system_client(&client) {
        match state
            .api
            .client_grantable_permissions(&correlation.0, &tenant.0, &sso)
            .await
        {
            Ok(a) => (a.codes, false),
            Err(e) => {
                tracing::warn!(error = %e, "failed to load client-grantable permission codes");
                (Vec::new(), true)
            }
        }
    } else {
        (Vec::new(), false)
    };
    // 保有済みは選択肢から除く（付与しても変化しない操作を見せない）。
    let grantable: Vec<String> = grantable_source
        .into_iter()
        .filter(|code| !permission_codes.contains(code))
        .collect();

    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
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

/// 詳細画面のクエリ。付与・剥奪の Post/Redirect/Get で戻ってきたときのエラー種別を運ぶ。
#[derive(Debug, Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    pub error: Option<String>,
}

fn permission_error_key(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "code" => Some("api-client-permission-not-grantable"),
        "notfound" => Some("admin-client-not-found-message"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

// ── 管理権限の付与・剥奪（ADR-0037。Post/Redirect/Get）──────────────────────────

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
    if !csrf_valid(headers, &form.csrf_token, state.config.csrf_secret()) {
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
        // 包括的な管理権限・未知のコードはここに来る（画面の選択肢からは出ないが、
        // 直接 POST された場合に api が拒む。ADR-0037）。
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=code")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

// ── 編集フォーム ──────────────────────────────────────────────────────────────

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
    let csrf = csrf_from(&headers, state.config.csrf_secret());
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

// ── 編集の実行 ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EditClientForm {
    pub app_name: String,
    pub redirect_uris: String,
    /// scope はチェックボックスで受ける（新規登録と同じ。`openid` は必須なので欄を持たない）。
    #[serde(default)]
    pub scope_profile: Option<String>,
    #[serde(default)]
    pub scope_email: Option<String>,
    #[serde(default)]
    pub scope_offline_access: Option<String>,
    pub client_status: String,
    /// クライアントの用途（`client_usage`。ADR-0032）。新規登録と同じ翻訳を通す。
    pub usage: String,
    /// クライアント認証方式（G3）。confidential のときだけ送られる。
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// `private_key_jwt` の検証鍵（JWK Set の JSON。ADR-0030）。鍵ローテーションはこの欄の
    /// 差し替えで行う。
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

    // 再表示に備え、現行 client を取得する（種別など読み取り専用表示のため）。ClientView は Send。
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

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
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
        "allow_client_credentials": allow_client_credentials_update(&form.usage, &client),
        "token_endpoint_auth_method": form.token_endpoint_auth_method,
        "jwks": jwks_for_method(&form.token_endpoint_auth_method, &form.jwks),
    });
    let result = state
        .api
        .for_locale(locale(&headers))
        .update_client(&correlation.0, &tenant.0, &sso(&headers), &client_id, body)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(_) => found(&format!("{}{CLIENTS_SEGMENT}/{client_id}", tenant.prefix())),
        Err(AdminApiError::NotFound) => not_found(&messages, &tenant, &admin),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => bad_request_form(
            render_edit_form(&messages, &tenant, &admin, &client, &csrf, &values, Some(m)),
        ),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── secret 再発行 ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

/// クライアントを論理削除する（ADR-0035）。実体は残り、一覧から消えて認可・トークンが通らなくなる。
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, client_id)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        return bad_request_page(&messages, &tenant, &admin, "admin-error-csrf");
    }
    let result = state
        .api
        .for_locale(locale(&headers))
        .delete_client(&correlation.0, &tenant.0, &sso(&headers), &client_id)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        // 削除後は詳細ページが 404 になるので、一覧へ戻す。
        Ok(()) => found(&format!("{}{CLIENTS_SEGMENT}", tenant.prefix())),
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

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
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
            // 再発行結果は詳細を取り直して表示する（ClientView は Send）。
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

// ── フォームの共通表現・パース ────────────────────────────────────────────────

/// 用途が `client_credentials` を含むか（ADR-0032）。
fn allows_client_credentials(usage: &str) -> bool {
    usage == client_usage::SYSTEM
}

/// 更新で api へ送る `allow_client_credentials`。`None` は「触らない」（api は現状維持と読む）。
///
/// ADR-0032 より前に登録された「両方」の姿（`client_credentials` + redirect_uri）は画面の用途では
/// 表せないため、`usage_from_registration` は利用者ログインとして表示する。その表示のまま
/// `allow_client_credentials: false` を送ると、状態を DISABLED にするだけの保存でも
/// `client_credentials` が黙って外れ、稼働中のサーバ間連携が止まる。api 側が既存の「両方」を
/// 通しているのと同じ理由で、用途を変えていない保存では許可に触れない。用途を「システム」へ
/// 明示的に切り替えた保存だけが、その姿を解消する。
fn allow_client_credentials_update(usage: &str, client: &ClientView) -> Option<bool> {
    let registered_both = client.grant_types.iter().any(|g| g == "client_credentials")
        && !client.redirect_uris.is_empty();
    if registered_both && usage != client_usage::SYSTEM {
        return None;
    }
    Some(allows_client_credentials(usage))
}

/// 用途に応じた redirect_uri。システム用は持たないので、入力欄の残骸があっても送らない
/// （用途を切り替えてから保存したとき、隠れた欄の値が生き残らないようにする）。
fn redirect_uris_for(usage: &str, raw: &str) -> Vec<String> {
    if usage == client_usage::SYSTEM {
        Vec::new()
    } else {
        parse_uris(raw)
    }
}

/// 用途に応じた client_type。システム用では select を描画しないため、値が来なくても
/// confidential とする。
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

/// 空欄（および空白のみ）は「未指定」として api へ送らない。空文字をそのまま送ると、api 側は
/// 「値を指定した」と読んで検証に落ちる。
fn blank_to_none(raw: &Option<String>) -> Option<String> {
    raw.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 検証鍵は `private_key_jwt` を選んでいるときだけ送る（ADR-0030）。
///
/// 編集フォームの入力欄には現在の鍵が入ったままなので、他の方式へ切り替える更新でそれを
/// そのまま送ると、api は「鍵を指定した」と読んで `private_key_jwt` 以外では拒否する
/// （＝画面からは方式を切り替えられなくなる）。方式に合わない値は送らない。
fn jwks_for_method(method: &Option<String>, raw: &Option<String>) -> Option<String> {
    if method.as_deref() != Some("private_key_jwt") {
        return None;
    }
    blank_to_none(raw)
}

/// 新規登録で api へ送る検証鍵。
///
/// `jwks_for_method` に client type の判定を足したもの。新規フォームは public を選んでいる間も
/// 検証鍵の欄を DOM に残す（描画をやめると、JS で confidential へ戻したときに欄が現れない）ため、
/// public のまま送信されてきた値をここで落とす。編集フォームは public に方式・鍵の欄を出さないので
/// この判定は要らない（client type は登録後に変えられない）。
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

/// 入力エラーで新規登録フォームを描き直すときの認証方式。
///
/// 新規フォームの select は常に描画されるので通常は値が届くが、届かなかったときは新規フォームの
/// 初期選択（`ClientFormValues::default_new`）・api の省略時（ADR-0036）と同じ `private_key_jwt`
/// に揃える。3 か所が別々の既定を持つと、画面の初期表示と再描画で選択が変わる。
fn auth_method_or_default(raw: &Option<String>) -> String {
    raw.as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("private_key_jwt")
        .to_string()
}

/// チェックされた scope を、api へ送る配列にする。
///
/// `openid` は登録時の必須項目（`validate_scopes`）なので、入力欄を持たず常に先頭へ付ける。
/// 画面で外せる形にすると、外した瞬間に必ず 400 になる選択肢を見せることになる。
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

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    page: &ClientListView,
    offset: i64,
) -> String {
    let links = crate::pagination::pager_links(
        &format!("{}{CLIENTS_SEGMENT}", tenant.prefix()),
        &[],
        offset,
        page.limit,
        page.total,
    );
    render(&ClientsList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
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
        heading: &messages.get("admin-clients-new"),
        action: &format!("{}{CLIENTS_SEGMENT}/new", tenant.prefix()),
        is_new: true,
        values,
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
        heading: &messages.get("admin-clients-new"),
        action: &format!("{}{CLIENTS_SEGMENT}/new", tenant.prefix()),
        is_new: true,
        values,
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
        // 管理トークンを取れるのはシステム用クライアントだけ（ADR-0037）。それ以外に付けても
        // 効かないので区画ごと出さない。ただし既に保有していれば、剥奪できるよう出す。
        shows_permissions: is_system_client(client) || !permission_codes.is_empty(),
        // 付与フォームは剥奪と違い、システム用クライアントにしか出さない。用途を変えた後などに
        // 権限が残っているだけのブラウザログイン用クライアントへ、効かない権限を足させない。
        shows_grant_form: is_system_client(client),
        error_key,
    })
}

/// システム用クライアント（`client_credentials` を使える）か。管理トークン（`resource={issuer}/
/// {tenant_id}/admin`）を取れるのはこの種別だけなので、管理権限が実際に効くのもここに限る
/// （ADR-0037）。api 側が public クライアントに `client_credentials` を持たせないため、
/// grant_types の有無だけで判定できる。
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
        messages,
        tenant,
        admin,
        &client.client_id,
        Some(secret),
        false,
    )
}

fn render_secret_page(
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
    })
}

// ── レスポンスの共通ヘルパー ──────────────────────────────────────────────────

/// api の 401/403 を web の画面挙動へ写す（ログイン誘導 / 403 画面）。それ以外は 500。
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

    /// 方式を切り替える更新で、入力欄に残っている鍵を送らない（送ると api が弾く）。
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
        // 編集フォームで public のクライアントを開くと、方式そのものが送られない。
        assert_eq!(jwks_for_method(&None, &keys), None);
        // 空欄は「未指定」。
        assert_eq!(
            jwks_for_method(
                &Some("private_key_jwt".to_string()),
                &Some("  ".to_string())
            ),
            None
        );
    }

    /// 新規登録では public を選んでいる間も検証鍵の欄が DOM に残る（隠れているだけ）。
    /// 鍵を書いてから public へ切り替えた入力を、そのまま api へ送らない。
    #[test]
    fn a_new_public_client_never_carries_a_jwks() {
        let keys = Some(r#"{"keys":[]}"#.to_string());
        let method = Some("private_key_jwt".to_string());
        assert_eq!(jwks_for_new_client("public", &method, &keys), None);
        assert_eq!(jwks_for_new_client("confidential", &method, &keys), keys);
    }

    /// ADR-0032: 画面の「用途」1 つを、api が持つ 2 つの値へ翻訳する。
    #[test]
    fn usage_maps_to_the_two_values_the_api_actually_has() {
        let uris = "https://a.example.com/cb";

        // 利用者ログイン: redirect_uri を持ち、client_credentials は無い。
        assert!(!allows_client_credentials(client_usage::USER_LOGIN));
        assert_eq!(redirect_uris_for(client_usage::USER_LOGIN, uris).len(), 1);

        // システム用: client_credentials を持ち、redirect_uri は持たない。
        assert!(allows_client_credentials(client_usage::SYSTEM));
        assert!(redirect_uris_for(client_usage::SYSTEM, uris).is_empty());
    }

    /// 用途を「システム」へ切り替えて保存したとき、隠れた入力欄の値を送らない。
    /// （送ると api 側で `authorization_code` が付き、閉じたはずの経路が残る。）
    #[test]
    fn switching_to_a_system_client_drops_the_hidden_redirect_uris() {
        assert!(
            redirect_uris_for(client_usage::SYSTEM, "https://leftover.example.com/cb").is_empty()
        );
    }

    /// ADR-0032 より前に登録された「両方」のクライアントを、用途を変えずに保存しただけで
    /// `client_credentials` が外れないこと（＝稼働中のサーバ間連携を止めない）。
    #[test]
    fn saving_a_legacy_dual_usage_client_does_not_drop_client_credentials() {
        let mut client = client_view(
            &["authorization_code", "client_credentials"],
            &["https://a.example.com/cb"],
        );
        // 画面は「利用者ログイン」として表示する。そのまま保存しても許可には触れない。
        assert_eq!(
            allow_client_credentials_update(client_usage::USER_LOGIN, &client),
            None
        );
        // 「システム」へ明示的に切り替えたときだけ、その姿を解消する。
        assert_eq!(
            allow_client_credentials_update(client_usage::SYSTEM, &client),
            Some(true)
        );

        // 用途どおりに登録されたクライアントは、これまでどおり用途から決める。
        client.grant_types = vec!["authorization_code".into()];
        assert_eq!(
            allow_client_credentials_update(client_usage::USER_LOGIN, &client),
            Some(false)
        );
        let system = client_view(&["client_credentials"], &[]);
        assert_eq!(
            allow_client_credentials_update(client_usage::SYSTEM, &system),
            Some(true)
        );
        assert_eq!(
            allow_client_credentials_update(client_usage::USER_LOGIN, &system),
            Some(false)
        );
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

    /// システム用では client_type の select を描画しないので、値が来なくても confidential にする。
    #[test]
    fn system_clients_are_always_confidential() {
        assert_eq!(client_type_for(client_usage::SYSTEM, ""), "confidential");
        assert_eq!(
            client_type_for(client_usage::SYSTEM, "public"),
            "confidential"
        );
        // 他の用途では選ばれた値をそのまま通す。
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

    /// `openid` は入力欄を持たず常に付く。外せる形にすると、外した瞬間に必ず 400 になる
    /// 選択肢を見せることになる（`validate_scopes` が必須としている）。
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
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。生タグが残らないことを確認する。
        assert!(html.contains("&#60;script&#62;Evil&#60;/script&#62;"));
        assert!(!html.contains("<script>Evil"));
    }

    // ── 管理権限の区画（ADR-0037）─────────────────────────────────────────────

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

    /// システム用クライアント（`client_credentials`）にだけ管理権限の区画を出し、
    /// 保有コードと付与フォームを描く。
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

    /// ブラウザログイン用クライアントには出さない。管理トークンを取る手段が無いので、
    /// 付けても効かない操作を見せることになる。
    #[test]
    fn a_browser_client_does_not_get_the_section() {
        let html = detail_html(&["authorization_code"], &[], &["idp.audit:read"], false);
        assert!(!html.contains("permissions/grant"), "{html}");
        assert!(!html.contains("permissions/revoke"), "{html}");
    }

    /// ただし既に保有していれば出す —— 出さないと剥奪する導線が無くなる
    /// （用途を変えた後などに残り得る）。
    #[test]
    fn a_browser_client_that_still_holds_codes_can_revoke_them() {
        let html = detail_html(&["authorization_code"], &["idp.users:read"], &[], false);
        assert!(html.contains("permissions/revoke"), "{html}");
        assert!(html.contains("idp.users:read"), "{html}");
    }

    /// 剥奪の導線を出しても、付与フォームまでは出さない。ブラウザログイン用クライアントは
    /// 管理トークンを取れないので、新たに付けた権限は永久に効かない（ADR-0037）。
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

    /// 候補の取得に失敗したときは「候補が無い」と取り違えさせない。
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

    /// 付与できるコードが残っていないときは、そう伝える（空の select を出さない）。
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
