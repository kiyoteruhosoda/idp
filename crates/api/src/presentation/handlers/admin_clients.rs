//! クライアント（RP）登録・管理エンドポイント（`/admin/clients`、設計仕様 §9.3、Progress A1）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。`client_secret` は confidential
//! クライアントの登録・再発行時に**その応答でのみ**平文で返す（DB はハッシュのみ保存）。

use crate::application::client_management::{
    ClientManagementError, RegisterClientCommand, UpdateClientCommand,
};
use crate::domain::client::Client;
use crate::domain::values::{ClientStatus, ClientType, GrantType, TokenEndpointAuthMethod};
use crate::presentation::admin::{ClientsRead, ClientsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    ClientCreatedResponse, ClientListQueryParams, ClientListResponse, ClientRegisterRequest,
    ClientResponse, ClientSecretResponse, ClientUpdateRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// クライアントを登録する。`client_id` は自動採番。confidential のとき `client_secret` を平文で返す。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients",
    tag = "admin",
    request_body = ClientRegisterRequest,
    responses(
        (status = 201, description = "登録成功（confidential は client_secret を含む）", body = ClientCreatedResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn create_client(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<ClientRegisterRequest>,
) -> Result<(StatusCode, Json<ClientCreatedResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let client_type = ClientType::parse(&body.client_type).map_err(|_| {
        ApiError::BadRequest(ApiMessages::new(locale).get("api-client-type-invalid"))
    })?;
    let token_endpoint_auth_method = parse_auth_method(&body.token_endpoint_auth_method, locale)?;
    let cmd = RegisterClientCommand {
        app_name: body.app_name,
        client_type,
        redirect_uris: body.redirect_uris,
        scopes: body.scopes,
        allow_client_credentials: body.allow_client_credentials.unwrap_or(false),
        token_endpoint_auth_method,
        jwks: body.jwks,
        post_logout_redirect_uris: body.post_logout_redirect_uris.unwrap_or_default(),
        frontchannel_logout_uri: body.frontchannel_logout_uri,
        backchannel_logout_uri: body.backchannel_logout_uri,
    };

    let registered = state
        .clients_admin
        .register(tenant.context(), cmd, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;

    Ok((
        StatusCode::CREATED,
        Json(ClientCreatedResponse {
            client: client_response(&registered.client),
            client_secret: registered.client_secret,
        }),
    ))
}

/// `?grant_type=` の解釈（ADR-0038）。
///
/// **未知の値は 400 で断る。** ADR-0037 の `?grantable_to=` は綴り違いを「絞り込まない」に倒したが、
/// あちらは選択肢を狭めるだけの支援 API なので害が無かった。こちらを黙って無視すると、
/// 「連携先」の一覧にサービスアカウントが混ざったまま表示される —— **絞り込みの失敗が
/// 画面上は成功に見える**。
fn parse_grant_type_filter(
    raw: Option<&str>,
    locale: ApiLocale,
) -> Result<Option<GrantType>, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    GrantType::parse(raw).map(Some).map_err(|_| {
        ApiError::BadRequest(ApiMessages::new(locale).get("api-client-grant-type-unknown"))
    })
}

/// 登録済みクライアントを新しい順に 1 ページ分と総件数で返す（G7）。
///
/// ページングは DB 側で行う。全件を返す方式は、テナント内のクライアント数に比例して
/// 応答が膨らむため採らない（`/admin/members` と同じ方針）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients",
    tag = "admin",
    params(ClientListQueryParams),
    responses(
        (status = 200, description = "クライアント一覧（1 ページ分と総件数）", body = ClientListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_clients(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<ClientListQueryParams>,
) -> Result<Json<ClientListResponse>, ApiError> {
    let grant_type = parse_grant_type_filter(params.grant_type.as_deref(), locale)?;
    let result = state
        .clients_admin
        .list_page(tenant.context(), grant_type, params.limit, params.offset)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientListResponse {
        clients: result.page.items.iter().map(client_response).collect(),
        total: result.page.total,
        limit: result.applied.limit(),
        offset: result.applied.offset(),
    }))
}

/// 単一クライアントを取得する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 200, description = "クライアント", body = ClientResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn get_client(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // 先頭のパスセグメントは `{tenant_id}`（`ResolvedTenant` から取得済みのため破棄する）。
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientResponse>, ApiError> {
    let client = state
        .clients_admin
        .get(tenant.context(), &client_id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(client_response(&client)))
}

/// クライアントを部分更新する（app_name / redirect_uris / scopes / status）。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    request_body = ClientUpdateRequest,
    responses(
        (status = 200, description = "更新後のクライアント", body = ClientResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_client(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<ClientUpdateRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let status = body
        .client_status
        .as_deref()
        .map(ClientStatus::parse)
        .transpose()
        .map_err(|_| {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-client-status-invalid"))
        })?;
    let cmd = UpdateClientCommand {
        app_name: body.app_name,
        redirect_uris: body.redirect_uris,
        scopes: body.scopes,
        status,
        post_logout_redirect_uris: body.post_logout_redirect_uris,
        frontchannel_logout_uri: body.frontchannel_logout_uri.map(Some),
        backchannel_logout_uri: body.backchannel_logout_uri.map(Some),
        allow_client_credentials: body.allow_client_credentials,
        token_endpoint_auth_method: parse_auth_method(&body.token_endpoint_auth_method, locale)?,
        jwks: body.jwks,
    };

    let client = state
        .clients_admin
        .update(tenant.context(), &client_id, cmd, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(client_response(&client)))
}

/// confidential クライアントの `client_secret` を再発行する。新しい平文をこの応答でのみ返す。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients/{client_id}/secret",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 200, description = "新しい client_secret", body = ClientSecretResponse),
        (status = 400, description = "public クライアントには secret が無い"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn rotate_client_secret(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientSecretResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let (client, secret) = state
        .clients_admin
        .rotate_secret(tenant.context(), &client_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientSecretResponse {
        client_id: client.client_id,
        client_secret: secret,
    }))
}

/// クライアントを論理削除する（`DELETE /admin/clients/{client_id}`。ADR-0035）。
///
/// 実体は残し、状態を `DELETED` にする。発行済みトークン・同意・監査ログが `client_id` で
/// 紐づいているため、実体を消すと監査で「どのアプリだったか」を追えなくなる。使えなくなるのは
/// 即座である（認可・トークン・introspection は `is_active()` で弾く）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 204, description = "論理削除した（実体は監査のため残る）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "不存在（削除済みを含む）"),
    )
)]
pub async fn delete_client(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .clients_admin
        .delete(tenant.context(), &client_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// クライアント状況一覧（`GET /admin/clients/status`）。状態・scope・最終利用時刻。管理コンソール
/// （web）の状況画面が用いる支援 API（`idp.tenant.admin` 必須）。
pub async fn list_client_status(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<Vec<assay_contracts::admin::ClientStatusResponse>>, ApiError> {
    let views = state
        .clients_status
        .list(tenant.context())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(
        views
            .iter()
            .map(|v| assay_contracts::admin::ClientStatusResponse {
                client_id: v.client_id.clone(),
                app_name: v.app_name.clone(),
                status: v.status.as_str().to_string(),
                scopes: v.scopes.clone(),
                last_used_at: v.last_used_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
    ))
}

/// `token_endpoint_auth_method` の文字列をパースする（G3。未指定は `None` ＝ 変更・既定のまま）。
fn parse_auth_method(
    raw: &Option<String>,
    locale: ApiLocale,
) -> Result<Option<TokenEndpointAuthMethod>, ApiError> {
    raw.as_deref()
        .filter(|s| !s.is_empty())
        .map(TokenEndpointAuthMethod::parse)
        .transpose()
        .map_err(|_| {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-client-auth-method-invalid"))
        })
}

fn client_response(c: &Client) -> ClientResponse {
    ClientResponse {
        id: c.id.to_string(),
        client_id: c.client_id.clone(),
        client_type: c.client_type.as_str().to_string(),
        client_status: c.client_status.as_str().to_string(),
        app_name: c.app_name.clone(),
        redirect_uris: c.redirect_uris.clone(),
        grant_types: c.grant_types.clone(),
        response_types: c.response_types.clone(),
        scopes: c.scopes.clone(),
        token_endpoint_auth_method: c.token_endpoint_auth_method.as_str().to_string(),
        // `private_key_jwt` の検証鍵。公開鍵しか保存していないので、そのまま返して差し支えない
        // （管理者が「どの鍵が今有効か」をローテーション中に確認できる必要がある）。
        jwks: c.jwks.as_ref().map(|j| j.to_storage_json()),
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
        frontchannel_logout_uri: c.frontchannel_logout_uri.clone(),
        backchannel_logout_uri: c.backchannel_logout_uri.clone(),
        created_at: c.created_at.to_rfc3339(),
        updated_at: c.updated_at.to_rfc3339(),
    }
}

fn map_error(e: ClientManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        ClientManagementError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        ClientManagementError::NotFound => ApiError::NotFound(msgs.get("api-client-not-found")),
        ClientManagementError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        ClientManagementError::Internal(m) => ApiError::Internal(m),
    }
}
