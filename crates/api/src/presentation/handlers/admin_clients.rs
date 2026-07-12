//! クライアント（RP）登録・管理エンドポイント（`/admin/clients`、設計仕様 §9.3、Progress A1）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。`client_secret` は confidential
//! クライアントの登録・再発行時に**その応答でのみ**平文で返す（DB はハッシュのみ保存）。

use crate::application::client_management::{
    ClientManagementError, RegisterClientCommand, UpdateClientCommand,
};
use crate::domain::client::Client;
use crate::domain::values::{ClientStatus, ClientType};
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    ClientCreatedResponse, ClientRegisterRequest, ClientResponse, ClientSecretResponse,
    ClientUpdateRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
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
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<ClientRegisterRequest>,
) -> Result<(StatusCode, Json<ClientCreatedResponse>), ApiError> {
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let client_type = ClientType::parse(&body.client_type)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-client-type-invalid")))?;
    let cmd = RegisterClientCommand {
        app_name: body.app_name,
        client_type,
        redirect_uris: body.redirect_uris,
        scopes: body.scopes,
        require_pkce: body.require_pkce,
        post_logout_redirect_uris: body.post_logout_redirect_uris.unwrap_or_default(),
        frontchannel_logout_uri: body.frontchannel_logout_uri,
        backchannel_logout_uri: body.backchannel_logout_uri,
    };

    let registered = state
        .clients_admin
        .register(tenant.context(), cmd, admin.user_id, &ctx)
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

/// 登録済みクライアントを新しい順に一覧する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients",
    tag = "admin",
    responses(
        (status = 200, description = "クライアント一覧", body = [ClientResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_clients(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<Vec<ClientResponse>>, ApiError> {
    let clients = state
        .clients_admin
        .list(tenant.context())
        .await.map_err(|e| map_error(e, locale))?;
    Ok(Json(clients.iter().map(client_response).collect()))
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
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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
pub async fn update_client(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<ClientUpdateRequest>,
) -> Result<Json<ClientResponse>, ApiError> {
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let status = body
        .client_status
        .as_deref()
        .map(ClientStatus::parse)
        .transpose()
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-client-status-invalid")))?;
    let cmd = UpdateClientCommand {
        app_name: body.app_name,
        redirect_uris: body.redirect_uris,
        scopes: body.scopes,
        status,
        post_logout_redirect_uris: body.post_logout_redirect_uris,
        frontchannel_logout_uri: body.frontchannel_logout_uri.map(Some),
        backchannel_logout_uri: body.backchannel_logout_uri.map(Some),
    };

    let client = state
        .clients_admin
        .update(tenant.context(), &client_id, cmd, admin.user_id, &ctx)
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
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientSecretResponse>, ApiError> {
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let (client, secret) = state
        .clients_admin
        .rotate_secret(tenant.context(), &client_id, admin.user_id, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(ClientSecretResponse {
        client_id: client.client_id,
        client_secret: secret,
    }))
}

/// クライアント状況一覧（`GET /admin/clients/status`）。状態・scope・最終利用時刻。管理コンソール
/// （web）の状況画面が用いる支援 API（`idp.tenant.admin` 必須）。
pub async fn list_client_status(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<Vec<idp_contracts::admin::ClientStatusResponse>>, ApiError> {
    let views = state
        .clients_status
        .list(tenant.context())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(
        views
            .iter()
            .map(|v| idp_contracts::admin::ClientStatusResponse {
                client_id: v.client_id.clone(),
                app_name: v.app_name.clone(),
                status: v.status.as_str().to_string(),
                scopes: v.scopes.clone(),
                last_used_at: v.last_used_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
    ))
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
        require_pkce: c.require_pkce,
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
        ClientManagementError::Validation(m) => ApiError::BadRequest(m),
        ClientManagementError::NotFound => ApiError::NotFound(msgs.get("api-client-not-found")),
        ClientManagementError::Conflict(m) => ApiError::Conflict(m),
        ClientManagementError::Internal(m) => ApiError::Internal(m),
    }
}
