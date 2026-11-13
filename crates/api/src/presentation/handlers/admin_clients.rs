//! Client (RP) registration and management endpoints (`/admin/clients`, design spec §9.3, Progress A1).
//!
//! Reading needs `idp.clients:read`; create/update/delete/secret reissue need `idp.clients:write`
//! (`RequirePerms<ClientsRead>` / `<ClientsWrite>`; `idp.tenant.admin` implies both). For confidential clients, `client_secret`
//! is returned in plaintext **only in the response** to registration/reissue (the DB stores only the hash).

use crate::application::client_management::{
    ClientManagementError, RegisterClientCommand, UpdateClientCommand,
};
use crate::domain::client::Client;
use crate::domain::values::{ClientStatus, ClientType, GrantType, TokenEndpointAuthMethod};
use crate::presentation::admin::{ClientsRead, ClientsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    ClientCreatedResponse, ClientListQueryParams, ClientListResponse, ClientRegisterRequest,
    ClientResponse, ClientSecretResponse, ClientStatusResponse, ClientUpdateRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_admin_account_guard_error, request_context};
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// Registers a client. `client_id` is auto-assigned. For confidential clients, returns `client_secret` in plaintext.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients",
    tag = "admin",
    request_body = ClientRegisterRequest,
    responses(
        (status = 201, description = "登録成功（confidential は client_secret を含む）", body = ClientCreatedResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
    ),
    security(("bearer_token" = []))
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
        note: body.note,
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

/// Interpretation of `?grant_type=` (ADR-0038).
///
/// **Unknown values are rejected with 400.** ADR-0037's `?grantable_to=` falls back to "no filtering" on misspellings,
/// but that is a support API that only narrows choices, so it was harmless. Silently ignoring it here would
/// show the "connected apps" list with service accounts mixed in -- **a failed filter would
/// look like success on screen**.
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

/// Returns one page of registered clients, newest first, plus the total count (G7).
///
/// Paging happens in the DB. Returning everything is not used, as responses would grow with the number of
/// clients in the tenant (same policy as `/admin/members`).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients",
    tag = "admin",
    params(ClientListQueryParams),
    responses(
        (status = 200, description = "クライアント一覧（1 ページ分と総件数）", body = ClientListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:read 必須）"),
    ),
    security(("bearer_token" = []))
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

/// Gets a single client.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 200, description = "クライアント", body = ClientResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:read 必須）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_client(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // The first path segment is `{tenant_id}` (discarded; already obtained from `ResolvedTenant`).
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ClientResponse>, ApiError> {
    let client = state
        .clients_admin
        .get(tenant.context(), &client_id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(client_response(&client)))
}

/// Partially updates a client (app_name / redirect_uris / scopes / status).
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
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
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
    state
        .admin_account_guard
        .ensure_may_manage_client(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            &client_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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

/// Reissues a confidential client's `client_secret`. The new plaintext is returned only in this response.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/clients/{client_id}/secret",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 200, description = "新しい client_secret", body = ClientSecretResponse),
        (status = 400, description = "public クライアントには secret が無い"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
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
    state
        .admin_account_guard
        .ensure_may_manage_client(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            &client_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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

/// Soft-deletes a client (`DELETE /admin/clients/{client_id}`, ADR-0035).
///
/// The row is kept and its status set to `DELETED`. Issued tokens, consents and audit logs are linked by `client_id`,
/// so deleting the row would make "which app was it" untraceable in audits. It becomes unusable
/// immediately (authorization, tokens and introspection reject it via `is_active()`).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/clients/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "クライアント識別子")),
    responses(
        (status = 204, description = "論理削除した（実体は監査のため残る）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "不存在（削除済みを含む）"),
    ),
    security(("bearer_token" = []))
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
        .admin_account_guard
        .ensure_may_manage_client(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            &client_id,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    state
        .clients_admin
        .delete(tenant.context(), &client_id, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Client status list (`GET /admin/clients/status`): status, scopes, last used time. A support API used by
/// the status screen of the admin console (web) (requires `idp.clients:read`).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/clients/status",
    tag = "admin",
    responses(
        (status = 200, description = "クライアントごとの状態・scope・最終利用時刻", body = [ClientStatusResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_client_status(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<Vec<ClientStatusResponse>>, ApiError> {
    let views = state
        .clients_status
        .list(tenant.context())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(
        views
            .iter()
            .map(|v| ClientStatusResponse {
                client_id: v.client_id.clone(),
                app_name: v.app_name.clone(),
                status: v.status.as_str().to_string(),
                scopes: v.scopes.clone(),
                last_used_at: v.last_used_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
    ))
}

/// Parses the `token_endpoint_auth_method` string (G3; unspecified is `None` = unchanged / default).
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
        // Verification keys for `private_key_jwt`. Only public keys are stored, so returning them as is is fine
        // (admins need to check "which key is currently active" during rotation).
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
