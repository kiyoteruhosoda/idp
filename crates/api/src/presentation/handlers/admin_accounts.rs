//! Management endpoints for accounts (people and service accounts) (ADR-0065).
//!
//! - `GET /{tenant_id}/admin/accounts` -- a single list of people and service accounts
//! - `GET /{tenant_id}/admin/service-accounts/{client_id}` -- one service account
//! - `PUT /{tenant_id}/admin/service-accounts/{client_id}/note` -- its admin note
//!
//! A single person and their note are at `/admin/members/{user_id}` ([`super::admin_members`]); usable apps have
//! per-kind endpoints in [`super::admin_applications`]. Endpoints are split by kind (read/write permissions
//! differ: `idp.members:*` / `idp.clients:*`), but the response shape and rules are one regardless of kind.

use crate::application::account_directory::{AccountDirectoryError, AccountSearchParams};
use crate::application::account_note::AccountNoteError;
use crate::domain::account::{Account, AccountKind, AccountLocator, ServiceAccount};
use crate::presentation::admin::{ClientsRead, ClientsWrite, ManagementPrincipal, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AccountListQueryParams, AccountListResponse, AccountResponse, IdentityApplicationResponse,
    ServiceAccountResponse, UpdateAccountNoteRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::admin_members::{member_response, note_response};
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// Lists accounts (`GET /{tenant_id}/admin/accounts`).
///
/// ⚠ **Only lists the kinds the calling principal can read** (people: `idp.members:read`, service accounts:
/// `idp.clients:read`). There is no new permission code, so the permission decision is made not by an extractor but by
/// the application layer looking at held permissions.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/accounts",
    tag = "admin",
    params(AccountListQueryParams),
    responses(
        (status = 200, description = "アカウント一覧（1 ページ分と総件数）", body = AccountListResponse),
        (status = 400, description = "kind が未知の値"),
        (status = 401, description = "未認証"),
        (status = 403, description = "求めた種別（または、どの種別も）を読む権限が無い"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_accounts(
    ManagementPrincipal(principal): ManagementPrincipal,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<AccountListQueryParams>,
) -> Result<Json<AccountListResponse>, ApiError> {
    let kind = match params
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        // ⚠ Don't fall back to "all" on a misspelling. A failed filter would look like success on screen (same as
        //   ADR-0038's `?grant_type=`).
        Some(raw) => Some(AccountKind::parse(raw).ok_or_else(|| {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-account-kind-unknown"))
        })?),
        None => None,
    };
    let result = state
        .account_directory
        .search(
            tenant.context(),
            &principal.permission_codes,
            AccountSearchParams {
                kind,
                search: params.q,
                limit: params.limit,
                offset: params.offset,
            },
        )
        .await
        .map_err(|e| match e {
            AccountDirectoryError::Forbidden => {
                ApiError::Forbidden(ApiMessages::new(locale).get("api-permission-insufficient"))
            }
            AccountDirectoryError::Internal(m) => ApiError::Internal(m),
        })?;
    let now = state.clock.now();
    Ok(Json(AccountListResponse {
        accounts: result
            .page
            .accounts
            .into_iter()
            .map(|account| match account {
                Account::User(m) => AccountResponse {
                    kind: AccountKind::User.as_str().to_string(),
                    user: Some(member_response(m, now)),
                    service_account: None,
                },
                Account::ServiceAccount(sa) => AccountResponse {
                    kind: AccountKind::ServiceAccount.as_str().to_string(),
                    user: None,
                    service_account: Some(service_account_response(sa)),
                },
            })
            .collect(),
        kinds: result
            .kinds
            .iter()
            .map(|k| k.as_str().to_string())
            .collect(),
        readable_kinds: result
            .readable
            .iter()
            .map(|k| k.as_str().to_string())
            .collect(),
        total: result.page.total,
        limit: result.limit,
        offset: result.offset,
    }))
}

/// One service account (`GET /{tenant_id}/admin/service-accounts/{client_id}`).
///
/// Exists for the single-item screen. 404 unless it is a service account of the requesting tenant (federated,
/// deleted and other-tenant are not distinguished).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/service-accounts/{client_id}",
    tag = "admin",
    params(("client_id" = String, Path, description = "サービスアカウントの client_id")),
    responses(
        (status = 200, description = "サービスアカウント 1 件", body = ServiceAccountResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:read 必須）"),
        (status = 404, description = "このテナントのサービスアカウントではない"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_service_account(
    RequirePerms(_admin, _): RequirePerms<ClientsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, client_id)): Path<(String, String)>,
) -> Result<Json<ServiceAccountResponse>, ApiError> {
    let found = state
        .account_directory
        .find_service_account(tenant.context(), &client_id)
        .await
        .map_err(|e| match e {
            AccountDirectoryError::Forbidden => {
                ApiError::Forbidden(ApiMessages::new(locale).get("api-permission-insufficient"))
            }
            AccountDirectoryError::Internal(m) => ApiError::Internal(m),
        })?;
    match found {
        Some(sa) => Ok(Json(service_account_response(sa))),
        None => Err(ApiError::NotFound(
            ApiMessages::new(locale).get("api-service-account-not-found"),
        )),
    }
}

/// Writes / clears a service account's admin note
/// (`PUT /{tenant_id}/admin/service-accounts/{client_id}/note`, ADR-0065).
///
/// Same rules as a person's note (`PUT /admin/members/{user_id}/note`): up to 2000 characters, empty clears it, the audit log
/// does not carry its content.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/service-accounts/{client_id}/note",
    tag = "admin",
    params(("client_id" = String, Path, description = "サービスアカウントの client_id")),
    request_body = UpdateAccountNoteRequest,
    responses(
        (status = 204, description = "保存した（空なら消した）"),
        (status = 400, description = "メモが長すぎる"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.clients:write 必須）"),
        (status = 404, description = "このテナントのサービスアカウントではない"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_service_account_note(
    RequirePerms(admin, _): RequirePerms<ClientsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, client_id)): Path<(String, String)>,
    Json(body): Json<UpdateAccountNoteRequest>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .account_notes
        .write(
            tenant.context(),
            AccountLocator::ServiceAccount {
                client_id: &client_id,
            },
            &body.note,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| {
            let msgs = ApiMessages::new(locale);
            match e {
                AccountNoteError::NotFound => {
                    ApiError::NotFound(msgs.get("api-service-account-not-found"))
                }
                AccountNoteError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
                AccountNoteError::Internal(m) => ApiError::Internal(m),
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

fn service_account_response(sa: ServiceAccount) -> ServiceAccountResponse {
    ServiceAccountResponse {
        client_id: sa.client_id,
        app_name: sa.app_name,
        status: sa.status.as_str().to_string(),
        created_at: sa.created_at.to_rfc3339(),
        identity_of: sa.identity_of.map(|a| IdentityApplicationResponse {
            application_id: a.application_id.to_string(),
            display_name: a.display_name,
        }),
        note: note_response(sa.note),
    }
}
