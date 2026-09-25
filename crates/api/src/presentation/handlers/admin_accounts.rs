//! アカウント（人とサービスアカウント）の管理エンドポイント（ADR-0065）。
//!
//! - `GET /{tenant_id}/admin/accounts` —— 人とサービスアカウントを 1 つに並べた一覧
//! - `GET /{tenant_id}/admin/service-accounts/{client_id}` —— サービスアカウント 1 件
//! - `PUT /{tenant_id}/admin/service-accounts/{client_id}/note` —— その管理者メモ
//!
//! 人の側の 1 件・メモは `/admin/members/{user_id}`（[`super::admin_members`]）、使えるアプリは
//! 種別ごとの口が [`super::admin_applications`] にある。口は種別で分かれる（読む・書く権限が
//! `idp.members:*` / `idp.clients:*` で違う）が、応答の形と規則は種別を問わず 1 つ。

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

/// アカウントを一覧する（`GET /{tenant_id}/admin/accounts`）。
///
/// ⚠ **呼んだ主体が読める種別だけを並べる**（人は `idp.members:read`、サービスアカウントは
/// `idp.clients:read`）。新しい権限コードは無いので、権限の判定は extractor ではなく
/// Application 層が保有権限を見て行う。
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
    )
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
        // ⚠ 綴り違いを「すべて」に倒さない。絞り込みの失敗が画面上は成功に見える（ADR-0038 の
        //   `?grant_type=` と同じ）。
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

/// サービスアカウント 1 件（`GET /{tenant_id}/admin/service-accounts/{client_id}`）。
///
/// 1 件の画面のためにある。要求テナントのサービスアカウントでなければ 404（連携先・削除済み・
/// 他テナントを区別しない）。
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
    )
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

/// サービスアカウントの管理者メモを書く・消す
/// （`PUT /{tenant_id}/admin/service-accounts/{client_id}/note`。ADR-0065）。
///
/// 人のメモ（`PUT /admin/members/{user_id}/note`）と同じ規則（2000 文字まで・空なら消す・監査に
/// 中身を載せない）。
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
    )
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
