//! 利用者権限の付与・剥奪・参照エンドポイント（`/admin/users/{user_id}/permissions`、
//! A2・ADR-0006・設計仕様 §7）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。付与・剥奪は `audit_log` に記録する
//! （`user_permission.granted` / `.revoked`）。判定は Application 層（`PermissionManagementService`）
//! が行い、本ハンドラは HTTP への写像のみを担う。

use crate::domain::permission;
use crate::presentation::admin::{PermissionsRead, PermissionsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{GrantPermissionRequest, UserPermissionsResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_permission_management_error, request_context};
use crate::presentation::i18n::ApiLocale;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use uuid::Uuid;

/// 付与可能な権限コード（`permissions` マスタ）を一覧する（`GET /admin/permissions`）。
/// 管理コンソール（web）の付与フォームの選択肢に使う支援 API。
///
/// **要求テナントで付与し得ないコードは常に落とす。** `idp.system.admin` は root scope でしか
/// 存在できない（ADR-0009 §4）ため、非 root テナントで返すと「選べるのに必ず 403 になる選択肢」に
/// なる。ADR-0032 の「選べないものを見せない」をここでも適用する。
///
/// `?grantable_to=client` を付けると、さらに**クライアントへ付与できるコードだけ**へ絞る（ADR-0037）。
/// 絞り込みを api で行うのは、判定（`domain::permission` の各関数）の出所を core に一本化するため
/// である。web は core に依存しない（crate 境界で強制。ADR-0007）ので、web 側で同じ判定を書くと
/// **マスタが増えたときに片方だけ古くなる**。
pub async fn list_available_permissions(
    RequirePerms(_admin, _): RequirePerms<PermissionsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(query): Query<AvailablePermissionsQuery>,
) -> Result<Json<idp_contracts::admin::AvailablePermissionsResponse>, ApiError> {
    let mut codes = state
        .permissions_admin
        .available_codes()
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    let tenant_is_root = tenant.tenant().is_root();
    codes.retain(|code| permission::is_grantable_in_tenant(code, tenant_is_root));
    if query.grantable_to.as_deref() == Some(GRANTABLE_TO_CLIENT) {
        codes.retain(|code| permission::is_grantable_to_client(code));
    }
    Ok(Json(idp_contracts::admin::AvailablePermissionsResponse {
        codes,
    }))
}

/// `grantable_to` の唯一の許可値。未知の値は絞り込まない（＝全件）——ここで 400 にしないのは、
/// 支援 API であり、綴りを誤っても「候補が多すぎる」に留まって害が無いためである。
const GRANTABLE_TO_CLIENT: &str = "client";

/// `GET /admin/permissions` のクエリ。
#[derive(Debug, serde::Deserialize)]
pub struct AvailablePermissionsQuery {
    /// `client` を指定すると、クライアントへ付与できるコードだけを返す。
    #[serde(default)]
    pub grantable_to: Option<String>,
}

/// 対象利用者が保有する権限コードを一覧する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "保有する権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
pub async fn list_permissions(
    RequirePerms(_admin, _): RequirePerms<PermissionsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // 先頭のパスセグメントは `{tenant_id}`（`ResolvedTenant` から取得済みのため破棄する）。
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let codes = state
        .permissions_admin
        .list(tenant.context(), target)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// 対象利用者へ権限コードを付与する（冪等）。付与後の保有コード一覧を返す。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = GrantPermissionRequest,
    responses(
        (status = 200, description = "付与後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "バリデーションエラー（未知の権限コード等）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn grant_permission(
    RequirePerms(admin, _): RequirePerms<PermissionsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<GrantPermissionRequest>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let codes = state
        .permissions_admin
        .grant(
            tenant.context(),
            target,
            &body.permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// 対象利用者から権限コードを剥奪する（未保有でもエラーにしない）。剥奪後の保有コード一覧を返す。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}/permissions/{permission_code}",
    tag = "admin",
    params(
        ("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）"),
        ("permission_code" = String, Path, description = "剥奪する権限コード"),
    ),
    responses(
        (status = 200, description = "剥奪後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない・権限コードが空"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
pub async fn revoke_permission(
    RequirePerms(admin, _): RequirePerms<PermissionsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id, permission_code)): Path<(String, String, String)>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let codes = state
        .permissions_admin
        .revoke(
            tenant.context(),
            target,
            &permission_code,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

fn parse_user_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    use crate::presentation::i18n::ApiMessages;
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))
}
