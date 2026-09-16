//! テナントの設定値（`/{tenant_id}/admin/settings/tenant/keys`。ADR-0058）。
//!
//! テナント管理者が、自分のテナントの設定（パスワードポリシー・ロックアウト・セッションの寿命等）を
//! 決める口。保護は `idp.tenant-settings:read` / `:write`。
//!
//! # 項目はキー定義から導く
//!
//! ⚠ **項目ごとに型を書き足さない。** 並べる項目・値の型・選択肢は `RUNTIME_SETTING_DEFINITIONS`
//! （`scope = TenantOverridable`）から導く。キーを 1 つ降ろすたびに DTO と画面を書き足す形にすると、
//! 書き足し忘れたキーは「降ろしたのに誰も決められない」になる。
//!
//! # テナントの権限で全体のキーを開かない
//!
//! 二重に止める（ADR-0058 §11。ADR-0051 と同じ作り）。
//!
//! - **付与の側** —— `idp.tenant-settings:*` は `idp.system.admin` を含意しない
//!   （`domain::permission::implies`）。全体の設定の口（`/admin/system-settings*`）は完全一致の
//!   `idp.system.admin` でしか通らない
//! - **使う側** —— この口は `TenantSettingsService` を通り、`scope = Global` のキー・定義に無いキー・
//!   秘匿値のキーは書き込みも解除も断る。書く先も `tenant_settings`（そのテナントの行）だけで、
//!   `system_settings` には触れない

use crate::application::tenant_settings::{SettingOrigin, TenantSettingView};
use crate::domain::error::DomainError;
use crate::domain::system_setting::SettingKind;
use crate::presentation::admin::{RequirePerms, TenantSettingsRead, TenantSettingsWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    SettingChoiceResponse, TenantSettingResponse, TenantSettingsListResponse,
    UpdateTenantSettingRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::Json;

/// テナントが上書きできる設定を、出どころと全体の値つきで一覧する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/tenant/keys",
    tag = "admin",
    responses(
        (status = 200, description = "テナントが上書きできる設定の一覧", body = TenantSettingsListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:read 必須）"),
    )
)]
pub async fn list_tenant_settings(
    RequirePerms(_admin, _): RequirePerms<TenantSettingsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<TenantSettingsListResponse>, ApiError> {
    list_response(&state, &tenant).await.map(Json)
}

/// このテナントの値を決める（行を書く）。締め出し得る値は `confirmed: true` が要る。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/settings/tenant/keys/{key}",
    tag = "admin",
    params(("key" = String, Path, description = "設定キー（例 PASSWORD_MIN_LENGTH）")),
    request_body = UpdateTenantSettingRequest,
    responses(
        (status = 200, description = "更新後の一覧", body = TenantSettingsListResponse),
        (status = 400, description = "テナントが決められないキー・値が型に合わない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:write 必須）"),
        (status = 409, description = "利用者を締め出し得る値で、確認（confirmed）が無い"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn set_tenant_setting(
    RequirePerms(admin, _): RequirePerms<TenantSettingsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, key)): Path<(String, String)>,
    Json(body): Json<UpdateTenantSettingRequest>,
) -> Result<Json<TenantSettingsListResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .tenant_settings
        .set(
            tenant.context(),
            &key,
            &body.value,
            body.confirmed,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_error(e, locale))?;
    list_response(&state, &tenant).await.map(Json)
}

/// このテナントの上書きを消す（＝全体に従う状態へ戻す）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/settings/tenant/keys/{key}",
    tag = "admin",
    params(("key" = String, Path, description = "設定キー（例 PASSWORD_MIN_LENGTH）")),
    responses(
        (status = 200, description = "更新後の一覧", body = TenantSettingsListResponse),
        (status = 400, description = "テナントが決められないキー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:write 必須）"),
    )
)]
pub async fn clear_tenant_setting(
    RequirePerms(admin, _): RequirePerms<TenantSettingsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, key)): Path<(String, String)>,
) -> Result<Json<TenantSettingsListResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .tenant_settings
        .clear(tenant.context(), &key, &admin.actor, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    list_response(&state, &tenant).await.map(Json)
}

async fn list_response(
    state: &AppState,
    tenant: &ResolvedTenant,
) -> Result<TenantSettingsListResponse, ApiError> {
    let views = state
        .tenant_settings
        .list(tenant.context().tenant_id())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(TenantSettingsListResponse {
        settings: views.iter().map(to_response).collect(),
    })
}

fn map_error(e: DomainError, locale: ApiLocale) -> ApiError {
    match e {
        // どのキーが断られたかは要求の経路から自明なので、共通の案内を返す。
        DomainError::InvalidValue(_) => {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-tenant-setting-invalid"))
        }
        // 締め出し得る値で確認が無い。画面はこれを受けて確認を挟み、`confirmed` を付けて送り直す。
        DomainError::Conflict(_) => ApiError::Conflict(
            ApiMessages::new(locale).get("api-tenant-setting-needs-confirmation"),
        ),
        other => ApiError::Internal(other.to_string()),
    }
}

fn to_response(view: &TenantSettingView) -> TenantSettingResponse {
    let def = view.definition;
    let (kind, choices) = match def.kind {
        SettingKind::UnsignedInteger => ("UNSIGNED_INTEGER", Vec::new()),
        SettingKind::Boolean => ("BOOLEAN", Vec::new()),
        SettingKind::Text => ("TEXT", Vec::new()),
        SettingKind::PublicBaseUrl => ("PUBLIC_BASE_URL", Vec::new()),
        SettingKind::Choice(choices) => (
            "CHOICE",
            choices
                .iter()
                .map(|choice| SettingChoiceResponse {
                    value: choice.value.to_string(),
                    locks_out: choice.locks_out,
                })
                .collect(),
        ),
    };
    TenantSettingResponse {
        key: def.key.to_string(),
        description: def.description.to_string(),
        kind: kind.to_string(),
        choices,
        value: view.value.clone(),
        origin: match view.origin {
            SettingOrigin::TenantOverride => "TENANT_OVERRIDE",
            SettingOrigin::Inherited => "INHERITED",
        }
        .to_string(),
        whole_idp_value: view.whole_idp_value.clone(),
    }
}
