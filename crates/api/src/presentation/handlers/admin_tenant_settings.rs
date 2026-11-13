//! Tenant setting values (`/{tenant_id}/admin/settings/tenant/keys`, ADR-0058).
//!
//! Endpoints where a tenant admin decides their own tenant's settings (password policy, lockout, session lifetime, etc.).
//! Protected by `idp.tenant-settings:read` / `:write`.
//!
//! # Fields are derived from key definitions
//!
//! ⚠ **Don't add a type per field.** Listed fields, value types and choices are derived from `RUNTIME_SETTING_DEFINITIONS`
//! (`scope = TenantOverridable`). If every key delegated required adding to the DTO and the screen,
//! a key someone forgot to add would become "delegated, yet nobody can set it".
//!
//! # Tenant permissions never open global keys
//!
//! Blocked twice (ADR-0058 §11; same design as ADR-0051).
//!
//! - **Granting side** -- `idp.tenant-settings:*` does not imply `idp.system.admin`
//!   (`domain::permission::implies`). The global settings endpoints (`/admin/system-settings*`) only pass with an exact
//!   `idp.system.admin`
//! - **Using side** -- this endpoint goes through `TenantSettingsService`, which refuses writes and clears for `scope = Global` keys,
//!   undefined keys and secret keys. It writes only to `tenant_settings` (that tenant's rows) and
//!   never touches `system_settings`

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

/// Lists the settings the tenant can override, with their source and the global value.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/tenant/keys",
    tag = "admin",
    responses(
        (status = 200, description = "テナントが上書きできる設定の一覧", body = TenantSettingsListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant-settings:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_tenant_settings(
    RequirePerms(_admin, _): RequirePerms<TenantSettingsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<TenantSettingsListResponse>, ApiError> {
    list_response(&state, &tenant).await.map(Json)
}

/// Sets this tenant's value (writes a row). Values that could lock people out need `confirmed: true`.
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
    ),
    security(("bearer_token" = []))
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
    // The registered-device-only setting (task #916) is not enabled while there are people it would lock out
    // (lockout is the biggest danger; have those people register a device first).
    if key == crate::domain::effective_tenant_settings::REGISTERED_DEVICE_REQUIRED
        && body.value.trim() == "true"
    {
        let unready = state
            .device_gate
            .members_without_trusted_device(tenant.context().tenant_id())
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if !unready.is_empty() {
            return Err(ApiError::BadRequest(ApiMessages::new(locale).get_message(
                &crate::domain::message::MessageKey::with_value(
                    "api-registered-device-required-unready",
                    unready.join("、"),
                ),
            )));
        }
    }
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

/// Deletes this tenant's override (= reverts to following the global value).
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
    ),
    security(("bearer_token" = []))
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
        // Which key was refused is obvious from the request path, so return a common message.
        DomainError::InvalidValue(_) => {
            ApiError::BadRequest(ApiMessages::new(locale).get("api-tenant-setting-invalid"))
        }
        // A value that could lock people out, without confirmation. The screen then asks for confirmation and resends with `confirmed`.
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
