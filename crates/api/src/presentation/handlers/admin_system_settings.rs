//! System settings endpoints (`/{tenant_id}/admin/system-settings`, MT14).
//!
//! Listing/updating settings and runtime settings need `idp.system.admin` (`RequirePerms<IdpSystemAdmin>`).
//! `idp.system.admin` can only exist in root scope, so only system admins of the root tenant can read and update
//! system settings (ADR-0009 §4). The SMTP-only endpoint (`/system-settings/smtp`) uses
//! `idp.smtp:read` / `idp.smtp:write` (`RequirePerms<SmtpRead>` / `<SmtpWrite>`, ADR-0051),
//! not implied by `idp.tenant.admin` (implied by `idp.system.admin`). The SMTP password is stored encrypted and never returned as plaintext
//! (only whether it is set).

use crate::application::tenant_settings::TenantSettingAdoption;
use crate::config::{ResolvedSetting, SettingSafetyStatus, SettingSource};
use crate::domain::error::DomainError;
use crate::domain::system_setting::{
    is_shared_with_web, is_tenant_overridable, DefaultRisk, SettingOwner, SmsSettingsView,
    SmtpSettingsView, UpdateSmsCommand, UpdateSmtpCommand,
};
use crate::presentation::admin::{IdpSystemAdmin, RequirePerms, SmtpRead, SmtpWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    RuntimeSettingResponse, SmtpSettingsResponse, SystemSettingsResponse, TenantOverrideResponse,
    UpdateRuntimeSettingRequest, UpdateSmtpSettingsRequest, UpdateSystemSettingsRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_root_tenant, ResolvedTenant};
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use std::collections::HashMap;

/// Gets the system settings (SMTP, etc.).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/system-settings",
    tag = "admin",
    responses(
        (status = 200, description = "システム設定（SMTP パスワードは設定有無のみ）", body = SystemSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_system_settings(
    RequirePerms(_admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
) -> Result<Json<SystemSettingsResponse>, ApiError> {
    let smtp = state
        .system_settings
        .get_smtp()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let sms = state
        .system_settings
        .get_sms()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let overrides = state
        .system_settings
        .runtime_overrides()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let adoption = tenant_adoption(&state).await?;
    Ok(Json(to_response(
        smtp,
        sms,
        state.config.resolved_settings(),
        &overrides,
        &adoption,
    )))
}

/// Updates the DB override values of runtime settings (only `DB_MANAGED`, non-secret keys).
/// When `value` is `None` or empty the override is cleared. Takes effect after a restart.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/system-settings/runtime",
    tag = "admin",
    request_body = UpdateRuntimeSettingRequest,
    responses(
        (status = 200, description = "更新後のシステム設定", body = SystemSettingsResponse),
        (status = 400, description = "キーが DB 管理対象でない・値が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_runtime_setting(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<UpdateRuntimeSettingRequest>,
) -> Result<Json<SystemSettingsResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .system_settings
        .update_runtime_setting(tenant.context(), &body.key, body.value, &admin.actor, &ctx)
        .await
        .map_err(|e| match e {
            // Malformed runtime setting value (unknown key, unparseable). This is an admin API for operators,
            // and which key is invalid is obvious from the request body, so return the common "bad request".
            DomainError::InvalidValue(_) => {
                ApiError::BadRequest(ApiMessages::new(locale).get("api-runtime-setting-invalid"))
            }
            // Well-formed, but the next startup would fail with this value (https ISSUER x dev default secret,
            // or a mismatch with COOKIE_DOMAIN). Mixed with 400 the screen could only say "malformed", and
            // operators would keep doubting a correct URL. Distinguish it as a conflict with deployment state via 409 (ADR-0017).
            //
            // The screen gets a translated generic message, so **which condition failed** goes to the ops log
            // (needed to find the cause; ops logs are kept in the ops language).
            DomainError::Conflict(reason) => {
                tracing::warn!(
                    key = %body.key,
                    reason = %reason,
                    "rejected a runtime setting override that would prevent the next startup"
                );
                ApiError::Conflict(ApiMessages::new(locale).get("api-runtime-setting-not-bootable"))
            }
            other => ApiError::Internal(other.to_string()),
        })?;
    // Tenant-overridable keys are read on every lookup without waiting for a restart (ADR-0058 §9). Unless the global rows'
    // cache is dropped here, decisions keep using stale values for the lifetime of the tenant-resolution cache.
    state.tenant_settings.invalidate_global();
    let smtp = state
        .system_settings
        .get_smtp()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let sms = state
        .system_settings
        .get_sms()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let overrides = state
        .system_settings
        .runtime_overrides()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let adoption = tenant_adoption(&state).await?;
    Ok(Json(to_response(
        smtp,
        sms,
        state.config.resolved_settings(),
        &overrides,
        &adoption,
    )))
}

/// Updates the system settings (SMTP, etc.). The password is overwritten only when `smtp_password` is given.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/system-settings",
    tag = "admin",
    request_body = UpdateSystemSettingsRequest,
    responses(
        (status = 200, description = "更新後のシステム設定", body = SystemSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update_system_settings(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Json(body): Json<UpdateSystemSettingsRequest>,
) -> Result<Json<SystemSettingsResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let updated = state
        .system_settings
        .update_smtp(
            tenant.context(),
            UpdateSmtpCommand {
                host: body.smtp_host,
                port: body.smtp_port,
                username: body.smtp_username,
                password: body.smtp_password,
                from_address: body.smtp_from_address,
                use_tls: body.smtp_use_tls,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    // SMS gateway (AP13). Handled in the same single save as SMTP (the settings screen is one page,
    // and saving separately would create a state where only one side was updated).
    let sms = state
        .system_settings
        .update_sms(
            tenant.context(),
            UpdateSmsCommand {
                gateway_url: body.sms_gateway_url,
                auth_header: body.sms_auth_header,
                auth_token: body.sms_auth_token,
                sender_id: body.sms_sender_id,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let overrides = state
        .system_settings
        .runtime_overrides()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let adoption = tenant_adoption(&state).await?;
    Ok(Json(to_response(
        updated,
        sms,
        state.config.resolved_settings(),
        &overrides,
        &adoption,
    )))
}

/// Reads only the SMTP settings (`GET /{tenant_id}/admin/system-settings/smtp`, ADR-0051).
///
/// Protected by `idp.smtp:read`. **The password plaintext is never returned** (only whether it is set).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/system-settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "SMTP 設定（パスワードは設定有無のみ）", body = SmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:read 必須。root テナントのみ）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_smtp_settings(
    RequirePerms(_admin, _): RequirePerms<SmtpRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<SmtpSettingsResponse>, ApiError> {
    require_root_tenant(&tenant, locale)?;
    let smtp = state
        .system_settings
        .get_smtp()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_smtp_response(smtp)))
}

/// Updates only the SMTP settings (`PUT /{tenant_id}/admin/system-settings/smtp`, ADR-0051).
///
/// Protected by `idp.smtp:write`. Does not touch SMS or runtime settings -- the scope "only the mail route is opened to machines"
/// is expressed **both by type and by route**. Omitting `smtp_password` keeps the current one.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/system-settings/smtp",
    tag = "admin",
    request_body = UpdateSmtpSettingsRequest,
    responses(
        (status = 200, description = "更新後の SMTP 設定", body = SmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須。root テナントのみ）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update_smtp_settings(
    RequirePerms(admin, _): RequirePerms<SmtpWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<UpdateSmtpSettingsRequest>,
) -> Result<Json<SmtpSettingsResponse>, ApiError> {
    require_root_tenant(&tenant, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let updated = state
        .system_settings
        .update_smtp(
            tenant.context(),
            UpdateSmtpCommand {
                host: body.smtp_host,
                port: body.smtp_port,
                username: body.smtp_username,
                password: body.smtp_password,
                from_address: body.smtp_from_address,
                use_tls: body.smtp_use_tls,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_smtp_response(updated)))
}

fn to_smtp_response(smtp: SmtpSettingsView) -> SmtpSettingsResponse {
    SmtpSettingsResponse {
        smtp_host: smtp.host,
        smtp_port: smtp.port,
        smtp_username: smtp.username,
        smtp_password_set: smtp.password_set,
        smtp_from_address: smtp.from_address,
        smtp_use_tls: smtp.use_tls,
    }
}

/// For each tenant-overridable key, the number of tenants following it and the tenants deviating from it (ADR-0058 §6).
///
/// ⚠ Reads across tenants. Call only from `idp.system.admin` endpoints (this module's global settings).
async fn tenant_adoption(
    state: &AppState,
) -> Result<HashMap<&'static str, TenantSettingAdoption>, ApiError> {
    state
        .tenant_settings
        .adoption_across_tenants()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

fn to_response(
    smtp: SmtpSettingsView,
    sms: SmsSettingsView,
    runtime: &[ResolvedSetting],
    db_overrides: &HashMap<String, String>,
    adoption: &HashMap<&'static str, TenantSettingAdoption>,
) -> SystemSettingsResponse {
    SystemSettingsResponse {
        smtp_host: smtp.host,
        smtp_port: smtp.port,
        smtp_username: smtp.username,
        smtp_password_set: smtp.password_set,
        smtp_from_address: smtp.from_address,
        smtp_use_tls: smtp.use_tls,
        sms_gateway_url: sms.gateway_url,
        sms_auth_header: sms.auth_header,
        sms_auth_token_set: sms.auth_token_set,
        sms_sender_id: sms.sender_id,
        runtime_settings: runtime
            .iter()
            .map(|s| to_runtime_response(s, db_overrides.get(&s.key), adoption.get(s.key.as_str())))
            .collect(),
    }
}

fn to_runtime_response(
    setting: &ResolvedSetting,
    db_value: Option<&String>,
    adoption: Option<&TenantSettingAdoption>,
) -> RuntimeSettingResponse {
    RuntimeSettingResponse {
        key: setting.key.clone(),
        owner: match setting.owner {
            SettingOwner::Builtin => "BUILTIN",
            SettingOwner::EnvLocked => "ENV_LOCKED",
            SettingOwner::DbManaged => "DB_MANAGED",
        }
        .to_string(),
        source: match setting.source {
            SettingSource::Builtin => "BUILTIN",
            SettingSource::Env => "ENV",
            SettingSource::Db => "DB",
        }
        .to_string(),
        secret: setting.secret,
        restart_required: setting.restart_required,
        default_risk: match setting.default_risk {
            DefaultRisk::Safe => "SAFE",
            DefaultRisk::Review => "REVIEW",
            DefaultRisk::Dangerous => "DANGEROUS",
        }
        .to_string(),
        status: match setting.status {
            SettingSafetyStatus::Safe => "SAFE",
            SettingSafetyStatus::NeedsAction => "NEEDS_ACTION",
        }
        .to_string(),
        reason: setting.reason.clone(),
        description: setting.description.clone(),
        value: setting.value.clone(),
        default_value: setting.default_value.clone(),
        db_value: if setting.secret {
            None
        } else {
            db_value.cloned()
        },
        editable: setting.owner == SettingOwner::DbManaged && !setting.secret,
        // Make it visible on screen that just saving doesn't change behaviour (MT27). The single source of the
        // rule is `ResolvedSetting::is_pending_restart` (clearing an override also counts as not yet applied).
        pending_restart: setting.is_pending_restart(db_value.map(String::as_str)),
        shared_with_web: is_shared_with_web(&setting.key),
        tenant_overridable: is_tenant_overridable(&setting.key),
        tenants_following: adoption.map(|a| a.following),
        tenants_overriding: adoption
            .map(|a| {
                a.overriding
                    .iter()
                    .map(|entry| TenantOverrideResponse {
                        tenant_id: entry.tenant_id.to_string(),
                        tenant_name: entry.tenant_name.clone(),
                        value: entry.value.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}
