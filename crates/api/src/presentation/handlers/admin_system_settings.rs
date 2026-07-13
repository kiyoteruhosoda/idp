//! システム設定エンドポイント（`/{tenant_id}/admin/system-settings`。MT14）。
//!
//! すべて `idp.system.admin` 権限が必要（`RequirePerms<IdpSystemAdmin>`）。`idp.system.admin` は root
//! scope でしか存在できないため、システム設定（SMTP 等）を参照・更新できるのは root テナントの system
//! 管理者だけになる（ADR-0009 §4）。SMTP パスワードは暗号化して保存し、参照時は平文を返さない
//! （設定済みか否かのみ）。

use crate::config::{ResolvedSetting, SettingSource};
use crate::domain::system_setting::{
    DefaultRisk, SettingOwner, SmtpSettingsView, UpdateSmtpCommand,
};
use crate::presentation::admin::{IdpSystemAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    RuntimeSettingResponse, SystemSettingsResponse, UpdateSystemSettingsRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;

/// システム設定（SMTP 等）を取得する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/system-settings",
    tag = "admin",
    responses(
        (status = 200, description = "システム設定（SMTP パスワードは設定有無のみ）", body = SystemSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    )
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
    Ok(Json(to_response(smtp, state.config.resolved_settings())))
}

/// システム設定（SMTP 等）を更新する。`smtp_password` が指定されたときのみパスワードを上書きする。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/system-settings",
    tag = "admin",
    request_body = UpdateSystemSettingsRequest,
    responses(
        (status = 200, description = "更新後のシステム設定", body = SystemSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    )
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_response(updated, state.config.resolved_settings())))
}

fn to_response(smtp: SmtpSettingsView, runtime: &[ResolvedSetting]) -> SystemSettingsResponse {
    SystemSettingsResponse {
        smtp_host: smtp.host,
        smtp_port: smtp.port,
        smtp_username: smtp.username,
        smtp_password_set: smtp.password_set,
        smtp_from_address: smtp.from_address,
        smtp_use_tls: smtp.use_tls,
        runtime_settings: runtime.iter().map(to_runtime_response).collect(),
    }
}

fn to_runtime_response(setting: &ResolvedSetting) -> RuntimeSettingResponse {
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
    }
}
