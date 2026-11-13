//! The tenant's own mail route (`/{tenant_id}/admin/settings/smtp`, ADR-0058 §8).
//!
//! Protected by `idp.smtp:read` / `idp.smtp:write`. ⚠ **Not implied by `idp.tenant.admin`** (granted explicitly, one by one.
//! If implied, root's tenant admin would reach the global route -- the shape ADR-0051 rejected).
//!
//! It reaches **only the requesting tenant's route** and never touches the global route (`/admin/system-settings/smtp`).
//! If the tenant has no route, mail is sent via the global route. ⚠ The route is resolved **as a whole**;
//! missing fields are not filled from the global values (`SystemSettingsService::smtp_server_for`).
//!
//! The password is stored encrypted and **plaintext is never returned** (only whether it is set).

use crate::application::system_settings::TenantSmtpView;
use crate::domain::error::DomainError;
use crate::domain::system_setting::UpdateSmtpCommand;
use crate::presentation::admin::{RequirePerms, SmtpRead, SmtpWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{TenantSmtpSettingsResponse, UpdateSmtpSettingsRequest};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;

/// Reads the tenant's mail route.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "テナントの SMTP 設定（パスワードは設定有無のみ。経路を持たなければ inherited=true で項目は空）", body = TenantSmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_tenant_smtp(
    RequirePerms(_admin, _): RequirePerms<SmtpRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<TenantSmtpSettingsResponse>, ApiError> {
    let view = state
        .system_settings
        .get_tenant_smtp(tenant.context().tenant_id())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_response(view)))
}

/// Saves the tenant's mail route. `smtp_password` omitted = keep current / empty = clear.
///
/// If all route-defining fields (host, username, password, sender) become empty, the row is deleted and
/// it reverts to following the global route.
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    request_body = UpdateSmtpSettingsRequest,
    responses(
        (status = 200, description = "更新後のテナントの SMTP 設定", body = TenantSmtpSettingsResponse),
        (status = 400, description = "宛先が宅内・ループバック・リンクローカルを指している"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update_tenant_smtp(
    RequirePerms(admin, _): RequirePerms<SmtpWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<UpdateSmtpSettingsRequest>,
) -> Result<Json<TenantSmtpSettingsResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let view = state
        .system_settings
        .update_tenant_smtp(
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
        .map_err(|e| match e {
            DomainError::InvalidValue(_) => {
                ApiError::BadRequest(ApiMessages::new(locale).get("api-smtp-host-internal"))
            }
            other => ApiError::Internal(other.to_string()),
        })?;
    Ok(Json(to_response(view)))
}

/// Deletes the tenant's mail route and reverts to following the global route.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "消したあとの状態（inherited=true）", body = TenantSmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn clear_tenant_smtp(
    RequirePerms(admin, _): RequirePerms<SmtpWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
) -> Result<Json<TenantSmtpSettingsResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let view = state
        .system_settings
        .clear_tenant_smtp(tenant.context(), &admin.actor, &ctx)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_response(view)))
}

fn to_response(view: TenantSmtpView) -> TenantSmtpSettingsResponse {
    TenantSmtpSettingsResponse {
        inherited: view.inherited,
        smtp_host: view.settings.host,
        smtp_port: view.settings.port,
        smtp_username: view.settings.username,
        smtp_password_set: view.settings.password_set,
        smtp_from_address: view.settings.from_address,
        smtp_use_tls: view.settings.use_tls,
    }
}
