//! テナント自身のメールの経路（`/{tenant_id}/admin/settings/smtp`。ADR-0058 §8）。
//!
//! 保護は `idp.smtp:read` / `idp.smtp:write`。⚠ **`idp.tenant.admin` は含意しない**（付与は明示の 1 枚。
//! 含意させると root のテナント管理者が全体の経路へ届く ——ADR-0051 が断った形）。
//!
//! 届くのは**要求テナントの経路だけ**で、全体の経路（`/admin/system-settings/smtp`）には触れない。
//! テナントが経路を持っていなければ、メールは全体の経路で送られる。⚠ 経路は**塊**で解決し、
//! 欠けた項目を全体の値で埋めない（`SystemSettingsService::smtp_server_for`）。
//!
//! パスワードは暗号化して保存し、**平文を返さない**（設定の有無だけ）。

use crate::application::system_settings::TenantSmtpView;
use crate::domain::system_setting::UpdateSmtpCommand;
use crate::presentation::admin::{RequirePerms, SmtpRead, SmtpWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{TenantSmtpSettingsResponse, UpdateSmtpSettingsRequest};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;

/// テナントのメールの経路を参照する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "テナントの SMTP 設定（パスワードは設定有無のみ。経路を持たなければ inherited=true で項目は空）", body = TenantSmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:read 必須）"),
    )
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

/// テナントのメールの経路を保存する。`smtp_password` は省略 = 現行維持 / 空文字 = 消去。
///
/// 経路を決める項目（host・利用者名・パスワード・差出人）がすべて空になった場合は、行ごと消して
/// 全体の経路に従う状態へ戻す。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    request_body = UpdateSmtpSettingsRequest,
    responses(
        (status = 200, description = "更新後のテナントの SMTP 設定", body = TenantSmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須）"),
    )
)]
pub async fn update_tenant_smtp(
    RequirePerms(admin, _): RequirePerms<SmtpWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
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
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(to_response(view)))
}

/// テナントのメールの経路を消し、全体の経路に従う状態へ戻す。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "消したあとの状態（inherited=true）", body = TenantSmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須）"),
    )
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
