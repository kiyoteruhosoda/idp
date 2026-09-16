//! システム設定エンドポイント（`/{tenant_id}/admin/system-settings`。MT14）。
//!
//! すべて `idp.system.admin` 権限が必要（`RequirePerms<IdpSystemAdmin>`）。`idp.system.admin` は root
//! scope でしか存在できないため、システム設定（SMTP 等）を参照・更新できるのは root テナントの system
//! 管理者だけになる（ADR-0009 §4）。SMTP パスワードは暗号化して保存し、参照時は平文を返さない
//! （設定済みか否かのみ）。

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
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use std::collections::HashMap;

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

/// ランタイム設定の DB 上書き値を更新する（`DB_MANAGED` かつ非 secret のキーのみ）。
/// `value` が `None` または空のときは上書きを解除する。反映には再起動が必要。
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
    )
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
            // ランタイム設定の値の書式違反（キー未知・パース不能）。運用者向けの管理 API であり、
            // どのキーが不正かは要求本文から自明なため、共通の「不正なリクエスト」を返す。
            DomainError::InvalidValue(_) => {
                ApiError::BadRequest(ApiMessages::new(locale).get("api-runtime-setting-invalid"))
            }
            // 書式は正しいが、その値では次回起動できない（https ISSUER × 開発用既定 secret、
            // または COOKIE_DOMAIN との不整合）。400 と混ぜると画面が「書式が不正」としか言えず、
            // 運用者は正しい URL を疑い続ける。配置状態との衝突として 409 で区別する（ADR-0017）。
            //
            // 画面へ返すのは翻訳済みの一般的な案内なので、**どの条件で落ちたか**は運用ログへ出す
            // （原因を突き止めるにはこちらが要る。運用ログは運用言語で統一する）。
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
    // テナントが上書きできるキーは再起動を待たずに参照のたびに引く（ADR-0058 §9）。全体の行の
    // キャッシュをここで捨てないと、テナント解決のキャッシュの寿命ぶん古い値で判定が続く。
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
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    // SMS ゲートウェイ（AP13）。SMTP と同じ 1 回の保存で扱う（設定画面が 1 枚のため、
    // 別々に保存させると片方だけ更新した状態が生まれる）。
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

/// SMTP 設定だけを参照する（`GET /{tenant_id}/admin/system-settings/smtp`。ADR-0051）。
///
/// 保護は `idp.smtp:read`。**パスワードの平文は返さない**（設定済みか否かのみ）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/system-settings/smtp",
    tag = "admin",
    responses(
        (status = 200, description = "SMTP 設定（パスワードは設定有無のみ）", body = SmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:read 必須。root テナントのみ）"),
    )
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

/// SMTP 設定だけを更新する（`PUT /{tenant_id}/admin/system-settings/smtp`。ADR-0051）。
///
/// 保護は `idp.smtp:write`。SMS・ランタイム設定には触れない ——機械へ開けるのはメールの経路だけ
/// である、という範囲を**型と経路の両方**で示す。`smtp_password` を省略したときは現行維持。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/system-settings/smtp",
    tag = "admin",
    request_body = UpdateSmtpSettingsRequest,
    responses(
        (status = 200, description = "更新後の SMTP 設定", body = SmtpSettingsResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.smtp:write 必須。root テナントのみ）"),
    )
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

/// 要求テナントが root であることを課す（ADR-0051）。
///
/// ⚠ **権限の判定だけでは足りない。** `idp.smtp:*` を root 以外で配れないようにしてあるのは
/// 付与の側（`is_grantable_in_tenant`）で、**既に配られてしまった行**や、将来テナントを
/// 増やしたときの取りこぼしまでは面倒を見ない。`system_settings` がテナント横断の表である以上、
/// 使う側でも同じ条件を課す（二重防御。ADR-0037 §5 と同じ考え方）。
fn require_root_tenant(tenant: &ResolvedTenant, locale: ApiLocale) -> Result<(), ApiError> {
    if tenant.tenant().is_root() {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        ApiMessages::new(locale).get("api-permission-insufficient"),
    ))
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

/// テナントが上書きできる各キーについて、従っているテナントの件数と外れているテナント（ADR-0058 §6）。
///
/// ⚠ テナントをまたいで読む。`idp.system.admin` の口（本モジュールの全体設定）からだけ呼ぶ。
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
        // 保存しただけでは挙動が変わらないことを画面から見えるようにする（MT27）。判定規則は
        // `ResolvedSetting::is_pending_restart` が単一の出所（上書きの解除も未反映に含む）。
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
