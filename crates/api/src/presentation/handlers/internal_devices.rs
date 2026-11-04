//! 利用者の端末の一覧と、ログインした端末の結び付け（`/internal/devices/*`・`/internal/account/devices*`。
//! task #872。ADR-0071）。
//!
//! どれも web だけが呼ぶ内部の口（サービストークンの内側）。判定は Application 層
//! （`DeviceRegistryService`）にあり、ここは DTO の詰め替えだけを行う。

use crate::application::audit::RequestContext;
use crate::application::device_registry::{
    DeviceOverviewOutcome, ObserveOutcome, ObserveSignIn, RegisterDeviceOutcome,
    RevokeDeviceOutcome,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountDeviceSummary, InternalAccountDevicesRequest, InternalAccountDevicesResponse,
    InternalAccountRegisterDeviceRequest, InternalAccountRegisterDeviceResponse,
    InternalAccountRevokeDeviceRequest, InternalAccountRevokeDeviceResponse,
    InternalDeviceObserveRequest, InternalDeviceObserveResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// ログインしたばかりの SSO セッションへ端末を結び付ける（`POST /internal/devices/observe`）。
pub async fn observe(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalDeviceObserveRequest>,
) -> Json<InternalDeviceObserveResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .device_registry
        .observe_sign_in(
            ObserveSignIn {
                sso_session_id: &req.sso_session_id,
                device_token: req.device_token.as_deref(),
                country: req.country.as_deref(),
            },
            &ctx,
        )
        .await;
    // ログイン履歴（task #879）。端末の判定と同じ所で写す（国はここでしか分からない）。
    // 端末の判定が失敗しても履歴は残す（登録の有無は分からない扱い）。
    let device_registered = match &outcome {
        Ok(ObserveOutcome::Registered) => Some(true),
        Ok(ObserveOutcome::Unregistered) if req.device_token.is_some() => Some(false),
        _ => None,
    };
    if let Err(e) = state
        .sign_in_history
        .record_sign_in(
            &req.sso_session_id,
            req.country.as_deref(),
            device_registered,
        )
        .await
    {
        tracing::error!(error = %e, "sign-in history could not be recorded");
    }
    Json(match outcome {
        Ok(ObserveOutcome::Registered) => InternalDeviceObserveResponse::Registered,
        Ok(ObserveOutcome::Unregistered) => InternalDeviceObserveResponse::Unregistered,
        Ok(ObserveOutcome::Ignored) => InternalDeviceObserveResponse::Ignored,
        Err(e) => {
            tracing::error!(error = %e, "device observation failed with internal error");
            InternalDeviceObserveResponse::Internal
        }
    })
}

/// 「端末」の欄（`POST /internal/account/devices`）。
pub async fn account_devices(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountDevicesRequest>,
) -> Result<Json<InternalAccountDevicesResponse>, Response> {
    // テナントは必須（他の `/internal/account/*` と同じ fail-closed）。
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .device_registry
        .overview(&req.sso_session_id, req.device_token.as_deref())
        .await;
    Ok(Json(match outcome {
        DeviceOverviewOutcome::Ok(view) => InternalAccountDevicesResponse::Ok {
            current_registered: view.current_device_id.is_some(),
            current_identified: view.current_device_identified,
            passkey_fresh: view.passkey_fresh,
            alerts_enabled: view.alerts_enabled,
            devices: view
                .devices
                .iter()
                .map(|d| AccountDeviceSummary {
                    id: d.id.to_string(),
                    name: d.name.clone(),
                    current: Some(d.id) == view.current_device_id,
                    user_agent: d.user_agent.clone(),
                    registered_at: d.registered_at.to_rfc3339(),
                    last_used_at: d.last_used_at.to_rfc3339(),
                    last_country: d.last_country.as_ref().map(|c| c.as_str().to_string()),
                    expires_at: d.expires_at().to_rfc3339(),
                })
                .collect(),
        },
        DeviceOverviewOutcome::SessionExpired => InternalAccountDevicesResponse::SessionExpired,
        DeviceOverviewOutcome::Internal(e) => {
            tracing::error!(error = %e, "device overview failed with internal error");
            InternalAccountDevicesResponse::Internal
        }
    }))
}

/// 今のブラウザを端末として登録する（`POST /internal/account/devices/register`）。
pub async fn account_register_device(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRegisterDeviceRequest>,
) -> Result<Json<InternalAccountRegisterDeviceResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .device_registry
        .register(
            tenant,
            &req.sso_session_id,
            req.device_token.as_deref(),
            &req.name,
            req.country.as_deref(),
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        RegisterDeviceOutcome::Registered => InternalAccountRegisterDeviceResponse::Registered,
        RegisterDeviceOutcome::PasskeyRequired => {
            InternalAccountRegisterDeviceResponse::PasskeyRequired
        }
        RegisterDeviceOutcome::AlreadyRegistered => {
            InternalAccountRegisterDeviceResponse::AlreadyRegistered
        }
        RegisterDeviceOutcome::InvalidName => InternalAccountRegisterDeviceResponse::InvalidName,
        RegisterDeviceOutcome::DeviceUnidentified => {
            InternalAccountRegisterDeviceResponse::DeviceUnidentified
        }
        RegisterDeviceOutcome::SessionExpired => {
            InternalAccountRegisterDeviceResponse::SessionExpired
        }
        RegisterDeviceOutcome::Internal(e) => {
            tracing::error!(error = %e, "device registration failed with internal error");
            InternalAccountRegisterDeviceResponse::Internal
        }
    }))
}

/// 端末の登録を取り消す（`POST /internal/account/devices/revoke`）。
pub async fn account_revoke_device(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeDeviceRequest>,
) -> Result<Json<InternalAccountRevokeDeviceResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(device_id) = Uuid::parse_str(&req.device_id) else {
        return Ok(Json(InternalAccountRevokeDeviceResponse::NotFound));
    };
    let outcome = state
        .device_registry
        .revoke(tenant, &req.sso_session_id, device_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeDeviceOutcome::Revoked { sessions } => {
            InternalAccountRevokeDeviceResponse::Revoked { sessions }
        }
        RevokeDeviceOutcome::NotFound => InternalAccountRevokeDeviceResponse::NotFound,
        RevokeDeviceOutcome::SessionExpired => InternalAccountRevokeDeviceResponse::SessionExpired,
        RevokeDeviceOutcome::Internal(e) => {
            tracing::error!(error = %e, "device revocation failed with internal error");
            InternalAccountRevokeDeviceResponse::Internal
        }
    }))
}
