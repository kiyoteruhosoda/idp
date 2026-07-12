//! MFA（TOTP）API ハンドラ（`/internal/mfa/*`）。
//!
//! TOTP の自己登録（setup/confirm/delete）と、ログインフローの TOTP 検証（verify）を扱う。
//! すべて `/internal/*` ルータに属し、サービス認証トークンで保護される。

use crate::application::mfa_login::{MfaLoginCommand, MfaLoginOutcome};
use crate::application::audit::RequestContext;
use crate::application::totp_registration::TotpRegistrationError;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use idp_contracts::auth::{
    InternalTotpConfirmRequest, InternalTotpConfirmResponse, InternalTotpDeleteRequest,
    InternalTotpDeleteResponse, InternalTotpSetupRequest, InternalTotpSetupResponse,
    InternalVerifyTotpRequest, InternalVerifyTotpResponse,
};

/// TOTP セットアップ開始（`POST /internal/mfa/totp/setup`）。
///
/// QR URI と生シークレット（base32）を返す。すでに有効な TOTP がある場合は `AlreadyConfigured`。
pub async fn setup_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpSetupRequest>,
) -> Json<InternalTotpSetupResponse> {
    match state
        .totp_registration
        .setup(&req.sso_session_id, &req.account_name)
        .await
    {
        Ok(data) => Json(InternalTotpSetupResponse::Ok {
            totp_uri: data.totp_uri,
            secret_base32: data.secret_base32,
        }),
        Err(TotpRegistrationError::AlreadyConfigured) => {
            Json(InternalTotpSetupResponse::AlreadyConfigured)
        }
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpSetupResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp setup internal error");
            Json(InternalTotpSetupResponse::Internal)
        }
    }
}

/// TOTP 確認（`POST /internal/mfa/totp/confirm`）。6 桁コードを検証して有効化する。
pub async fn confirm_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpConfirmRequest>,
) -> Json<InternalTotpConfirmResponse> {
    match state
        .totp_registration
        .confirm(&req.sso_session_id, &req.code)
        .await
    {
        Ok(()) => Json(InternalTotpConfirmResponse::Ok),
        Err(TotpRegistrationError::InvalidCode) => Json(InternalTotpConfirmResponse::InvalidCode),
        Err(TotpRegistrationError::NotFound) => Json(InternalTotpConfirmResponse::NotFound),
        Err(TotpRegistrationError::AlreadyConfigured) => {
            Json(InternalTotpConfirmResponse::AlreadyConfigured)
        }
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpConfirmResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp confirm internal error");
            Json(InternalTotpConfirmResponse::Internal)
        }
    }
}

/// TOTP 削除（`POST /internal/mfa/totp/delete`）。MFA を無効化する。
pub async fn delete_totp(
    State(state): State<AppState>,
    Json(req): Json<InternalTotpDeleteRequest>,
) -> Json<InternalTotpDeleteResponse> {
    match state.totp_registration.delete(&req.sso_session_id).await {
        Ok(()) => Json(InternalTotpDeleteResponse::Ok),
        Err(TotpRegistrationError::SessionExpired) => {
            Json(InternalTotpDeleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "totp delete internal error");
            Json(InternalTotpDeleteResponse::Internal)
        }
    }
}

/// ログインフロー TOTP 検証（`POST /internal/mfa/totp/verify`）。
///
/// パスワード認証済み（`password_verified_at` 設定済み）の AuthSession で TOTP コードを検証し、
/// 成功時に SSO セッション発行 → code 発行（または同意画面へ誘導）を行う。
pub async fn verify_totp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalVerifyTotpRequest>,
) -> Result<Json<InternalVerifyTotpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    let outcome = state
        .mfa_login
        .verify(
            tenant,
            MfaLoginCommand {
                auth_session_id: req.auth_session_id,
                totp_code: req.totp_code,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        MfaLoginOutcome::Success {
            location,
            sso_session_id,
        } => InternalVerifyTotpResponse::Success {
            redirect_to: location,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        MfaLoginOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
        } => InternalVerifyTotpResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        MfaLoginOutcome::SessionExpired => InternalVerifyTotpResponse::SessionExpired,
        MfaLoginOutcome::CsrfMismatch => InternalVerifyTotpResponse::CsrfMismatch,
        MfaLoginOutcome::InvalidCode => InternalVerifyTotpResponse::InvalidCode,
        MfaLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "mfa verify internal error");
            InternalVerifyTotpResponse::Internal
        }
    }))
}
