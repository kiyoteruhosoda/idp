//! 同意 API（`/internal/consent-info`、`/internal/consent/approve`、`/internal/consent/deny`）。
//!
//! 同意画面に必要な情報の提供と、同意付与・拒否の処理を担う内部エンドポイント。
//! ログイン画面と同様に `/internal/*` は外部公開しない（`require_service_token` で保護）。

use crate::application::audit::RequestContext;
use crate::application::consent::ConsentOutcome;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::auth::{
    InternalConsentApproveRequest, InternalConsentApproveResponse, InternalConsentDenyRequest,
    InternalConsentDenyResponse, InternalConsentInfoRequest, InternalConsentInfoResponse,
};

/// 同意画面情報（`GET /internal/consent-info`）。
/// `auth_session_id` の AuthSession を確認し、クライアント名・要求 scope を返す。
pub async fn consent_info(
    State(state): State<AppState>,
    Query(req): Query<InternalConsentInfoRequest>,
) -> Result<Json<InternalConsentInfoResponse>, Response> {
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    Ok(match state
        .consent
        .info(tenant, &req.auth_session_id)
        .await {
        Ok(Some(info)) => Json(InternalConsentInfoResponse::Ok {
            auth_session_id: info.auth_session_id,
            client_name: info.client_name,
            client_id: info.client_id,
            requested_scopes: info.requested_scopes,
        }),
        Ok(None) => Json(InternalConsentInfoResponse::SessionExpired),
        Err(e) => {
            tracing::error!(error = %e, "consent_info: failed to get consent info");
            Json(InternalConsentInfoResponse::SessionExpired)
        }
    })
}

/// 同意承認（`POST /internal/consent/approve`）。同意を記録し code を発行する。
pub async fn consent_approve(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalConsentApproveRequest>,
) -> Result<impl IntoResponse, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    let outcome = state
        .consent
        .approve(tenant, &req.auth_session_id, &ctx)
        .await;
    Ok(Json(match outcome {
        ConsentOutcome::Approved { location } => {
            InternalConsentApproveResponse::Success { redirect_to: location }
        }
        ConsentOutcome::SessionExpired => InternalConsentApproveResponse::SessionExpired,
        ConsentOutcome::Internal(e) => {
            tracing::error!(error = %e, "consent_approve: internal error");
            InternalConsentApproveResponse::Internal
        }
        ConsentOutcome::Denied { .. } => {
            // approve エンドポイントで Denied は起きないが念のため。
            InternalConsentApproveResponse::Internal
        }
    }))
}

/// 同意拒否（`POST /internal/consent/deny`）。`access_denied` エラーを RP へリダイレクトする。
pub async fn consent_deny(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalConsentDenyRequest>,
) -> Result<impl IntoResponse, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    let outcome = state
        .consent
        .deny(tenant, &req.auth_session_id, &ctx)
        .await;
    Ok((
        StatusCode::OK,
        Json(match outcome {
            ConsentOutcome::Denied { location } => {
                InternalConsentDenyResponse::Ok { redirect_to: location }
            }
            ConsentOutcome::SessionExpired => InternalConsentDenyResponse::SessionExpired,
            ConsentOutcome::Internal(e) => {
                tracing::error!(error = %e, "consent_deny: internal error");
                InternalConsentDenyResponse::Internal
            }
            ConsentOutcome::Approved { .. } => {
                // deny エンドポイントで Approved は起きないが念のため。
                InternalConsentDenyResponse::Internal
            }
        }),
    ))
}
