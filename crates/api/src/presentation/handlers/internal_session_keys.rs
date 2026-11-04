//! SSO セッションの端末の鍵への結び付け（DBSC。`/internal/sso/key-binding*`。task #887・ADR-0074）。
//!
//! どれも web だけが呼ぶ内部の口（サービストークンの内側）。判定は Application 層
//! （`SessionKeyBindingService`）にあり、ここは DTO の詰め替えだけを行う。

use crate::application::audit::RequestContext;
use crate::application::session_key_binding::SessionKeyOutcome;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use assay_contracts::auth::{
    InternalSessionKeyBindingRequest, InternalSessionKeyBindingResponse,
    InternalSessionKeyRefreshRequest, InternalSessionKeyRegisterRequest,
    InternalSessionKeyResponse,
};
use axum::extract::{Extension, State};
use axum::Json;

fn response(
    outcome: Result<SessionKeyOutcome, crate::domain::error::DomainError>,
) -> InternalSessionKeyResponse {
    match outcome {
        Ok(SessionKeyOutcome::Bound {
            session_identifier,
            remaining_secs,
        }) => InternalSessionKeyResponse::Bound {
            session_identifier,
            remaining_secs,
        },
        Ok(SessionKeyOutcome::Rejected) => InternalSessionKeyResponse::Rejected,
        Ok(SessionKeyOutcome::KeyMismatch) => InternalSessionKeyResponse::KeyMismatch,
        Ok(SessionKeyOutcome::SessionGone) => InternalSessionKeyResponse::SessionGone,
        Err(e) => {
            tracing::error!(error = %e, "session key binding failed with internal error");
            InternalSessionKeyResponse::Internal
        }
    }
}

/// 登録（`POST /internal/sso/key-binding/register`）。
pub async fn register(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSessionKeyRegisterRequest>,
) -> Json<InternalSessionKeyResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    Json(response(
        state
            .session_key_binding
            .register(&req.sso_session_id, &req.proof, &ctx)
            .await,
    ))
}

/// 更新（`POST /internal/sso/key-binding/refresh`）。
pub async fn refresh(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSessionKeyRefreshRequest>,
) -> Json<InternalSessionKeyResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    Json(response(
        state
            .session_key_binding
            .refresh(
                &req.sso_session_id,
                &req.session_identifier,
                &req.proof,
                &ctx,
            )
            .await,
    ))
}

/// 結び付いているか（`POST /internal/sso/key-binding`）。web の入口の確かめが使う。
pub async fn binding(
    State(state): State<AppState>,
    Json(req): Json<InternalSessionKeyBindingRequest>,
) -> Json<InternalSessionKeyBindingResponse> {
    Json(
        match state
            .session_key_binding
            .binding_of(&req.sso_session_id)
            .await
        {
            Ok(Some(session_identifier)) => {
                InternalSessionKeyBindingResponse::Bound { session_identifier }
            }
            Ok(None) => InternalSessionKeyBindingResponse::Unbound,
            Err(e) => {
                tracing::error!(error = %e, "session key binding lookup failed with internal error");
                InternalSessionKeyBindingResponse::Internal
            }
        },
    )
}
