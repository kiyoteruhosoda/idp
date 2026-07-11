//! Passkey（WebAuthn）API ハンドラ（`/internal/passkey/*`）。
//!
//! セルフ登録（register/begin, register/complete, delete, list）と
//! ログインフロー認証（login/begin, login/complete）を提供する。
//! すべて `/internal/*` ルータに属し、サービス認証トークンで保護される。

use crate::application::passkey_authentication::PasskeyAuthOutcome;
use crate::application::passkey_registration::PasskeyRegistrationError;
use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::internal_tenant;
use axum::extract::{Extension, State};
use axum::Json;
use idp_contracts::auth::{
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse,
    InternalPasskeyListRequest, InternalPasskeyListResponse,
    InternalPasskeyLoginBeginRequest, InternalPasskeyLoginBeginResponse,
    InternalPasskeyLoginCompleteRequest, InternalPasskeyLoginCompleteResponse,
    InternalPasskeyRegisterBeginRequest, InternalPasskeyRegisterBeginResponse,
    InternalPasskeyRegisterCompleteRequest, InternalPasskeyRegisterCompleteResponse,
    PasskeyCredentialInfo,
};
use uuid::Uuid;

/// Passkey 登録開始（`POST /internal/passkey/register/begin`）。
pub async fn register_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyRegisterBeginRequest>,
) -> Json<InternalPasskeyRegisterBeginResponse> {
    match state
        .passkey_registration
        .begin(&req.sso_session_id, &req.user_name)
        .await
    {
        Ok((challenge_id, options)) => Json(InternalPasskeyRegisterBeginResponse::Ok {
            challenge_id: challenge_id.to_string(),
            options,
        }),
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyRegisterBeginResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey register begin error");
            Json(InternalPasskeyRegisterBeginResponse::Internal)
        }
    }
}

/// Passkey 登録完了（`POST /internal/passkey/register/complete`）。
pub async fn register_complete(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyRegisterCompleteRequest>,
) -> Json<InternalPasskeyRegisterCompleteResponse> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Json(InternalPasskeyRegisterCompleteResponse::ChallengeNotFound),
    };
    match state
        .passkey_registration
        .complete(&req.sso_session_id, challenge_id, &req.name, req.credential)
        .await
    {
        Ok(cred_id) => Json(InternalPasskeyRegisterCompleteResponse::Ok {
            credential_id: cred_id.to_string(),
        }),
        Err(PasskeyRegistrationError::ChallengeNotFound) => {
            Json(InternalPasskeyRegisterCompleteResponse::ChallengeNotFound)
        }
        Err(PasskeyRegistrationError::InvalidCredential(msg)) => {
            tracing::warn!(error = %msg, "passkey register complete: invalid credential");
            Json(InternalPasskeyRegisterCompleteResponse::InvalidCredential)
        }
        Err(PasskeyRegistrationError::DuplicateCredential) => {
            Json(InternalPasskeyRegisterCompleteResponse::DuplicateCredential)
        }
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyRegisterCompleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey register complete error");
            Json(InternalPasskeyRegisterCompleteResponse::Internal)
        }
    }
}

/// Passkey 削除（`POST /internal/passkey/delete`）。
pub async fn passkey_delete(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyDeleteRequest>,
) -> Json<InternalPasskeyDeleteResponse> {
    let credential_id = match req.credential_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Json(InternalPasskeyDeleteResponse::Internal),
    };
    match state
        .passkey_registration
        .delete(&req.sso_session_id, credential_id)
        .await
    {
        Ok(()) => Json(InternalPasskeyDeleteResponse::Ok),
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyDeleteResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey delete error");
            Json(InternalPasskeyDeleteResponse::Internal)
        }
    }
}

/// 登録済み Passkey 一覧（`POST /internal/passkey/list`）。
pub async fn passkey_list(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyListRequest>,
) -> Json<InternalPasskeyListResponse> {
    match state.passkey_registration.list(&req.sso_session_id).await {
        Ok(infos) => {
            let credentials = infos
                .into_iter()
                .map(|c| PasskeyCredentialInfo {
                    id: c.id.to_string(),
                    name: c.name,
                    created_at: c.created_at.to_rfc3339(),
                    last_used_at: c.last_used_at.map(|d| d.to_rfc3339()),
                })
                .collect();
            Json(InternalPasskeyListResponse::Ok { credentials })
        }
        Err(PasskeyRegistrationError::SessionExpired) => {
            Json(InternalPasskeyListResponse::SessionExpired)
        }
        Err(e) => {
            tracing::error!(error = %e, "passkey list error");
            Json(InternalPasskeyListResponse::Internal)
        }
    }
}

/// Passkey 認証開始（`POST /internal/passkey/login/begin`）。
pub async fn login_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalPasskeyLoginBeginRequest>,
) -> Json<InternalPasskeyLoginBeginResponse> {
    match state
        .passkey_authentication
        .begin(req.auth_session_id.as_deref())
        .await
    {
        Ok((challenge_id, options)) => Json(InternalPasskeyLoginBeginResponse::Ok {
            challenge_id: challenge_id.to_string(),
            options,
        }),
        Err(e) => {
            tracing::error!(error = %e, "passkey login begin error");
            Json(InternalPasskeyLoginBeginResponse::Internal)
        }
    }
}

/// Passkey 認証完了（`POST /internal/passkey/login/complete`）。
pub async fn login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasskeyLoginCompleteRequest>,
) -> Json<InternalPasskeyLoginCompleteResponse> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Json(InternalPasskeyLoginCompleteResponse::ChallengeNotFound),
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let ttl = state.config.sso_absolute_ttl().as_secs();
    let tenant = internal_tenant(&state, req.tenant_id.as_deref());
    let outcome = state
        .passkey_authentication
        .complete(tenant, challenge_id, req.credential, &ctx)
        .await;
    Json(match outcome {
        PasskeyAuthOutcome::Success {
            location,
            sso_session_id,
        } => InternalPasskeyLoginCompleteResponse::Success {
            redirect_to: location,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        PasskeyAuthOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
        } => InternalPasskeyLoginCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        PasskeyAuthOutcome::ChallengeNotFound => {
            InternalPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        PasskeyAuthOutcome::SessionExpired => InternalPasskeyLoginCompleteResponse::SessionExpired,
        PasskeyAuthOutcome::InvalidCredential => {
            InternalPasskeyLoginCompleteResponse::InvalidCredential
        }
        PasskeyAuthOutcome::Internal(e) => {
            tracing::error!(error = %e, "passkey login complete error");
            InternalPasskeyLoginCompleteResponse::Internal
        }
    })
}
