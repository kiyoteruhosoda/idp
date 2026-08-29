//! Passkey（WebAuthn）API ハンドラ（`/internal/passkey/*`）。
//!
//! セルフ登録（register/begin, register/complete, delete, list）と、ログイン 3 経路の認証
//! （login/begin と、経路ごとの login/complete・login/admin/complete・login/portal/complete）を
//! 提供する。**開始（begin）は 3 経路で共通**で、`auth_session_id` を渡すかどうかがそのまま
//! チャレンジの用途になる（渡す＝ OIDC 認可フロー、渡さない＝直接ログイン）。Cookie から
//! その値を決めるのは web の仕事で、api は渡された値だけを見る。
//! すべて `/internal/*` ルータに属し、サービス認証トークンで保護される。

use crate::application::admin_login::{AdminLoginOutcome, AdminPasskeyLoginCommand};
use crate::application::audit::RequestContext;
use crate::application::passkey_authentication::PasskeyAuthOutcome;
use crate::application::passkey_registration::PasskeyRegistrationError;
use crate::application::portal_login::{PortalLoginOutcome, PortalPasskeyLoginCommand};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use idp_contracts::auth::{
    InternalAdminPasskeyLoginCompleteRequest, InternalAdminPasskeyLoginCompleteResponse,
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse, InternalPasskeyListRequest,
    InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginBeginResponse, InternalPasskeyLoginCompleteRequest,
    InternalPasskeyLoginCompleteResponse, InternalPasskeyRegisterBeginRequest,
    InternalPasskeyRegisterBeginResponse, InternalPasskeyRegisterCompleteRequest,
    InternalPasskeyRegisterCompleteResponse, InternalPortalPasskeyLoginCompleteRequest,
    InternalPortalPasskeyLoginCompleteResponse, PasskeyCredentialInfo,
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
) -> Result<Json<InternalPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let ttl = state.config.sso_absolute_ttl().as_secs();
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .passkey_authentication
        .complete(tenant, challenge_id, req.credential, &ctx)
        .await;
    Ok(Json(match outcome {
        PasskeyAuthOutcome::Success {
            location,
            form_post,
            sso_session_id,
        } => InternalPasskeyLoginCompleteResponse::Success {
            redirect_to: location,
            form_post,
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
        PasskeyAuthOutcome::PolicyDenied => InternalPasskeyLoginCompleteResponse::PolicyDenied,
        PasskeyAuthOutcome::Internal(e) => {
            tracing::error!(error = %e, "passkey login complete error");
            InternalPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// 管理コンソールの Passkey ログイン完了（`POST /internal/passkey/login/admin/complete`）。
///
/// 認可フローの `login_complete` と違い、`auth_session` も authorization code も関わらない。
/// admin 権限を確認して SSO セッションを直接発行する（`AdminLoginService` がパスワード経路と
/// 同じ判定を通す）。
pub async fn admin_login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminPasskeyLoginCompleteRequest>,
) -> Result<Json<InternalAdminPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let ttl = state.config.sso_absolute_ttl().as_secs();
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .login_with_passkey(
            tenant,
            AdminPasskeyLoginCommand {
                challenge_id,
                credential: req.credential,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        AdminLoginOutcome::Success { sso_session_id } => {
            InternalAdminPasskeyLoginCompleteResponse::Success {
                sso_session_id,
                sso_absolute_ttl_secs: ttl,
            }
        }
        AdminLoginOutcome::PasskeyChallengeNotFound => {
            InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminPasskeyLoginCompleteResponse::InvalidCredential
        }
        AdminLoginOutcome::Forbidden => InternalAdminPasskeyLoginCompleteResponse::Forbidden,
        AdminLoginOutcome::PolicyDenied => InternalAdminPasskeyLoginCompleteResponse::PolicyDenied,
        AdminLoginOutcome::RateLimited => InternalAdminPasskeyLoginCompleteResponse::RateLimited,
        // パスワード経路でしか出ない outcome（パスキー経路では到達しない）。
        other => {
            tracing::error!(
                outcome = admin_outcome_label(&other),
                "unexpected outcome from admin passkey login"
            );
            InternalAdminPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// ポータルの Passkey ログイン完了（`POST /internal/passkey/login/portal/complete`）。
///
/// admin 権限を要求しない点と、メール検証ゲート（SEC6b）・表示言語の返却がある点が管理コンソール版と
/// 異なる。TOTP のステップは踏ませない（パスキーが `require_mfa` を満たすため）。
pub async fn portal_login_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalPasskeyLoginCompleteRequest>,
) -> Result<Json<InternalPortalPasskeyLoginCompleteResponse>, Response> {
    let challenge_id = match req.challenge_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Json(
                InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound,
            ))
        }
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let ttl = state.config.sso_absolute_ttl().as_secs();
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .login_with_passkey(
            tenant,
            PortalPasskeyLoginCommand {
                challenge_id,
                credential: req.credential,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        PortalLoginOutcome::Success {
            sso_session_id,
            user_language,
        } => InternalPortalPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
            user_language,
        },
        PortalLoginOutcome::PasskeyChallengeNotFound => {
            InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound
        }
        PortalLoginOutcome::InvalidCredentials => {
            InternalPortalPasskeyLoginCompleteResponse::InvalidCredential
        }
        PortalLoginOutcome::EmailVerificationRequired => {
            InternalPortalPasskeyLoginCompleteResponse::EmailVerificationRequired
        }
        PortalLoginOutcome::PolicyDenied => {
            InternalPortalPasskeyLoginCompleteResponse::PolicyDenied
        }
        PortalLoginOutcome::RateLimited => InternalPortalPasskeyLoginCompleteResponse::RateLimited,
        // パスワード経路でしか出ない outcome（パスキー経路では到達しない）。
        other => {
            tracing::error!(
                outcome = portal_outcome_label(&other),
                "unexpected outcome from portal passkey login"
            );
            InternalPortalPasskeyLoginCompleteResponse::Internal
        }
    }))
}

/// 到達しないはずの outcome をログへ出すための名前（内部ログなので運用言語＝英語・PII なし）。
fn admin_outcome_label(outcome: &AdminLoginOutcome) -> &'static str {
    match outcome {
        AdminLoginOutcome::Success { .. } => "success",
        AdminLoginOutcome::PasswordChangeRequired { .. } => "password_change_required",
        AdminLoginOutcome::RateLimited => "rate_limited",
        AdminLoginOutcome::InvalidCredentials => "invalid_credentials",
        AdminLoginOutcome::Locked => "locked",
        AdminLoginOutcome::Forbidden => "forbidden",
        AdminLoginOutcome::WeakPassword(_) => "weak_password",
        AdminLoginOutcome::PolicyDenied => "policy_denied",
        AdminLoginOutcome::PasskeyChallengeNotFound => "passkey_challenge_not_found",
        AdminLoginOutcome::MfaEnrollmentRequired => "mfa_enrollment_required",
        AdminLoginOutcome::MfaRequired => "mfa_required",
        AdminLoginOutcome::Internal(_) => "internal",
    }
}

/// 到達しないはずの outcome をログへ出すための名前（内部ログなので運用言語＝英語・PII なし）。
fn portal_outcome_label(outcome: &PortalLoginOutcome) -> &'static str {
    match outcome {
        PortalLoginOutcome::Success { .. } => "success",
        PortalLoginOutcome::MfaRequired { .. } => "mfa_required",
        PortalLoginOutcome::EmailVerificationRequired => "email_verification_required",
        PortalLoginOutcome::PasswordChangeRequired { .. } => "password_change_required",
        PortalLoginOutcome::PolicyDenied => "policy_denied",
        PortalLoginOutcome::MfaEnrollmentRequired => "mfa_enrollment_required",
        PortalLoginOutcome::PasskeyChallengeNotFound => "passkey_challenge_not_found",
        PortalLoginOutcome::RateLimited => "rate_limited",
        PortalLoginOutcome::InvalidCredentials => "invalid_credentials",
        PortalLoginOutcome::Locked => "locked",
        PortalLoginOutcome::Internal(_) => "internal",
    }
}
