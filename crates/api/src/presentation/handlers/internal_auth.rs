//! 内部認証 API（`/internal/*`、ADR-0007 §3・§5）。
//!
//! ログイン画面（将来の `web` crate）と認可サーバ（api）を分離するための **OIDC 標準外の内部
//! エンドポイント**。web はフォーム描画とリダイレクトのみを担い、資格情報・`auth_session_id` 参照・
//! 接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を本 API へ転送する。資格情報検証・ロックアウト
//! （設計仕様 §4.3）・IP レート制限・SSO/code 発行・監査記録はすべて api（唯一の DB 所有者）が行い、
//! Cookie 組み立てとエラー文言のローカライズは web が担う。
//!
//! P2（ADR-0007）では api・web が同一プロセスのため、既存の HTML ログイン画面ハンドラは
//! [`crate::application::login::LoginService`] を直接呼び続ける。本モジュールは同じユースケースを
//! **内部エンドポイント越しに呼べる形**として公開し、P3 の web crate 化で HTTP クライアントから
//! 利用される。
//!
//! 保護（§5）: `/internal/*` は外部公開しない（リバースプロキシで遮断）。多層防御として、web→api の
//! 呼び出しにサービス認証トークン（共有シークレット。`X-Internal-Auth-Token` ヘッダ）を必須とする。
//! トークンは設定（`config` 経由）で注入する。

use crate::application::account_language::{UpdateLanguageCommand, UpdateLanguageOutcome};
use crate::application::account_password::{AccountPasswordCommand, AccountPasswordOutcome};
use crate::application::account_profile::{ProfileOutcome, UpdateNameCommand, UpdateNameOutcome};
use crate::application::account_security::{
    RevokeConsentOutcome, RevokeSessionOutcome, SecurityOverviewOutcome,
};
use crate::application::account_tenants::ListTenantsOutcome;
use crate::application::admin_login::{
    AdminChangePasswordCommand, AdminLoginCommand, AdminLoginOutcome,
};
use crate::application::audit::RequestContext;
use crate::application::authenticator_management::AuthenticatorManagementError;
use crate::application::change_password::{ChangePasswordCommand, ChangePasswordOutcome};
use crate::application::external_login::{
    CallbackCommand, CallbackOutcome, SamlAcsCommand, StartOutcome, SuccessLocation,
};
use crate::application::login::{LoginCommand, LoginOutcome};
use crate::application::password_reset::{RequestResetOutcome, ResetPasswordOutcome};
use crate::application::portal_login::{
    PortalChangePasswordCommand, PortalChangePasswordOutcome, PortalLoginCommand,
    PortalLoginOutcome, PortalMfaCommand, PortalMfaOutcome,
};
use crate::application::step_up::{StepUpCheckOutcome, StepUpVerifyCommand, StepUpVerifyOutcome};
use crate::domain::password_policy::PasswordRejection;
use crate::domain::step_up::SensitiveOperation;
use crate::domain::user_authenticator::AuthenticatorStatus;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::auth::{
    AccountConnectedAppSummary, AccountSessionSummary, AccountTenantSummary,
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountProfileRequest, InternalAccountProfileResponse,
    InternalAccountRevokeConsentRequest, InternalAccountRevokeConsentResponse,
    InternalAccountRevokeSessionRequest, InternalAccountRevokeSessionResponse,
    InternalAccountSecurityRequest, InternalAccountSecurityResponse, InternalAccountTenantsRequest,
    InternalAccountTenantsResponse, InternalAccountUpdateLanguageRequest,
    InternalAccountUpdateLanguageResponse, InternalAccountUpdateNameRequest,
    InternalAccountUpdateNameResponse, InternalAdminAuthenticateRequest,
    InternalAdminAuthenticateResponse, InternalAdminChangePasswordRequest,
    InternalAdminChangePasswordResponse, InternalAuthenticateRequest, InternalAuthenticateResponse,
    InternalChangePasswordRequest, InternalChangePasswordResponse, InternalLogoutRequest,
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
    InternalPasswordResetRequestRequest, InternalPasswordResetRequestResponse,
    InternalPortalAuthenticateRequest, InternalPortalAuthenticateResponse,
    InternalPortalChangePasswordRequest, InternalPortalChangePasswordResponse,
    InternalPortalMfaRequest, InternalPortalMfaResponse, InternalStepUpCheckRequest,
    InternalStepUpCheckResponse, InternalStepUpVerifyRequest, InternalStepUpVerifyResponse,
    PasswordRejectionReason,
};
use idp_contracts::auth::{
    AuthenticatorSummaryResponse, InternalAuthenticatorStatusRequest,
    InternalAuthenticatorStatusResponse, InternalAuthenticatorsRequest,
    InternalAuthenticatorsResponse, InternalEmailOtpRequest, InternalEmailOtpResponse,
    InternalPhoneConfirmationRequest, InternalPhoneConfirmationResponse,
    InternalPhoneRegistrationRequest, InternalPhoneRegistrationResponse,
    InternalRecoveryCodesRequest, InternalRecoveryCodesResponse, InternalSmsOtpRequest,
    InternalSmsOtpResponse,
};
use idp_contracts::auth::{
    ExternalIdpButton, InternalExternalCallbackRequest, InternalExternalCallbackResponse,
    InternalExternalProvidersRequest, InternalExternalProvidersResponse,
    InternalExternalStartRequest, InternalExternalStartResponse,
};

use idp_contracts::internal_auth::{service_token_matches, SERVICE_TOKEN_HEADER};

/// `/internal/*` を保護するミドルウェア（ADR-0007 §5）。設定のサービストークンとヘッダ値を
/// 定数時間で照合し、一致しなければ 401 で遮断する。
pub async fn require_service_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(SERVICE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !service_token_matches(presented, state.config.internal_service_token()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

/// 認証（OIDC ログイン）。web から転送された資格情報・`auth_session_id`・接続元情報で
/// [`LoginService`](crate::application::login::LoginService) を実行し、結果を JSON で返す。
pub async fn authenticate(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthenticateRequest>,
) -> Result<Json<InternalAuthenticateResponse>, Response> {
    // 接続元情報は web が転送する（api はプロキシ直下ではないため自前で X-Forwarded-For を見ない）。
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .login
        .login(
            tenant,
            LoginCommand {
                auth_session_id: req.auth_session_id,
                username: req.username,
                password: req.password,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        LoginOutcome::Success {
            location,
            form_post,
            sso_session_id,
            user_language,
        } => InternalAuthenticateResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
            user_language,
        },
        LoginOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
        } => InternalAuthenticateResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        LoginOutcome::MfaRequired { auth_session_id } => {
            InternalAuthenticateResponse::MfaRequired { auth_session_id }
        }
        LoginOutcome::PasswordChangeRequired { auth_session_id } => {
            InternalAuthenticateResponse::PasswordChangeRequired { auth_session_id }
        }
        LoginOutcome::EmailVerificationRequired => {
            InternalAuthenticateResponse::EmailVerificationRequired
        }
        LoginOutcome::PolicyDenied => InternalAuthenticateResponse::PolicyDenied,
        LoginOutcome::MfaEnrollmentRequired => InternalAuthenticateResponse::MfaEnrollmentRequired,
        LoginOutcome::SessionExpired => InternalAuthenticateResponse::SessionExpired,
        LoginOutcome::CsrfMismatch => InternalAuthenticateResponse::CsrfMismatch,
        LoginOutcome::RateLimited => InternalAuthenticateResponse::RateLimited,
        LoginOutcome::InvalidCredentials => InternalAuthenticateResponse::InvalidCredentials,
        LoginOutcome::Locked => InternalAuthenticateResponse::Locked,
        LoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal authenticate failed with internal error");
            InternalAuthenticateResponse::Internal
        }
    }))
}

/// パスワード変更（`POST /internal/change-password`、ADR-0009 §5）。`LoginService` が検出した
/// `must_change_password` を受けて、パスワード検証済みの `auth_session_id` で新パスワードを設定する。
/// セルフサービスのパスワード変更（`POST /internal/account/change-password`。MT15）。ログイン済み
/// ユーザーが SSO セッションで本人確認のうえ、現行パスワードを再検証して新パスワードを設定する。
pub async fn account_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountChangePasswordRequest>,
) -> Json<InternalAccountChangePasswordResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let outcome = state
        .account_password
        .change(
            AccountPasswordCommand {
                sso_session_id: req.sso_session_id,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    Json(match outcome {
        AccountPasswordOutcome::Ok => InternalAccountChangePasswordResponse::Ok,
        AccountPasswordOutcome::SessionExpired => {
            InternalAccountChangePasswordResponse::SessionExpired
        }
        AccountPasswordOutcome::InvalidCurrentPassword => {
            InternalAccountChangePasswordResponse::InvalidCurrentPassword
        }
        AccountPasswordOutcome::WeakPassword(rejection) => {
            InternalAccountChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        AccountPasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "account change-password failed with internal error");
            InternalAccountChangePasswordResponse::Internal
        }
    })
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalChangePasswordRequest>,
) -> Result<Json<InternalChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .change_password
        .change(
            tenant,
            ChangePasswordCommand {
                auth_session_id: req.auth_session_id,
                current_password: req.current_password,
                new_password: req.new_password,
                csrf_token: req.csrf_token,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        ChangePasswordOutcome::Success {
            location,
            form_post,
            sso_session_id,
        } => InternalChangePasswordResponse::Success {
            redirect_to: location,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        ChangePasswordOutcome::ConsentRequired {
            auth_session_id,
            sso_session_id,
        } => InternalChangePasswordResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
        },
        ChangePasswordOutcome::MfaRequired { auth_session_id } => {
            InternalChangePasswordResponse::MfaRequired { auth_session_id }
        }
        ChangePasswordOutcome::PolicyDenied => InternalChangePasswordResponse::PolicyDenied,
        ChangePasswordOutcome::MfaEnrollmentRequired => {
            InternalChangePasswordResponse::MfaEnrollmentRequired
        }
        ChangePasswordOutcome::SessionExpired => InternalChangePasswordResponse::SessionExpired,
        ChangePasswordOutcome::CsrfMismatch => InternalChangePasswordResponse::CsrfMismatch,
        ChangePasswordOutcome::InvalidCurrentPassword => {
            InternalChangePasswordResponse::InvalidCurrentPassword
        }
        ChangePasswordOutcome::WeakPassword(rejection) => {
            InternalChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        ChangePasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal change-password failed with internal error");
            InternalChangePasswordResponse::Internal
        }
    }))
}

/// Domain の拒否理由を contracts の理由コードへ写す（AP7）。
///
/// web は理由ごとに違う文言を出す。訳文そのものではなく**理由コード**を渡すのは、翻訳を
/// 引くのは表示する側（web）の責務であり、api が言語を決めないためである。
fn rejection_reason(rejection: &PasswordRejection) -> PasswordRejectionReason {
    match rejection {
        PasswordRejection::Strength(_) => PasswordRejectionReason::Policy,
        PasswordRejection::Breached => PasswordRejectionReason::Breached,
        PasswordRejection::Reused => PasswordRejectionReason::Reused,
    }
}

/// 管理コンソール認証。CSRF は web 側で検証済み（ADR-0007 §4）。成功時は SSO セッション id を返す。
pub async fn authenticate_admin(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminAuthenticateRequest>,
) -> Result<Json<InternalAdminAuthenticateResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .login(
            tenant,
            AdminLoginCommand {
                username: req.username,
                password: req.password,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        AdminLoginOutcome::Success { sso_session_id } => {
            InternalAdminAuthenticateResponse::Success {
                sso_session_id,
                sso_absolute_ttl_secs: ttl,
            }
        }
        AdminLoginOutcome::RateLimited => InternalAdminAuthenticateResponse::RateLimited,
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminAuthenticateResponse::InvalidCredentials
        }
        AdminLoginOutcome::Locked => InternalAdminAuthenticateResponse::Locked,
        AdminLoginOutcome::Forbidden => InternalAdminAuthenticateResponse::Forbidden,
        AdminLoginOutcome::PasswordChangeRequired { username } => {
            InternalAdminAuthenticateResponse::PasswordChangeRequired { username }
        }
        AdminLoginOutcome::PolicyDenied => InternalAdminAuthenticateResponse::PolicyDenied,
        AdminLoginOutcome::MfaEnrollmentRequired => {
            InternalAdminAuthenticateResponse::MfaEnrollmentRequired
        }
        AdminLoginOutcome::MfaRequired => InternalAdminAuthenticateResponse::MfaRequired,
        AdminLoginOutcome::WeakPassword(_) => {
            tracing::error!("unexpected WeakPassword outcome from admin authenticate");
            InternalAdminAuthenticateResponse::Internal
        }
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal admin authenticate failed with internal error");
            InternalAdminAuthenticateResponse::Internal
        }
    }))
}

/// エンドユーザー・ポータル認証（`POST /internal/authenticate/portal`）。CSRF は web 側で検証済み。
/// 成功時は SSO セッション id を返す（code/redirect は無い）。TOTP 設定済みなら `mfa_ticket` を返す。
pub async fn authenticate_portal(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalAuthenticateRequest>,
) -> Result<Json<InternalPortalAuthenticateResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .login(
            tenant,
            PortalLoginCommand {
                username: req.username,
                password: req.password,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        PortalLoginOutcome::Success {
            sso_session_id,
            user_language,
        } => InternalPortalAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
            user_language,
        },
        PortalLoginOutcome::MfaRequired { mfa_ticket } => {
            InternalPortalAuthenticateResponse::MfaRequired { mfa_ticket }
        }
        PortalLoginOutcome::EmailVerificationRequired => {
            InternalPortalAuthenticateResponse::EmailVerificationRequired
        }
        PortalLoginOutcome::PasswordChangeRequired { username } => {
            InternalPortalAuthenticateResponse::PasswordChangeRequired { username }
        }
        PortalLoginOutcome::PolicyDenied => InternalPortalAuthenticateResponse::PolicyDenied,
        PortalLoginOutcome::MfaEnrollmentRequired => {
            InternalPortalAuthenticateResponse::MfaEnrollmentRequired
        }
        PortalLoginOutcome::RateLimited => InternalPortalAuthenticateResponse::RateLimited,
        PortalLoginOutcome::InvalidCredentials => {
            InternalPortalAuthenticateResponse::InvalidCredentials
        }
        PortalLoginOutcome::Locked => InternalPortalAuthenticateResponse::Locked,
        PortalLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal authenticate failed with internal error");
            InternalPortalAuthenticateResponse::Internal
        }
    }))
}

/// ポータルの TOTP 検証（`POST /internal/authenticate/portal/mfa`）。`mfa_ticket` ＋ TOTP コードを
/// 検証し、成功時に SSO セッション id を返す。
pub async fn authenticate_portal_mfa(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalMfaRequest>,
) -> Result<Json<InternalPortalMfaResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .verify_mfa(
            tenant,
            PortalMfaCommand {
                mfa_ticket: req.mfa_ticket,
                totp_code: req.totp_code,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        PortalMfaOutcome::Success {
            sso_session_id,
            user_language,
        } => InternalPortalMfaResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
            user_language,
        },
        PortalMfaOutcome::InvalidCode => InternalPortalMfaResponse::InvalidCode,
        PortalMfaOutcome::TicketExpired => InternalPortalMfaResponse::TicketExpired,
        PortalMfaOutcome::PolicyDenied => InternalPortalMfaResponse::PolicyDenied,
        PortalMfaOutcome::RateLimited => InternalPortalMfaResponse::RateLimited,
        PortalMfaOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal mfa failed with internal error");
            InternalPortalMfaResponse::Internal
        }
    }))
}

/// ポータルの強制パスワード変更（`POST /internal/authenticate/portal/change-password`、ADR-0009 §5）。
/// ポータルログインは一時状態を持たないため、現行パスワードを含めフルに再検証する（admin 権限は不要）。
pub async fn authenticate_portal_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPortalChangePasswordRequest>,
) -> Result<Json<InternalPortalChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .portal_login
        .change_password(
            tenant,
            PortalChangePasswordCommand {
                username: req.username,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        PortalChangePasswordOutcome::Success {
            sso_session_id,
            user_language,
        } => InternalPortalChangePasswordResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
            user_language,
        },
        PortalChangePasswordOutcome::MfaRequired { mfa_ticket } => {
            InternalPortalChangePasswordResponse::MfaRequired { mfa_ticket }
        }
        PortalChangePasswordOutcome::PolicyDenied => {
            InternalPortalChangePasswordResponse::PolicyDenied
        }
        PortalChangePasswordOutcome::MfaEnrollmentRequired => {
            InternalPortalChangePasswordResponse::MfaEnrollmentRequired
        }
        PortalChangePasswordOutcome::EmailVerificationRequired => {
            InternalPortalChangePasswordResponse::EmailVerificationRequired
        }
        PortalChangePasswordOutcome::RateLimited => {
            InternalPortalChangePasswordResponse::RateLimited
        }
        PortalChangePasswordOutcome::InvalidCredentials => {
            InternalPortalChangePasswordResponse::InvalidCredentials
        }
        PortalChangePasswordOutcome::Locked => InternalPortalChangePasswordResponse::Locked,
        PortalChangePasswordOutcome::WeakPassword(rejection) => {
            InternalPortalChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        PortalChangePasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal change-password failed with internal error");
            InternalPortalChangePasswordResponse::Internal
        }
    }))
}

/// 管理コンソールの強制パスワード変更（`POST /internal/authenticate/admin/change-password`、
/// ADR-0009 §5）。管理ログインは一時状態を持たないため、現行パスワードを含めフルに再検証する。
pub async fn admin_change_password(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminChangePasswordRequest>,
) -> Result<Json<InternalAdminChangePasswordResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .admin_login
        .change_password(
            tenant,
            AdminChangePasswordCommand {
                username: req.username,
                current_password: req.current_password,
                new_password: req.new_password,
            },
            &ctx,
        )
        .await;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(match outcome {
        AdminLoginOutcome::Success { sso_session_id } => {
            InternalAdminChangePasswordResponse::Success {
                sso_session_id,
                sso_absolute_ttl_secs: ttl,
            }
        }
        AdminLoginOutcome::RateLimited => InternalAdminChangePasswordResponse::RateLimited,
        AdminLoginOutcome::InvalidCredentials => {
            InternalAdminChangePasswordResponse::InvalidCredentials
        }
        AdminLoginOutcome::Locked => InternalAdminChangePasswordResponse::Locked,
        AdminLoginOutcome::Forbidden => InternalAdminChangePasswordResponse::Forbidden,
        AdminLoginOutcome::WeakPassword(rejection) => {
            InternalAdminChangePasswordResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        AdminLoginOutcome::PolicyDenied => InternalAdminChangePasswordResponse::PolicyDenied,
        AdminLoginOutcome::MfaEnrollmentRequired => {
            InternalAdminChangePasswordResponse::MfaEnrollmentRequired
        }
        AdminLoginOutcome::MfaRequired => InternalAdminChangePasswordResponse::MfaRequired,
        AdminLoginOutcome::PasswordChangeRequired { .. } => {
            tracing::error!("unexpected PasswordChangeRequired outcome from admin change-password");
            InternalAdminChangePasswordResponse::Internal
        }
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal admin change-password failed with internal error");
            InternalAdminChangePasswordResponse::Internal
        }
    }))
}

/// ログアウト（`POST /internal/logout`）。web が管理コンソールのログアウトで呼ぶ。SSO セッションを
/// DB から失効させ監査へ記録する（Cookie 失効は web が行う）。不明・不正なセッションは冪等に無視する。
pub async fn logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalLogoutRequest>,
) -> Result<StatusCode, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    state
        .admin_login
        .logout(tenant, &req.sso_session_id, &ctx)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// 定数時間比較（サービストークン照合のタイミング差を避ける）。長さが異なれば即 false。
/// パスワードリセット要求（`POST /internal/password-reset/request`。MT18）。アカウントの有無では
/// 応答を分岐しない（列挙防止はユースケース側の責務）。
pub async fn password_reset_request(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasswordResetRequestRequest>,
) -> Result<Json<InternalPasswordResetRequestResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .password_reset
        .request_reset(tenant, &req.email, &ctx)
        .await;
    Ok(Json(match outcome {
        RequestResetOutcome::Accepted => InternalPasswordResetRequestResponse::Accepted,
        RequestResetOutcome::Unavailable => InternalPasswordResetRequestResponse::Unavailable,
        RequestResetOutcome::RateLimited => InternalPasswordResetRequestResponse::RateLimited,
    }))
}

/// パスワードリセット実行（`POST /internal/password-reset/complete`。MT18）。
pub async fn password_reset_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPasswordResetCompleteRequest>,
) -> Result<Json<InternalPasswordResetCompleteResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .password_reset
        .reset_password(tenant, &req.token, &req.new_password, &ctx)
        .await;
    Ok(Json(match outcome {
        ResetPasswordOutcome::Ok => InternalPasswordResetCompleteResponse::Ok,
        ResetPasswordOutcome::InvalidOrExpired => {
            InternalPasswordResetCompleteResponse::InvalidOrExpired
        }
        ResetPasswordOutcome::WeakPassword(rejection) => {
            InternalPasswordResetCompleteResponse::WeakPassword {
                reason: rejection_reason(&rejection),
            }
        }
        ResetPasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "password reset failed with internal error");
            InternalPasswordResetCompleteResponse::Internal
        }
    }))
}

/// セルフサービスの表示言語変更（`POST /internal/account/update-language`。MT20）。
/// ログイン済みユーザーが SSO セッション経由で自分の言語設定を更新する。
pub async fn account_update_language(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountUpdateLanguageRequest>,
) -> Json<InternalAccountUpdateLanguageResponse> {
    let outcome = state
        .account_language
        .update(UpdateLanguageCommand {
            sso_session_id: req.sso_session_id,
            language: req.language,
        })
        .await;
    Json(match outcome {
        UpdateLanguageOutcome::Ok => InternalAccountUpdateLanguageResponse::Ok,
        UpdateLanguageOutcome::SessionExpired => {
            InternalAccountUpdateLanguageResponse::SessionExpired
        }
        UpdateLanguageOutcome::InvalidLanguage => {
            InternalAccountUpdateLanguageResponse::InvalidLanguage
        }
        UpdateLanguageOutcome::Internal(e) => {
            tracing::error!(error = %e, "account update-language failed with internal error");
            InternalAccountUpdateLanguageResponse::Internal
        }
    })
}

/// セルフサービスのプロフィール取得（`POST /internal/account/profile`）。設定画面が表示名等を
/// 再表示するために SSO セッション経由で本人のプロフィールを取得する（副作用なし）。
pub async fn account_profile(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountProfileRequest>,
) -> Json<InternalAccountProfileResponse> {
    let outcome = state.account_profile.get(&req.sso_session_id).await;
    Json(match outcome {
        ProfileOutcome::Ok {
            name,
            preferred_username,
            email,
            language,
        } => InternalAccountProfileResponse::Ok {
            name,
            preferred_username,
            email,
            language,
        },
        ProfileOutcome::SessionExpired => InternalAccountProfileResponse::SessionExpired,
        ProfileOutcome::Internal(e) => {
            tracing::error!(error = %e, "account profile fetch failed with internal error");
            InternalAccountProfileResponse::Internal
        }
    })
}

/// セルフサービスの表示名更新（`POST /internal/account/update-name`）。ログイン済みユーザーが
/// SSO セッション経由で自分の表示名（`users.name`）を更新する。空・空白のみは解除扱い。
pub async fn account_update_name(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountUpdateNameRequest>,
) -> Json<InternalAccountUpdateNameResponse> {
    let outcome = state
        .account_profile
        .update_name(UpdateNameCommand {
            sso_session_id: req.sso_session_id,
            name: req.name,
        })
        .await;
    Json(match outcome {
        UpdateNameOutcome::Ok => InternalAccountUpdateNameResponse::Ok,
        UpdateNameOutcome::SessionExpired => InternalAccountUpdateNameResponse::SessionExpired,
        UpdateNameOutcome::Invalid => InternalAccountUpdateNameResponse::Invalid,
        UpdateNameOutcome::Internal(e) => {
            tracing::error!(error = %e, "account update-name failed with internal error");
            InternalAccountUpdateNameResponse::Internal
        }
    })
}

/// ログイン中ユーザーの所属テナント列挙（`POST /internal/account/tenants`）。テナント切り替え UI が
/// 切替先候補（`ACTIVE` メンバーシップを持つテナント）を取得するために呼ぶ。
pub async fn account_tenants(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountTenantsRequest>,
) -> Json<InternalAccountTenantsResponse> {
    let outcome = state.account_tenants.list(&req.sso_session_id).await;
    Json(match outcome {
        ListTenantsOutcome::Ok(tenants) => InternalAccountTenantsResponse::Ok {
            tenants: tenants
                .into_iter()
                .map(|t| AccountTenantSummary {
                    tenant_id: t.tenant_id,
                    name: t.name,
                    membership_type: t.membership_type,
                })
                .collect(),
        },
        ListTenantsOutcome::SessionExpired => InternalAccountTenantsResponse::SessionExpired,
        ListTenantsOutcome::Internal(e) => {
            tracing::error!(error = %e, "account tenants list failed with internal error");
            InternalAccountTenantsResponse::Internal
        }
    })
}

/// セルフサービスのセキュリティ画面（`POST /internal/account/security`。G10）。
///
/// ログイン中セッションの一覧と連携済みアプリの一覧を返す。CSRF は web 側で検証済み。
pub async fn account_security(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSecurityRequest>,
) -> Result<Json<InternalAccountSecurityResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .overview(tenant, &req.sso_session_id)
        .await;
    Ok(Json(match outcome {
        SecurityOverviewOutcome::Ok(overview) => InternalAccountSecurityResponse::Ok {
            sessions: overview
                .sessions
                .into_iter()
                .map(|s| AccountSessionSummary {
                    id: s.id,
                    current: s.current,
                    auth_time: s.auth_time.to_rfc3339(),
                    multi_factor: s.multi_factor,
                    user_agent: s.user_agent,
                    ip_address: s.ip_address,
                    created_at: s.created_at.to_rfc3339(),
                    idle_expires_at: s.idle_expires_at.to_rfc3339(),
                    absolute_expires_at: s.absolute_expires_at.to_rfc3339(),
                })
                .collect(),
            connected_apps: overview
                .connected_apps
                .into_iter()
                .map(|a| AccountConnectedAppSummary {
                    client_id: a.client_id,
                    app_name: a.app_name,
                    scopes: a.scopes,
                    granted_at: a.granted_at.to_rfc3339(),
                    updated_at: a.updated_at.to_rfc3339(),
                })
                .collect(),
        },
        SecurityOverviewOutcome::SessionExpired => InternalAccountSecurityResponse::SessionExpired,
        SecurityOverviewOutcome::Internal(e) => {
            tracing::error!(error = %e, "account security overview failed with internal error");
            InternalAccountSecurityResponse::Internal
        }
    }))
}

/// ログイン中セッションの失効（`POST /internal/account/security/revoke-session`。G10）。
pub async fn account_revoke_session(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeSessionRequest>,
) -> Result<Json<InternalAccountRevokeSessionResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .revoke_session(tenant, &req.sso_session_id, &req.session_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeSessionOutcome::Ok => InternalAccountRevokeSessionResponse::Ok,
        RevokeSessionOutcome::NotFound => InternalAccountRevokeSessionResponse::NotFound,
        RevokeSessionOutcome::CurrentSession => {
            InternalAccountRevokeSessionResponse::CurrentSession
        }
        RevokeSessionOutcome::SessionExpired => {
            InternalAccountRevokeSessionResponse::SessionExpired
        }
        RevokeSessionOutcome::Internal(e) => {
            tracing::error!(error = %e, "account session revocation failed with internal error");
            InternalAccountRevokeSessionResponse::Internal
        }
    }))
}

/// 連携済みアプリの解除（`POST /internal/account/security/revoke-consent`。G10）。
pub async fn account_revoke_consent(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeConsentRequest>,
) -> Result<Json<InternalAccountRevokeConsentResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .account_security
        .revoke_consent(tenant, &req.sso_session_id, &req.client_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeConsentOutcome::Ok => InternalAccountRevokeConsentResponse::Ok,
        RevokeConsentOutcome::SessionExpired => {
            InternalAccountRevokeConsentResponse::SessionExpired
        }
        RevokeConsentOutcome::Internal(e) => {
            tracing::error!(error = %e, "account consent revocation failed with internal error");
            InternalAccountRevokeConsentResponse::Internal
        }
    }))
}

/// Step-up の判定（`POST /internal/step-up/check`。AP5）。
///
/// 重要操作の直前に web が呼び、`ChallengeRequired` なら本人確認画面へ誘導する。
pub async fn step_up_check(
    State(state): State<AppState>,
    Json(req): Json<InternalStepUpCheckRequest>,
) -> Result<Json<InternalStepUpCheckResponse>, Response> {
    // テナントは必須（他の `/internal/*` と同じ fail-closed。監査のテナント記録に使う）。
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(operation) = SensitiveOperation::parse(&req.operation) else {
        return Ok(Json(InternalStepUpCheckResponse::UnknownOperation));
    };
    Ok(Json(
        match state.step_up.check(&req.sso_session_id, operation).await {
            StepUpCheckOutcome::Satisfied => InternalStepUpCheckResponse::Satisfied,
            StepUpCheckOutcome::ChallengeRequired {
                second_factor_required,
            } => InternalStepUpCheckResponse::ChallengeRequired {
                second_factor_required,
            },
            StepUpCheckOutcome::SessionExpired => InternalStepUpCheckResponse::SessionExpired,
            StepUpCheckOutcome::Internal(e) => {
                tracing::error!(error = %e, "step-up check failed with internal error");
                InternalStepUpCheckResponse::Internal
            }
        },
    ))
}

/// Step-up の検証（`POST /internal/step-up/verify`。AP5）。CSRF は web 側で検証済み。
pub async fn step_up_verify(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalStepUpVerifyRequest>,
) -> Result<Json<InternalStepUpVerifyResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(operation) = SensitiveOperation::parse(&req.operation) else {
        return Ok(Json(InternalStepUpVerifyResponse::UnknownOperation));
    };
    let outcome = state
        .step_up
        .verify(
            tenant,
            StepUpVerifyCommand {
                sso_session_id: req.sso_session_id,
                operation,
                password: req.password,
                totp_code: req.totp_code,
            },
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        StepUpVerifyOutcome::Ok => InternalStepUpVerifyResponse::Ok,
        StepUpVerifyOutcome::InvalidCredentials => InternalStepUpVerifyResponse::InvalidCredentials,
        StepUpVerifyOutcome::SecondFactorRequired => {
            InternalStepUpVerifyResponse::SecondFactorRequired
        }
        StepUpVerifyOutcome::RateLimited => InternalStepUpVerifyResponse::RateLimited,
        StepUpVerifyOutcome::SessionExpired => InternalStepUpVerifyResponse::SessionExpired,
        StepUpVerifyOutcome::Internal(e) => {
            tracing::error!(error = %e, "step-up verify failed with internal error");
            InternalStepUpVerifyResponse::Internal
        }
    }))
}

/// 登録済み認証器の一覧（`POST /internal/account/authenticators`。AP9）。
pub async fn account_authenticators(
    State(state): State<AppState>,
    Json(req): Json<InternalAuthenticatorsRequest>,
) -> Result<Json<InternalAuthenticatorsResponse>, Response> {
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalAuthenticatorsResponse::SessionExpired));
    };

    let authenticators = match state.authenticators.list(user_id).await {
        Ok(list) => list,
        Err(e) => {
            tracing::error!(error = %e, "authenticator list failed");
            return Ok(Json(InternalAuthenticatorsResponse::Internal));
        }
    };
    let recovery_codes_remaining = match state
        .authenticators
        .usable_recovery_code_count(user_id)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "recovery code count failed");
            return Ok(Json(InternalAuthenticatorsResponse::Internal));
        }
    };

    Ok(Json(InternalAuthenticatorsResponse::Ok {
        authenticators: authenticators
            .into_iter()
            .map(|a| AuthenticatorSummaryResponse {
                id: a.id.to_string(),
                authenticator_type: a.authenticator_type.as_str().to_string(),
                status: a.status.as_str().to_string(),
                label: a.label,
                created_at: a.created_at.to_rfc3339(),
                last_used_at: a.last_used_at.map(|t| t.to_rfc3339()),
            })
            .collect(),
        recovery_codes_remaining,
        phone_registered: state
            .authenticators
            .has_confirmed_phone(user_id)
            .await
            .unwrap_or(false),
        // ゲートウェイ未設定なら登録導線を出さない（登録できても送れない画面を並べない）。
        sms_available: state
            .system_settings
            .sms_gateway()
            .await
            .ok()
            .flatten()
            .is_some_and(|g| g.is_usable()),
    }))
}

/// SMS OTP の送信（`POST /internal/account/sms-otp`。AP13）。
///
/// email OTP と同じく **MFA 待ちの利用者**にだけ送る（未認証の要求で SMS を撃たせない。
/// SMS は 1 通ごとに費用が発生するので、この制限はコストの防御でもある）。
pub async fn account_sms_otp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalSmsOtpRequest>,
) -> Result<Json<InternalSmsOtpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let user_id = match (req.auth_session_id.as_deref(), req.mfa_ticket.as_deref()) {
        (Some(auth_session_id), _) if !auth_session_id.is_empty() => {
            state
                .mfa_login
                .pending_mfa_user(tenant, auth_session_id)
                .await
        }
        (_, Some(ticket)) if !ticket.is_empty() => {
            state.portal_login.pending_mfa_user(tenant, ticket)
        }
        _ => None,
    };
    let Some(user_id) = user_id else {
        return Ok(Json(InternalSmsOtpResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .send_sms_otp(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(()) => InternalSmsOtpResponse::Sent,
            Err(AuthenticatorManagementError::SmsUnavailable) => {
                InternalSmsOtpResponse::Unavailable
            }
            Err(AuthenticatorManagementError::PhoneNotRegistered) => {
                InternalSmsOtpResponse::NotRegistered
            }
            Err(e) => {
                tracing::error!(error = %e, "sms otp send failed");
                InternalSmsOtpResponse::Internal
            }
        },
    ))
}

/// 電話番号の登録開始（`POST /internal/account/phone/register`。AP13）。
/// ログイン済み利用者のセルフサービス操作のため、対象は SSO セッションから解決する。
pub async fn account_phone_register(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPhoneRegistrationRequest>,
) -> Result<Json<InternalPhoneRegistrationResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalPhoneRegistrationResponse::Unauthenticated));
    };

    Ok(Json(
        match state
            .authenticators
            .start_phone_registration(tenant.tenant_id(), user_id, &req.phone_number, &ctx)
            .await
        {
            Ok(()) => InternalPhoneRegistrationResponse::Sent,
            Err(AuthenticatorManagementError::InvalidPhoneNumber) => {
                InternalPhoneRegistrationResponse::InvalidPhoneNumber
            }
            Err(AuthenticatorManagementError::SmsUnavailable) => {
                InternalPhoneRegistrationResponse::Unavailable
            }
            Err(e) => {
                // 電話番号は PII なので、失敗ログにも載せない（エラー側にも含まれない）。
                tracing::error!(error = %e, "phone registration failed");
                InternalPhoneRegistrationResponse::Internal
            }
        },
    ))
}

/// 電話番号の登録確認（`POST /internal/account/phone/confirm`。AP13）。
pub async fn account_phone_confirm(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalPhoneConfirmationRequest>,
) -> Result<Json<InternalPhoneConfirmationResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalPhoneConfirmationResponse::Unauthenticated));
    };

    Ok(Json(
        match state
            .authenticators
            .confirm_phone_registration(tenant.tenant_id(), user_id, &req.code, &ctx)
            .await
        {
            Ok(true) => InternalPhoneConfirmationResponse::Confirmed,
            Ok(false) => InternalPhoneConfirmationResponse::InvalidCode,
            Err(e) => {
                tracing::error!(error = %e, "phone confirmation failed");
                InternalPhoneConfirmationResponse::Internal
            }
        },
    ))
}

/// 認証器の状態変更（`POST /internal/account/authenticators/status`。AP9）。
pub async fn account_authenticator_status(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAuthenticatorStatusRequest>,
) -> Result<Json<InternalAuthenticatorStatusResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(status) = AuthenticatorStatus::parse(&req.status) else {
        return Ok(Json(InternalAuthenticatorStatusResponse::UnknownStatus));
    };
    let Ok(authenticator_id) = uuid::Uuid::parse_str(&req.authenticator_id) else {
        return Ok(Json(InternalAuthenticatorStatusResponse::NotFound));
    };
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalAuthenticatorStatusResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .set_status(tenant.tenant_id(), user_id, authenticator_id, status, &ctx)
            .await
        {
            Ok(()) => InternalAuthenticatorStatusResponse::Ok,
            Err(AuthenticatorManagementError::NotFound) => {
                InternalAuthenticatorStatusResponse::NotFound
            }
            Err(AuthenticatorManagementError::InvalidTransition) => {
                InternalAuthenticatorStatusResponse::InvalidTransition
            }
            Err(e) => {
                tracing::error!(error = %e, "authenticator status change failed");
                InternalAuthenticatorStatusResponse::Internal
            }
        },
    ))
}

/// リカバリーコードの発行（`POST /internal/account/recovery-codes`。AP9）。
///
/// 平文はこの応答でしか返らない。web は 1 度だけ表示し、保存しない。
pub async fn account_recovery_codes(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalRecoveryCodesRequest>,
) -> Result<Json<InternalRecoveryCodesResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Some(user_id) = state
        .admin_access
        .authenticated_user(Some(&req.sso_session_id))
        .await
    else {
        return Ok(Json(InternalRecoveryCodesResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .issue_recovery_codes(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(issued) => InternalRecoveryCodesResponse::Ok {
                codes: issued.codes,
            },
            Err(e) => {
                tracing::error!(error = %e, "recovery code issuance failed");
                InternalRecoveryCodesResponse::Internal
            }
        },
    ))
}

/// email OTP の送信（`POST /internal/account/email-otp`。AP9）。
///
/// **MFA 待ちの利用者**にだけ送る。未認証のリクエストでメール送信を誘発させないため、
/// パスワード検証済みの `auth_session_id`（OIDC）か、署名済みの `mfa_ticket`（ポータル）から
/// 利用者を解決できた場合に限る。
pub async fn account_email_otp(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalEmailOtpRequest>,
) -> Result<Json<InternalEmailOtpResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let user_id = match (req.auth_session_id.as_deref(), req.mfa_ticket.as_deref()) {
        (Some(auth_session_id), _) if !auth_session_id.is_empty() => {
            state
                .mfa_login
                .pending_mfa_user(tenant, auth_session_id)
                .await
        }
        (_, Some(ticket)) if !ticket.is_empty() => {
            state.portal_login.pending_mfa_user(tenant, ticket)
        }
        _ => None,
    };
    let Some(user_id) = user_id else {
        return Ok(Json(InternalEmailOtpResponse::SessionExpired));
    };

    Ok(Json(
        match state
            .authenticators
            .send_email_otp(tenant.tenant_id(), user_id, &ctx)
            .await
        {
            Ok(()) => InternalEmailOtpResponse::Sent,
            Err(AuthenticatorManagementError::MailUnavailable) => {
                InternalEmailOtpResponse::Unavailable
            }
            Err(e) => {
                tracing::error!(error = %e, "email otp delivery failed");
                InternalEmailOtpResponse::Internal
            }
        },
    ))
}

/// 有効な外部 IdP の一覧（`POST /internal/external/providers`。AP10）。
/// ログイン画面のボタンを描くために web が呼ぶ。
pub async fn external_providers(
    State(state): State<AppState>,
    Json(req): Json<InternalExternalProvidersRequest>,
) -> Result<Json<InternalExternalProvidersResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_providers
            .list_enabled_for_tenant(tenant.tenant_id())
            .await
        {
            Ok(providers) => InternalExternalProvidersResponse::Ok {
                providers: providers
                    .into_iter()
                    .map(|p| ExternalIdpButton {
                        provider_code: p.provider_code,
                        display_name: p.display_name,
                    })
                    .collect(),
            },
            Err(e) => {
                tracing::error!(error = %e, "external idp list failed");
                InternalExternalProvidersResponse::Internal
            }
        },
    ))
}

/// 外部 IdP ログインの開始（`POST /internal/external/start`。AP10）。
pub async fn external_start(
    State(state): State<AppState>,
    Json(req): Json<InternalExternalStartRequest>,
) -> Result<Json<InternalExternalStartResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state
            .external_login
            .start(tenant, &req.provider_code, req.auth_session_id)
            .await
        {
            StartOutcome::Redirect { location } => {
                InternalExternalStartResponse::Redirect { location }
            }
            StartOutcome::ProviderUnavailable => InternalExternalStartResponse::ProviderUnavailable,
            StartOutcome::Internal(e) => {
                tracing::error!(error = %e, "external idp login start failed");
                InternalExternalStartResponse::Internal
            }
        },
    ))
}

/// 外部 IdP からのコールバック（`POST /internal/external/callback`。AP10）。
pub async fn external_callback(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalExternalCallbackRequest>,
) -> Result<Json<InternalExternalCallbackResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(
        match state
            .external_login
            .callback(
                tenant,
                CallbackCommand {
                    state: req.state,
                    code: req.code,
                },
                &ctx,
            )
            .await
        {
            CallbackOutcome::Success {
                location,
                sso_session_id,
                user_language,
            } => {
                // 認可フローの続きなら送信先とフォームフィールドの両方を渡す（G12）。
                // 認可フローの外（アカウント設定から始めた連携）は戻り先を web が決める。
                let (redirect_to, form_post) = match location {
                    SuccessLocation::Redirect {
                        location,
                        form_post,
                    } => (Some(location), form_post),
                    SuccessLocation::Account => (None, None),
                };
                InternalExternalCallbackResponse::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs: ttl,
                    redirect_to,
                    form_post,
                    user_language,
                }
            }
            CallbackOutcome::ConsentRequired {
                auth_session_id,
                sso_session_id,
                user_language,
            } => InternalExternalCallbackResponse::ConsentRequired {
                auth_session_id,
                sso_session_id,
                sso_absolute_ttl_secs: ttl,
                user_language,
            },
            CallbackOutcome::StateExpired => InternalExternalCallbackResponse::StateExpired,
            CallbackOutcome::NotLinked => InternalExternalCallbackResponse::NotLinked,
            CallbackOutcome::UserUnavailable => InternalExternalCallbackResponse::UserUnavailable,
            CallbackOutcome::PolicyDenied => InternalExternalCallbackResponse::PolicyDenied,
            CallbackOutcome::ExternalFailure => InternalExternalCallbackResponse::ExternalFailure,
            CallbackOutcome::Internal(e) => {
                tracing::error!(error = %e, "external idp callback failed");
                InternalExternalCallbackResponse::Internal
            }
        },
    ))
}

/// 外部 SAML IdP のアサーションを受け取る（ACS。AP12）。
///
/// 応答の形は OIDC のコールバックと**同じ**（`InternalExternalCallbackResponse`）。プロトコルが
/// 違うのは「誰が認証されたかをどう確かめるか」までで、そこから先の結果は同じだからである。
pub async fn external_saml_acs(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<idp_contracts::auth::InternalExternalSamlAcsRequest>,
) -> Result<Json<InternalExternalCallbackResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let ttl = state.config.sso_absolute_ttl().as_secs();
    Ok(Json(
        match state
            .external_login
            .saml_acs(
                tenant,
                SamlAcsCommand {
                    saml_response: req.saml_response,
                    relay_state: req.relay_state,
                },
                &ctx,
            )
            .await
        {
            CallbackOutcome::Success {
                location,
                sso_session_id,
                user_language,
            } => {
                let (redirect_to, form_post) = match location {
                    SuccessLocation::Redirect {
                        location,
                        form_post,
                    } => (Some(location), form_post),
                    SuccessLocation::Account => (None, None),
                };
                InternalExternalCallbackResponse::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs: ttl,
                    redirect_to,
                    form_post,
                    user_language,
                }
            }
            CallbackOutcome::ConsentRequired {
                auth_session_id,
                sso_session_id,
                user_language,
            } => InternalExternalCallbackResponse::ConsentRequired {
                auth_session_id,
                sso_session_id,
                sso_absolute_ttl_secs: ttl,
                user_language,
            },
            CallbackOutcome::StateExpired => InternalExternalCallbackResponse::StateExpired,
            CallbackOutcome::NotLinked => InternalExternalCallbackResponse::NotLinked,
            CallbackOutcome::UserUnavailable => InternalExternalCallbackResponse::UserUnavailable,
            CallbackOutcome::PolicyDenied => InternalExternalCallbackResponse::PolicyDenied,
            CallbackOutcome::ExternalFailure => InternalExternalCallbackResponse::ExternalFailure,
            CallbackOutcome::Internal(e) => {
                tracing::error!(error = %e, "external saml acs failed");
                InternalExternalCallbackResponse::Internal
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        // 照合そのものは contracts（`internal_auth`）に単一定義してある。ここでは
        // api がその関数を通していることだけを確かめる。
        assert!(service_token_matches("secret-token", "secret-token"));
        assert!(!service_token_matches("secret-token", "secret-tokeN"));
    }

    #[test]
    fn authenticate_response_is_tagged_by_result() {
        let success = InternalAuthenticateResponse::Success {
            form_post: None,
            redirect_to: "https://rp.example.com/cb?code=abc&state=s".to_string(),
            sso_session_id: "sso-123".to_string(),
            sso_absolute_ttl_secs: 86_400,
            user_language: None,
        };
        let json = serde_json::to_value(&success).unwrap();
        assert_eq!(json["result"], "success");
        assert_eq!(json["sso_session_id"], "sso-123");
        assert_eq!(json["sso_absolute_ttl_secs"], 86_400);

        let invalid =
            serde_json::to_value(InternalAuthenticateResponse::InvalidCredentials).unwrap();
        assert_eq!(invalid["result"], "invalid_credentials");
        // 失敗系は判別子以外のフィールドを持たない。
        assert_eq!(invalid.as_object().unwrap().len(), 1);
    }

    #[test]
    fn admin_response_is_tagged_by_result() {
        let forbidden = serde_json::to_value(InternalAdminAuthenticateResponse::Forbidden).unwrap();
        assert_eq!(forbidden["result"], "forbidden");

        let ok = serde_json::to_value(InternalAdminAuthenticateResponse::Success {
            sso_session_id: "sso-9".to_string(),
            sso_absolute_ttl_secs: 3_600,
        })
        .unwrap();
        assert_eq!(ok["result"], "success");
        assert_eq!(ok["sso_session_id"], "sso-9");
    }
}
