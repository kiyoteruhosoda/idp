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
use crate::application::admin_login::{
    AdminChangePasswordCommand, AdminLoginCommand, AdminLoginOutcome,
};
use crate::application::audit::RequestContext;
use crate::application::change_password::{ChangePasswordCommand, ChangePasswordOutcome};
use crate::application::login::{LoginCommand, LoginOutcome};
use crate::application::password_reset::{RequestResetOutcome, ResetPasswordOutcome};
use crate::application::portal_login::{
    PortalLoginCommand, PortalLoginOutcome, PortalMfaCommand, PortalMfaOutcome,
};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::auth::{
    InternalAccountChangePasswordRequest, InternalAccountChangePasswordResponse,
    InternalAccountUpdateLanguageRequest, InternalAccountUpdateLanguageResponse,
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalChangePasswordRequest,
    InternalChangePasswordResponse, InternalLogoutRequest, InternalPasswordResetCompleteRequest,
    InternalPasswordResetCompleteResponse, InternalPasswordResetRequestRequest,
    InternalPasswordResetRequestResponse, InternalPortalAuthenticateRequest,
    InternalPortalAuthenticateResponse, InternalPortalMfaRequest, InternalPortalMfaResponse,
};

/// 内部サービス認証トークンを載せるヘッダ名（小文字。`HeaderMap` は大小無視で引ける）。
const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

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
    if !constant_time_eq(
        presented.as_bytes(),
        state.config.internal_service_token().as_bytes(),
    ) {
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
            sso_session_id,
            user_language,
        } => InternalAuthenticateResponse::Success {
            redirect_to: location,
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
        AccountPasswordOutcome::WeakPassword => InternalAccountChangePasswordResponse::WeakPassword,
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
            sso_session_id,
        } => InternalChangePasswordResponse::Success {
            redirect_to: location,
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
        ChangePasswordOutcome::SessionExpired => InternalChangePasswordResponse::SessionExpired,
        ChangePasswordOutcome::CsrfMismatch => InternalChangePasswordResponse::CsrfMismatch,
        ChangePasswordOutcome::InvalidCurrentPassword => {
            InternalChangePasswordResponse::InvalidCurrentPassword
        }
        ChangePasswordOutcome::WeakPassword => InternalChangePasswordResponse::WeakPassword,
        ChangePasswordOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal change-password failed with internal error");
            InternalChangePasswordResponse::Internal
        }
    }))
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
        AdminLoginOutcome::WeakPassword => {
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
        PortalLoginOutcome::PasswordChangeRequired => {
            InternalPortalAuthenticateResponse::PasswordChangeRequired
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
        PortalMfaOutcome::RateLimited => InternalPortalMfaResponse::RateLimited,
        PortalMfaOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal portal mfa failed with internal error");
            InternalPortalMfaResponse::Internal
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
        AdminLoginOutcome::WeakPassword => InternalAdminChangePasswordResponse::WeakPassword,
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    state
        .admin_login
        .logout(tenant, &req.sso_session_id, &ctx)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// 定数時間比較（サービストークン照合のタイミング差を避ける）。長さが異なれば即 false。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;
    let outcome = state
        .password_reset
        .reset_password(tenant, &req.token, &req.new_password, &ctx)
        .await;
    Ok(Json(match outcome {
        ResetPasswordOutcome::Ok => InternalPasswordResetCompleteResponse::Ok,
        ResetPasswordOutcome::InvalidOrExpired => {
            InternalPasswordResetCompleteResponse::InvalidOrExpired
        }
        ResetPasswordOutcome::WeakPassword => InternalPasswordResetCompleteResponse::WeakPassword,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-tokeN"));
        assert!(!constant_time_eq(b"secret", b"secret-token"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn authenticate_response_is_tagged_by_result() {
        let success = InternalAuthenticateResponse::Success {
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
