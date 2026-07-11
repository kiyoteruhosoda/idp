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

use crate::application::admin_login::{AdminLoginCommand, AdminLoginOutcome};
use crate::application::audit::RequestContext;
use crate::application::login::{LoginCommand, LoginOutcome};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::internal_tenant;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use idp_contracts::admin::RootTenantResponse;
use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalLogoutRequest,
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
) -> Json<InternalAuthenticateResponse> {
    // 接続元情報は web が転送する（api はプロキシ直下ではないため自前で X-Forwarded-For を見ない）。
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = internal_tenant(&state, req.tenant_id.as_deref());
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
    Json(match outcome {
        LoginOutcome::Success {
            location,
            sso_session_id,
        } => InternalAuthenticateResponse::Success {
            redirect_to: location,
            sso_session_id,
            sso_absolute_ttl_secs: ttl,
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
        LoginOutcome::SessionExpired => InternalAuthenticateResponse::SessionExpired,
        LoginOutcome::CsrfMismatch => InternalAuthenticateResponse::CsrfMismatch,
        LoginOutcome::RateLimited => InternalAuthenticateResponse::RateLimited,
        LoginOutcome::InvalidCredentials => InternalAuthenticateResponse::InvalidCredentials,
        LoginOutcome::Locked => InternalAuthenticateResponse::Locked,
        LoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal authenticate failed with internal error");
            InternalAuthenticateResponse::Internal
        }
    })
}

/// 管理コンソール認証。CSRF は web 側で検証済み（ADR-0007 §4）。成功時は SSO セッション id を返す。
pub async fn authenticate_admin(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAdminAuthenticateRequest>,
) -> Json<InternalAdminAuthenticateResponse> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = internal_tenant(&state, req.tenant_id.as_deref());
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
    Json(match outcome {
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
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "internal admin authenticate failed with internal error");
            InternalAdminAuthenticateResponse::Internal
        }
    })
}

/// ログアウト（`POST /internal/logout`）。web が管理コンソールのログアウトで呼ぶ。SSO セッションを
/// DB から失効させ監査へ記録する（Cookie 失効は web が行う）。不明・不正なセッションは冪等に無視する。
pub async fn logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalLogoutRequest>,
) -> StatusCode {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant = internal_tenant(&state, req.tenant_id.as_deref());
    state
        .admin_login
        .logout(tenant, &req.sso_session_id, &ctx)
        .await;
    StatusCode::NO_CONTENT
}

/// root テナント UUID を返す（`GET /internal/root-tenant`、ADR-0009 §7）。web が起動時／初回に解決し、
/// `/{tenant_id}/admin/*` パスの前置に使う（過渡期。root UUID は環境毎に動的採番のため設定に埋めない）。
/// api は起動時に root を `default_tenant` として解決済みのため、それをそのまま返す。
pub async fn root_tenant(State(state): State<AppState>) -> Json<RootTenantResponse> {
    Json(RootTenantResponse {
        tenant_id: state.default_tenant.tenant_id().to_string(),
    })
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
