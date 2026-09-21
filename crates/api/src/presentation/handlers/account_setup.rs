//! アカウント設定リンクの内部 API（`/internal/account-setup/*`。ADR-0062）。
//!
//! 管理者が発行したワンタイムリンクを開いた画面（web）が呼ぶ。⚠ **`describe` は読むだけで
//! 消費しない** —— リンクはチャットで渡ることが多く、相手より先にプレビューの bot が取りに来る。
//! 消費するのは資格情報を実際に決める操作（パスキーの完了・パスワードの設定）だけである。
//!
//! パスワードを設定する経路は専用に作らない。⚠ **同じ表のトークンなので、忘失時の再設定
//! （`/internal/password-reset/complete`）がそのまま通る** —— 同じことをする口を 2 つ置くと、
//! ポリシー検証・セッション失効・監査のどれかが片方だけ古くなる。
//!
//! すべて `/internal/*` ルータに属し、サービス認証トークンで保護される。

use crate::application::account_setup::AccountSetupError;
use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalAccountSetupDescribeRequest, InternalAccountSetupDescribeResponse,
    InternalAccountSetupPasskeyBeginRequest, InternalAccountSetupPasskeyBeginResponse,
    InternalAccountSetupPasskeyCompleteRequest, InternalAccountSetupPasskeyCompleteResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// リンクの中身を読む（`POST /internal/account-setup/describe`）。消費しない。
pub async fn describe(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSetupDescribeRequest>,
) -> Result<Json<InternalAccountSetupDescribeResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state.account_setup.describe(tenant, &req.token).await {
            Ok(view) => InternalAccountSetupDescribeResponse::Ok {
                allows_passkey: view.allows_passkey_registration(),
                expires_at: view.expires_at.to_rfc3339(),
                email: view.email,
            },
            Err(AccountSetupError::InvalidOrExpired | AccountSetupError::NotAllowed) => {
                InternalAccountSetupDescribeResponse::InvalidOrExpired
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup describe error");
                InternalAccountSetupDescribeResponse::Internal
            }
        },
    ))
}

/// パスキー登録の開始（`POST /internal/account-setup/passkey/begin`）。
pub async fn passkey_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSetupPasskeyBeginRequest>,
) -> Result<Json<InternalAccountSetupPasskeyBeginResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state.account_setup.begin_passkey(tenant, &req.token).await {
            Ok((challenge_id, options)) => InternalAccountSetupPasskeyBeginResponse::Ok {
                challenge_id: challenge_id.to_string(),
                options,
            },
            Err(AccountSetupError::InvalidOrExpired) => {
                InternalAccountSetupPasskeyBeginResponse::InvalidOrExpired
            }
            Err(AccountSetupError::NotAllowed) => {
                InternalAccountSetupPasskeyBeginResponse::NotAllowed
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup passkey begin error");
                InternalAccountSetupPasskeyBeginResponse::Internal
            }
        },
    ))
}

/// パスキー登録の完了（`POST /internal/account-setup/passkey/complete`）。成功でリンクを消費する。
pub async fn passkey_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountSetupPasskeyCompleteRequest>,
) -> Result<Json<InternalAccountSetupPasskeyCompleteResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(challenge_id) = Uuid::parse_str(&req.challenge_id) else {
        // 形の違う値は、期限切れのチャレンジと同じ扱いにする（当たりを与えない）。
        return Ok(Json(
            InternalAccountSetupPasskeyCompleteResponse::InvalidOrExpired,
        ));
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    Ok(Json(
        match state
            .account_setup
            .complete_passkey(
                tenant,
                &req.token,
                challenge_id,
                &req.name,
                req.credential,
                &ctx,
            )
            .await
        {
            Ok(()) => InternalAccountSetupPasskeyCompleteResponse::Ok,
            Err(AccountSetupError::InvalidOrExpired) => {
                InternalAccountSetupPasskeyCompleteResponse::InvalidOrExpired
            }
            Err(AccountSetupError::NotAllowed) => {
                InternalAccountSetupPasskeyCompleteResponse::NotAllowed
            }
            Err(AccountSetupError::InvalidCredential(reason)) => {
                tracing::warn!(reason = %reason, "account setup passkey rejected");
                InternalAccountSetupPasskeyCompleteResponse::InvalidCredential
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup passkey complete error");
                InternalAccountSetupPasskeyCompleteResponse::Internal
            }
        },
    ))
}
