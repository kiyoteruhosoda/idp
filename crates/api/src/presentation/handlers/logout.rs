//! RP-initiated Logout の内部 API（`POST /internal/logout/rp`、OIDC RP-initiated Logout 1.0、
//! ADR-0018 決定 2）。
//!
//! `end_session_endpoint` は web（`GET /{tenant_id}/logout`）が受ける。api はブラウザ Cookie を
//! 読まず、web が転送した `sso_session_id`（自ドメインの host-only Cookie 値）とクエリパラメータで
//! 次を担う:
//!
//! 1. `id_token_hint` の検証（署名・issuer）と、SSO セッションの特定・終了（LogoutService）・監査記録。
//! 2. `post_logout_redirect_uri` の検証と `state` 付与済みリダイレクト URL の組み立て。
//! 3. Front-channel logout URI 群（`iss` クエリ付与済み）の列挙。
//!
//! SSO Cookie の破棄と front-channel iframe ページの描画は web が行う。
//!
//! ⚠ **back-channel logout の通知は積まない**（ADR-0055）。SSO セッションは同じ利用者の複数の RP で
//! 共有されており、1 つの RP からのサインアウトで他の RP のセッションまで閉じるのは、利用者が
//! 頼んでいない副作用になる。RP へ知らせるのは、管理者が利用者を止めたときだけである
//! （`stop_announcement`。ADR-0053）。

use crate::application::audit::RequestContext;
use crate::application::logout::LogoutOutcome;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;

/// RP-initiated logout の内部エンドポイント。
pub async fn rp_logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalRpLogoutRequest>,
) -> Result<Json<InternalRpLogoutResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;

    let result = match state
        .logout
        .logout(
            tenant,
            req.sso_session_id.as_deref(),
            req.client_id.as_deref(),
            req.id_token_hint.as_deref(),
            req.post_logout_redirect_uri.as_deref(),
            &ctx,
        )
        .await
    {
        LogoutOutcome::Completed(result) => result,
        // `id_token_hint` が別の利用者を指していた（G12）。セッションは残したままなので、
        // リダイレクトを起こさず、Cookie を消さないことだけを web へ伝える。
        LogoutOutcome::SubjectMismatch => {
            return Ok(Json(InternalRpLogoutResponse::SubjectMismatch))
        }
    };

    // 検証済み post_logout_redirect_uri へ state パラメータを透過的に付与する。
    let redirect_to = result.post_logout_redirect_uri.map(|uri| {
        match req.state.as_deref().filter(|s| !s.is_empty()) {
            Some(state_val) => {
                let sep = if uri.contains('?') { '&' } else { '?' };
                let encoded = percent_encoding::utf8_percent_encode(
                    state_val,
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                format!("{uri}{sep}state={encoded}")
            }
            None => uri,
        }
    });

    Ok(Json(InternalRpLogoutResponse::Ok {
        frontchannel_uris: result.frontchannel_uris,
        redirect_to,
    }))
}
