//! RP-initiated Logout の内部 API（`POST /internal/logout/rp`、OIDC RP-initiated Logout 1.0、
//! ADR-0018 決定 2）。
//!
//! `end_session_endpoint` は web（`GET /{tenant_id}/logout`）が受ける。api はブラウザ Cookie を
//! 読まず、web が転送した `sso_session_id`（自ドメインの host-only Cookie 値）とクエリパラメータで
//! 次を担う:
//!
//! 1. `id_token_hint` の検証（署名・issuer）と、SSO セッションの特定・終了（LogoutService）・監査記録。
//! 2. Back-channel logout: 通知要求を永続キューへ積む（送信はワーカー。G5）。
//! 3. `post_logout_redirect_uri` の検証と `state` 付与済みリダイレクト URL の組み立て。
//! 4. Front-channel logout URI 群（`iss` クエリ付与済み）の列挙。
//!
//! SSO Cookie の破棄と front-channel iframe ページの描画は web が行う。
//!
//! 通知の送信をこのリクエスト内で行わないのは意図的（G5）。従来は `tokio::spawn` で撃ちっぱなしに
//! していたため、非 2xx もプロセス再起動も黙って通知を失っていた。要求を行として残し、再試行付きの
//! ワーカー（`BackchannelLogoutDeliveryService`）に送信させる。

use crate::application::audit::RequestContext;
use crate::application::backchannel_logout::LogoutNotification;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use idp_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};

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
    let tenant = require_internal_tenant(req.tenant_id.as_deref())?;

    let result = state
        .logout
        .logout(
            tenant,
            req.sso_session_id.as_deref(),
            req.client_id.as_deref(),
            req.id_token_hint.as_deref(),
            req.post_logout_redirect_uri.as_deref(),
            &ctx,
        )
        .await;

    // Back-channel logout: 通知要求をキューへ積む（送信はワーカー。G5）。ここで HTTP を打つと、
    // 落ちている RP のタイムアウトぶんだけ利用者のログアウト応答が遅れる。
    if !result.backchannel_targets.is_empty() {
        if let Some(user_sub) = result.user_sub.as_deref() {
            let notifications: Vec<LogoutNotification> = result
                .backchannel_targets
                .iter()
                .map(|t| LogoutNotification {
                    client_id: t.client_id.clone(),
                    backchannel_logout_uri: t.backchannel_logout_uri.clone(),
                })
                .collect();
            if let Err(e) = state
                .backchannel_logout
                .enqueue(
                    tenant.tenant_id(),
                    user_sub,
                    result.sid.as_deref(),
                    &notifications,
                )
                .await
            {
                // 積めなかった通知は復旧できない。ログアウト自体は成立しているので応答は返すが、
                // RP 側にセッションが残るため ERROR として残す。
                tracing::error!(error = %e, "failed to enqueue back-channel logout notifications");
            }
        }
    }

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
