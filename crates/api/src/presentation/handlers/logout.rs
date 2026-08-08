//! RP-initiated Logout の内部 API（`POST /internal/logout/rp`、OIDC RP-initiated Logout 1.0、
//! ADR-0018 決定 2）。
//!
//! `end_session_endpoint` は web（`GET /{tenant_id}/logout`）が受ける。api はブラウザ Cookie を
//! 読まず、web が転送した `sso_session_id`（自ドメインの host-only Cookie 値）とクエリパラメータで
//! 次を担う:
//!
//! 1. SSO セッションの特定・終了（LogoutService）と監査記録。
//! 2. Back-channel logout: 登録クライアントの backchannel_logout_uri へ logout_token JWT を POST（非同期）。
//! 3. `post_logout_redirect_uri` の検証と `state` 付与済みリダイレクト URL の組み立て。
//! 4. Front-channel logout URI 群（`iss` クエリ付与済み）の列挙。
//!
//! SSO Cookie の破棄と front-channel iframe ページの描画は web が行う。

use crate::application::audit::RequestContext;
use crate::application::key_service::KeyService;
use crate::application::logout::BackchannelTarget;
use crate::infrastructure::jwt;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use idp_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

/// back-channel logout token のクレーム（OpenID Back-Channel Logout 1.0）。
#[derive(Debug, Serialize)]
struct LogoutTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    jti: String,
    events: serde_json::Value,
}

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
            req.post_logout_redirect_uri.as_deref(),
            &ctx,
        )
        .await;

    // Back-channel logout: 各クライアントへ logout_token を非同期送信。
    if !result.backchannel_targets.is_empty() {
        if let Some(user_sub) = result.user_sub.clone() {
            let targets = result.backchannel_targets.clone();
            let keys = state.keys.clone();
            let issuer = state.config.issuer().to_string();
            tokio::spawn(async move {
                send_backchannel_logout_tokens(targets, &user_sub, &issuer, &keys).await;
            });
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

/// back-channel logout token を各クライアントへ POST する。
async fn send_backchannel_logout_tokens(
    targets: Vec<BackchannelTarget>,
    user_sub: &str,
    issuer: &str,
    keys: &Arc<KeyService>,
) {
    // 現在の署名鍵を取得。
    let active_key = match keys.active_signing_key().await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "no active signing key for back-channel logout tokens");
            return;
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let now = chrono::Utc::now().timestamp();

    for target in &targets {
        // 送信直前にも宛先を検査する（SEC2）。登録時の検証（`client_management`）だけでは、
        // 検証導入より前に登録された行や DB を直接編集された行が素通りしてしまう。
        if crate::domain::outbound_uri::is_internal_destination(&target.backchannel_logout_uri) {
            tracing::warn!(
                client_id = %target.client_id,
                "skipped back-channel logout: the registered URI points at an internal destination"
            );
            continue;
        }

        let claims = LogoutTokenClaims {
            iss: issuer.to_string(),
            sub: user_sub.to_string(),
            aud: target.client_id.clone(),
            iat: now,
            jti: Uuid::new_v4().to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        };

        let logout_token = match jwt::sign(
            &active_key.private_pem,
            &active_key.kid,
            "logout+jwt",
            &active_key.algorithm,
            &claims,
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    client_id = %target.client_id,
                    "failed to sign back-channel logout token"
                );
                continue;
            }
        };

        let url = target.backchannel_logout_uri.clone();
        let client = client.clone();
        tokio::spawn(async move {
            match client
                .post(&url)
                .form(&[("logout_token", &logout_token)])
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!(
                            status = %resp.status(),
                            url = %url,
                            "back-channel logout endpoint returned non-2xx"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, url = %url, "back-channel logout request failed");
                }
            }
        });
    }
}
