//! RP-initiated Logout エンドポイント（`GET /logout`、OIDC RP-initiated Logout 1.0）。
//!
//! パラメータ:
//! - `id_token_hint`: 失効対象の ID Token（任意。現実装では iss/sub の参考に使う）。
//! - `post_logout_redirect_uri`: ログアウト後のリダイレクト先（登録済みのもののみ許可）。
//! - `state`: RP が受け取るランダム値（redirect_uri に透過的に付与）。
//! - `client_id`: post_logout_redirect_uri の検証に使う（任意）。
//!
//! 処理フロー:
//! 1. SSO Cookie からセッションを特定・終了（LogoutService）。
//! 2. SSO Cookie を失効。
//! 3. Back-channel logout: 登録クライアントの backchannel_logout_uri へ logout_token JWT を POST（非同期）。
//! 4. Front-channel logout: frontchannel_logout_uri を持つクライアント向けの iframe ページを返す。
//! 5. post_logout_redirect_uri が指定・検証済みなら 302 リダイレクト。

use crate::application::key_service::KeyService;
use crate::application::logout::BackchannelTarget;
use crate::infrastructure::jwt;
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::handlers::{found, request_context};
use crate::presentation::state::AppState;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
}

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

/// RP-initiated logout エンドポイント。
#[utoipa::path(
    get,
    path = "/logout",
    tag = "oidc",
    params(
        ("id_token_hint" = Option<String>, Query, description = "失効対象の ID Token（任意）"),
        ("post_logout_redirect_uri" = Option<String>, Query, description = "ログアウト後のリダイレクト先"),
        ("state" = Option<String>, Query, description = "RP が受け取るランダム値"),
        ("client_id" = Option<String>, Query, description = "クライアント ID（redirect URI 検証用）"),
    ),
    responses(
        (status = 200, description = "ログアウト成功（front-channel: iframe ページ）"),
        (status = 302, description = "ログアウト成功（post_logout_redirect_uri へリダイレクト）"),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Query(params): Query<LogoutParams>,
) -> Response {
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());

    // SSO Cookie を読む。
    let sso_session_id = cookies::get(&headers, cookies::SSO_SESSION_COOKIE);

    let result = state
        .logout
        .logout(
            sso_session_id.as_deref(),
            params.client_id.as_deref(),
            params.post_logout_redirect_uri.as_deref(),
            &ctx,
        )
        .await;

    // SSO Cookie を失効させる。
    let expire_cookie = cookies::expire(cookies::SSO_SESSION_COOKIE, state.config.cookie_secure());

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

    // post_logout_redirect_uri の構築（state パラメータを付与）。
    let redirect_to = result.post_logout_redirect_uri.map(|uri| {
        if let Some(state_val) = &params.state {
            if !state_val.is_empty() {
                let sep = if uri.contains('?') { '&' } else { '?' };
                let encoded = percent_encoding::utf8_percent_encode(
                    state_val,
                    percent_encoding::NON_ALPHANUMERIC,
                )
                .to_string();
                return format!("{uri}{sep}state={encoded}");
            }
        }
        uri
    });

    // Front-channel logout がある場合は iframe HTML を返す。
    if !result.frontchannel_uris.is_empty() {
        let html = build_frontchannel_html(&result.frontchannel_uris, redirect_to.as_deref());
        return (
            StatusCode::OK,
            [(header::SET_COOKIE, expire_cookie)],
            Html(html),
        )
            .into_response();
    }

    // Front-channel なし: redirect or 200。
    if let Some(uri) = redirect_to {
        let mut resp = found(&uri).into_response();
        resp.headers_mut().insert(
            header::SET_COOKIE,
            expire_cookie.parse().unwrap_or_else(|_| {
                axum::http::HeaderValue::from_static("")
            }),
        );
        resp
    } else {
        (StatusCode::NO_CONTENT, [(header::SET_COOKIE, expire_cookie)]).into_response()
    }
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

/// front-channel logout 用 HTML（iframe ページ）を構築する。
/// 全 iframe のロード後、`redirect_uri` に JS でリダイレクトする。
fn build_frontchannel_html(uris: &[String], redirect_to: Option<&str>) -> String {
    let iframes: String = uris
        .iter()
        .map(|uri| {
            let escaped = html_escape(uri);
            format!(r#"<iframe src="{escaped}" style="display:none;width:0;height:0;" sandbox="allow-same-origin allow-scripts"></iframe>"#)
        })
        .collect::<Vec<_>>()
        .join("\n");

    let redirect_script = if let Some(uri) = redirect_to {
        let escaped = js_escape(uri);
        format!(
            r#"<script>
var loaded = 0;
var total = document.querySelectorAll('iframe').length;
function onIframeLoad() {{ loaded++; if (loaded >= total) {{ window.location.href = '{escaped}'; }} }}
var frames = document.querySelectorAll('iframe');
if (frames.length === 0) {{ window.location.href = '{escaped}'; }}
else {{ frames.forEach(function(f) {{ f.onload = onIframeLoad; }}); }}
</script>"#
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Logout</title></head>
<body>
{iframes}
{redirect_script}
</body>
</html>"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
