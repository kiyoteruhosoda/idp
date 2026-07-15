//! web のハンドラ。

pub mod admin_clients_console;
pub mod admin_console;
pub mod admin_invitations_console;
pub mod admin_members_console;
pub mod admin_settings;
pub mod admin_signing_keys_console;
pub mod admin_status_console;
pub mod admin_tenants_console;
pub mod admin_users_console;
pub mod consent;
pub mod health;
pub mod invitation_accept;
pub mod login;
pub mod mfa_totp;
pub mod passkey;
pub mod password_change;
pub mod password_reset;
pub mod react_assets;
pub mod user_settings;
pub mod verify_email;

use crate::correlation::CorrelationId;
use axum::http::header::USER_AGENT;
use axum::http::header::{HeaderValue, LOCATION};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// 内部認証呼び出しへ転送する接続元情報。
pub(crate) struct ForwardedContext {
    pub correlation_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// ブラウザからのリクエストヘッダを解釈し、api へ転送する接続元情報を組み立てる。
/// IP はリバースプロキシ配下を想定して `X-Forwarded-For` の先頭値を使う。
pub(crate) fn forwarded_context(
    headers: &HeaderMap,
    correlation: &CorrelationId,
) -> ForwardedContext {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    ForwardedContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}

/// `302 Found` リダイレクト（設計仕様 §4.2。axum の `Redirect::to` は 303 のため使わない）。
pub(crate) fn found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => (StatusCode::FOUND, [(LOCATION, value)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redirect location is not a valid header value");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
