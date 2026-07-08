//! 各エンドポイントのハンドラ。

pub mod admin;
pub mod admin_audit;
pub mod admin_clients;
pub mod admin_permissions;
pub mod admin_signing_keys;
pub mod admin_users;
pub mod authorize;
pub mod consent;
pub mod discovery;
pub mod health;
pub mod internal_auth;
pub mod introspect;
pub mod logout;
pub mod register;
pub mod revoke;
pub mod token;
pub mod userinfo;

use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use axum::http::header::{HeaderValue, LOCATION, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

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

/// リクエストヘッダから監査コンテキストを組み立てる。
///
/// `trust_forwarded` が `true` のときのみ `X-Forwarded-For` を信頼して実 IP を採用する。
/// `false` のときはフォワードヘッダを無視する（ヘッダ偽装対策; S1）。
/// 接続元ソケット IP を直接取得するには `ConnectInfo` extractor が必要なため、ここでは
/// 信頼設定が無効の場合 `ip_address = None` となる（監査ログに IP が記録されない）。
pub(crate) fn request_context(
    headers: &HeaderMap,
    correlation: &CorrelationId,
    trust_forwarded: bool,
) -> RequestContext {
    let ip_address = if trust_forwarded {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    } else {
        None
    };
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    RequestContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}
