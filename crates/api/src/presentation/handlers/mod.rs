//! 各エンドポイントのハンドラ。

pub mod admin;
pub mod admin_audit;
pub mod admin_clients;
pub mod admin_permissions;
pub mod admin_signing_keys;
pub mod admin_users;
pub mod authorize;
pub mod discovery;
pub mod health;
pub mod internal_auth;
pub mod register;
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
/// IP はリバースプロキシ配下を想定して `X-Forwarded-For` の先頭値を使う。
pub(crate) fn request_context(headers: &HeaderMap, correlation: &CorrelationId) -> RequestContext {
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
    RequestContext {
        correlation_id: correlation.0.clone(),
        ip_address,
        user_agent,
    }
}
