//! HTTP API のエラー表現。ドメイン／ユースケースのエラーを HTTP ステータスと JSON に変換する。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Conflict(String),
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &str) {
        match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", m),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        // 内部エラーの詳細はクライアントに漏らさず、ログにのみ残す。
        let body = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %message, "internal server error");
            json!({ "error": code, "message": "internal server error" })
        } else {
            json!({ "error": code, "message": message })
        };
        (status, Json(body)).into_response()
    }
}
