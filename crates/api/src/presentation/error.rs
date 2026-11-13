//! Error representation of the HTTP API. Converts domain / use-case errors to HTTP status and JSON.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    /// Rate limit exceeded (429, SEC6).
    TooManyRequests(String),
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &str) {
        match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request", m),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", m),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
            Self::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", m),
            Self::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", m),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        // Internal error details are not leaked to the client, only logged. The 500 body is not translated
        // (the user has no action to take, and it would only add locale-resolution paths. MT19. See
        // the module comment "Not translated" in `presentation::i18n`).
        let body = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %message, "internal server error");
            json!({ "error": code, "message": "internal server error" })
        } else {
            json!({ "error": code, "message": message })
        };
        (status, Json(body)).into_response()
    }
}
