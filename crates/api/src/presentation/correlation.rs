//! correlation_id (requestId) middleware.
//!
//! Assigns a tracking key per request, shares it via `Extension`, and reflects it in the response's `x-request-id`
//! header. Audit logs (`audit_log.correlation_id`) and HTTP requests can be traced end to end
//! (`CLAUDE.md` "ログ"). If the client sends `x-request-id`, it is carried over
//! only when well-formed.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument as _;
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID_LEN: usize = 64;

/// Per-request tracking key. Handlers receive it as `Extension<CorrelationId>`.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

pub async fn propagate(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| is_valid_request_id(v))
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());

    request.extensions_mut().insert(CorrelationId(id.clone()));

    // Wrap the rest in a span carrying `correlation_id`. For WARN / ERROR emitted by handlers,
    // the ingestion layer picks the tracking key from this span into `log.correlation_id` (CLAUDE.md "ログ").
    // This lets "HTTP request -> error during processing -> audit event" be followed by the same key.
    let span = tracing::info_span!("http_request", correlation_id = %id);
    let mut response = next.run(request).instrument(span).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

fn is_valid_request_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_REQUEST_ID_LEN
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_incoming_request_ids() {
        assert!(is_valid_request_id("abc-123_XYZ"));
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id("has space"));
        assert!(!is_valid_request_id(&"a".repeat(65)));
    }
}
