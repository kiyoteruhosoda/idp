//! correlation_id（requestId）ミドルウェア。
//!
//! リクエストごとに追跡キーを採番して `Extension` で共有し、レスポンスの `x-request-id`
//! ヘッダに反映する。監査ログ（`audit_log.correlation_id`）と HTTP リクエストを一気通貫で
//! 追跡できる（`CLAUDE.md`「ログ」）。クライアントが `x-request-id` を送ってきた場合は
//! 妥当な形式に限り引き継ぐ。

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument as _;
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID_LEN: usize = 64;

/// リクエスト単位の追跡キー。ハンドラは `Extension<CorrelationId>` で受け取る。
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

    // 以降の処理を `correlation_id` 付きのスパンで囲う。ハンドラが出す WARN / ERROR は
    // 取り込み層がこのスパンから追跡キーを拾い、`log.correlation_id` に載せる（CLAUDE.md「ログ」）。
    // web は同じ id を api へも転送するため、web 側のエラーと api 側の記録が同じキーで並ぶ。
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
