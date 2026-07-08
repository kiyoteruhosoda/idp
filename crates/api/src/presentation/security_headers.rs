//! セキュリティヘッダミドルウェア（S1）。
//!
//! すべてのレスポンスに以下を付与する:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY`
//!
//! さらに `hsts_max_age > 0` のときは `Strict-Transport-Security` を付与する。

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::http::header::{HeaderValue, HeaderName};

/// セキュリティヘッダを付与するミドルウェアファクトリ。
///
/// `hsts_max_age` が `0` のときは HSTS ヘッダを付与しない。
pub async fn add_security_headers(
    request: Request,
    next: Next,
    hsts_max_age: u64,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );

    if hsts_max_age > 0 {
        if let Ok(value) =
            HeaderValue::from_str(&format!("max-age={hsts_max_age}"))
        {
            headers.insert(
                HeaderName::from_static("strict-transport-security"),
                value,
            );
        }
    }

    response
}
