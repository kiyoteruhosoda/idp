//! セキュリティヘッダミドルウェア（S1）。
//!
//! すべてのレスポンスに以下を付与する:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY`（画面を出さずに試す往復の 302 だけは設定した親の枠を許す。task #888）
//!
//! さらに `hsts_max_age > 0` のときは `Strict-Transport-Security` を付与する。

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// 画面を出さずに試す往復（`prompt=none`）の 302 を、設定した親の枠に入れてよくする（task #888・ADR-0076）。
/// 親が空なら何もしない。⚠ 描く応答には使わない（302 だけ）。
pub fn allow_silent_auth_framing(
    response: &mut Response,
    ancestors: &assay_contracts::frame_ancestors::FrameAncestors,
) {
    let Some(policy) = ancestors.content_security_policy() else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_SECURITY_POLICY, value);
    }
}

/// 応答の CSP が枠を許しているか。許しているなら `X-Frame-Options: DENY` を足さない。
fn csp_allows_framing(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|csp| {
            csp.contains("frame-ancestors") && !csp.contains("frame-ancestors 'none'")
        })
}

/// セキュリティヘッダを付与するミドルウェアファクトリ。
///
/// `hsts_max_age` が `0` のときは HSTS ヘッダを付与しない。
pub async fn add_security_headers(request: Request, next: Next, hsts_max_age: u64) -> Response {
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
    // 画面を出さずに試す往復の 302 だけは枠を許す（`allow_silent_auth_framing`。task #888）
    if !csp_allows_framing(headers) {
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
    }

    if hsts_max_age > 0 {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={hsts_max_age}")) {
            headers.insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}
