//! セキュリティヘッダミドルウェア（SEC3。api の `security_headers` と同方針）。
//!
//! web は HTML（ログイン画面・管理コンソール）を配信するため、全レスポンスに以下を付与する:
//! - `X-Content-Type-Options: nosniff`
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `X-Frame-Options: DENY`（クリックジャッキング対策）
//! - `Content-Security-Policy`（`frame-ancestors 'none'`・外部オリジン読み込み禁止）
//!
//! さらに `hsts_max_age > 0` のときは `Strict-Transport-Security` を付与する。
//!
//! CSP の `script-src`/`style-src` に `'unsafe-inline'` を許容しているのは、現行テンプレート
//! （login / passkey_register のインライン `<script>`、各画面のインライン `<style>`）のため。
//! nonce 化してインライン許容を外すのは後続改善とする。

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// 自オリジン限定 + インライン許容（現行テンプレート互換）の CSP。
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// セキュリティヘッダを付与するミドルウェアファクトリ。`hsts_max_age` が `0` のときは HSTS を付与しない。
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
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    // ハンドラが応答に CSP を設定済みの場合は尊重する（RP-initiated logout の front-channel ページが
    // 通知先オリジンだけ `frame-src` を許可した CSP を使う。`handlers::rp_logout`）。
    let csp = HeaderName::from_static("content-security-policy");
    if !headers.contains_key(&csp) {
        headers.insert(csp, HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    }

    if hsts_max_age > 0 {
        if let Ok(value) = HeaderValue::from_str(&format!("max-age={hsts_max_age}")) {
            headers.insert(HeaderName::from_static("strict-transport-security"), value);
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn respond(app: Router, uri: &str) -> Response {
        app.oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    fn app(hsts_max_age: u64) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                add_security_headers(req, next, hsts_max_age)
            }))
    }

    #[tokio::test]
    async fn adds_security_headers_to_every_response() {
        let res = respond(app(0), "/").await;
        let headers = res.headers();
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(
            headers["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("default-src 'self'"));
        // HSTS は hsts_max_age = 0 では付与しない。
        assert!(!headers.contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn adds_hsts_when_max_age_is_positive() {
        let res = respond(app(31_536_000), "/").await;
        assert_eq!(
            res.headers()["strict-transport-security"],
            "max-age=31536000"
        );
    }
}
