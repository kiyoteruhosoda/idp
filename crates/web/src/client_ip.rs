//! Determining the client IP (SEC1).
//!
//! Since ADR-0018 the entry point for sign-in is web. The IP that web assembles goes to api in the body of
//! `/internal/authenticate*` and **becomes the IP for api's sign-in rate limiter and the audit log**. So if
//! web trusted `X-Forwarded-For` unconditionally, api's `TRUST_FORWARDED_HEADERS` gate
//! (`request_context` in `crates/api/src/presentation/handlers/mod.rs`) would be bypassed on the sign-in path:
//!
//! - Change the header every time → slip past the per-IP rate limit (default 30 attempts / 5 min).
//! - Send no header → the IP becomes `None` and the rate-limit check is not performed at all.
//! - Send an arbitrary value → pollute the audit log's `ip_address`.
//!
//! So it is gated with **the same setting key and the same default** as api (`TRUST_FORWARDED_HEADERS`,
//! default `false`), and when untrusted it falls back to the TCP peer address ([`axum::extract::ConnectInfo`]).
//! Even when trusted, it takes the **rightmost** value (the peer appended by the trusted proxy), not the
//! leftmost client-declared one (the derivation lives in [`assay_contracts::forwarded`], shared with api).
//! api has no equivalent of `ConnectInfo` (its calls are server-to-server from web, so the peer is always web),
//! so only web has a fallback.
//!
//! The decision is made in one place, the middleware, and the result is passed to handlers via `Extension`.
//! If each handler read the header, gates would get forgotten as screens are added.

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

/// The client IP of this request. Handlers receive it as `Extension<ClientIp>`.
///
/// `None` = could not be determined (untrusted configuration with no `ConnectInfo` either; this happens when
/// tests call the router directly). The audit log IP is then empty and the per-IP rate limit does not apply.
#[derive(Debug, Clone, Default)]
pub struct ClientIp(pub Option<String>);

/// Middleware that determines the client IP and puts it into `Extension`.
///
/// Only when `trust_forwarded` is `true` does it look at `X-Forwarded-For` and take the **rightmost** value;
/// if there is no value, it is empty or non-ASCII, it falls back to `ConnectInfo`. When `false` it never looks at the header.
pub async fn resolve_client_ip(
    trust_forwarded: bool,
    mut request: Request,
    next: Next,
) -> Response {
    let forwarded = trust_forwarded
        .then(|| {
            // Take the **rightmost** value (the peer appended by the trusted proxy). The leftmost may be
            // a value the client claimed (see the module docs of `assay_contracts::forwarded`).
            assay_contracts::forwarded::client_ip(
                request
                    .headers()
                    .get_all("x-forwarded-for")
                    .iter()
                    .filter_map(|v| v.to_str().ok()),
            )
        })
        .flatten();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());
    request
        .extensions_mut()
        .insert(ClientIp(forwarded.or(peer)));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use tower::ServiceExt as _;

    async fn echo_ip(Extension(ip): Extension<ClientIp>) -> String {
        ip.0.unwrap_or_else(|| "none".to_string())
    }

    /// Injects `ConnectInfo`, sends one request to the router, and returns the IP that was determined.
    async fn resolved_ip(trust_forwarded: bool, forwarded_for: Option<&str>) -> String {
        let app = Router::new()
            .route("/", get(echo_ip))
            .layer(axum::middleware::from_fn(move |req, next| {
                resolve_client_ip(trust_forwarded, req, next)
            }));
        let mut builder = HttpRequest::builder().uri("/");
        if let Some(v) = forwarded_for {
            builder = builder.header("x-forwarded-for", v);
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40000))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn ignores_the_forwarded_header_when_it_is_not_trusted() {
        // Default configuration. Even if an attacker spoofs it, it is not used; the peer address is.
        assert_eq!(
            resolved_ip(false, Some("198.51.100.9")).await,
            "203.0.113.7"
        );
        assert_eq!(resolved_ip(false, None).await, "203.0.113.7");
    }

    #[tokio::test]
    async fn takes_the_hop_appended_by_the_trusted_proxy() {
        // A single value (the bundled nginx overwrites it with `$remote_addr`) is taken as is.
        assert_eq!(
            resolved_ip(true, Some("198.51.100.9")).await,
            "198.51.100.9"
        );
        // Even if swapped for an appending proxy configuration, the client's leftmost claim is not taken.
        assert_eq!(
            resolved_ip(true, Some("192.0.2.66, 198.51.100.9")).await,
            "198.51.100.9"
        );
    }

    #[tokio::test]
    async fn falls_back_to_the_peer_address_when_the_trusted_header_is_missing() {
        // Some paths behind the proxy send no header (internal health checks etc.).
        assert_eq!(resolved_ip(true, None).await, "203.0.113.7");
        assert_eq!(resolved_ip(true, Some("   ")).await, "203.0.113.7");
    }
}
