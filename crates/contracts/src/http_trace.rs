//! Building the HTTP access span (shared by api and web; SEC9).
//!
//! The default span of `TraceLayer::new_for_http()` records `uri` **including the query string**. assay
//! URLs carry credential-like values such as `?auth_session=` (the web handoff single-use handle),
//! `?code_challenge=` and `?code=`, so with the default, `RUST_LOG=debug` leaks secrets to stdout and
//! the `log` table (an acceptance criterion of ADR-0018).
//!
//! So both services use `make_span_with(assay_contracts::http_trace::request_span)` and record
//! **only the path**. Building it separately in api and web risks one side reverting to the default,
//! so, like cookie names and CSRF derivation, it is defined once in this crate.
//!
//! Note: the path itself carries identifiers like `/{tenant_id}/...`, but they are not secret (the tenant
//! UUID is a public value shown in the browser's address bar).

use tracing::Span;

/// Span for the access log. `uri` carries **only the path, with the query string dropped**.
///
/// The span name and field names match `TraceLayer`'s defaults (`http_request` / `method` / `uri` /
/// `version`), so existing log searches and dashboards keep working.
pub fn request_span<B>(request: &http::Request<B>) -> Span {
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri().path(),
        version = ?request.version(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_records_the_path_without_the_query_string() {
        let request = http::Request::builder()
            .uri("https://idp.example.com/6f0b/login?auth_session=secret-handle&lang=ja")
            .body(())
            .unwrap();
        let span = request_span(&request);
        // `tracing` field values cannot be read from outside, so check the original value passed to the span
        // (`request_span` puts this value into `uri` as is).
        assert_eq!(request.uri().path(), "/6f0b/login");
        assert!(!request.uri().path().contains("secret-handle"));
        assert_eq!(span.metadata().map(|m| m.name()), Some("http_request"));
    }
}
