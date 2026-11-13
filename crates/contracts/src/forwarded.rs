//! Extracting the client IP from `X-Forwarded-For` (shared by api and web; SEC1).
//!
//! The header value **can be set freely by the client**. A reverse proxy normally does not remove it,
//! and **appends** the peer it saw at the end (nginx's `$proxy_add_x_forwarded_for` does exactly this).
//! So it becomes
//!
//! ```text
//! X-Forwarded-For: 198.51.100.9, 203.0.113.7
//!                  ^^^^^^^^^^^^  ^^^^^^^^^^^^
//!                  claimed by    peer actually seen
//!                  the client    by the trusted proxy
//! ```
//!
//! and **taking the first value means trusting the attacker's claim as is** (varying it per request
//! bypasses per-IP rate limits and lets the audit log IP be polluted at will). This module always takes
//! **the rightmost value**, i.e. the peer observed by the hop right before the trust boundary.
//!
//! # Assumes one trusted hop
//!
//! assay's deployment (`docker/nginx.conf`, `docker/nginx.domain-split.conf`) has one proxy hop.
//! With multiple hops (CDN -> proxy -> api/web) the rightmost becomes "the front proxy's IP", not the
//! user's real IP. That failure **loses precision but cannot be spoofed**, so it is accepted as the safe side
//! (if the real IP is needed, overwrite `X-Forwarded-For` at the CDN or make the hop count configurable).
//!
//! The bundled nginx also **overwrites** `X-Forwarded-For` with `$remote_addr`, so only one value
//! is present in the first place. This function is a second line of defense so deployments with a
//! replaced proxy configuration do not break.

/// Extracts the client IP from the `X-Forwarded-For` header (multiple headers allowed).
///
/// Returns **the rightmost non-empty value** appended by the hop right before the trust boundary. `None` if
/// there is no value or only whitespace (the caller falls back to the TCP peer).
///
/// The value's validity (whether it parses as an IP) is not checked. It is only used as an audit log and
/// rate-limit key; this function's job is to lexically pick the value the trusted proxy wrote.
pub fn client_ip<'a>(raw_headers: impl IntoIterator<Item = &'a str>) -> Option<String> {
    raw_headers
        .into_iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .last()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_hop_appended_by_the_trusted_proxy() {
        // nginx's `$proxy_add_x_forwarded_for` keeps the client's claim and appends the peer it saw.
        // Whatever the attacker writes at the front, the rightmost (observed by the proxy) is taken.
        assert_eq!(
            client_ip(["198.51.100.9, 203.0.113.7"]).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(client_ip(["203.0.113.7"]).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn ignores_blank_entries() {
        assert_eq!(
            client_ip(["198.51.100.9, 203.0.113.7, "]).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(client_ip(["   "]), None);
        assert_eq!(client_ip([","]), None);
        assert_eq!(client_ip(std::iter::empty::<&str>()), None);
    }

    #[test]
    fn spans_repeated_headers() {
        // Even when split across multiple headers, the overall rightmost is the proxy's appended value.
        assert_eq!(
            client_ip(["198.51.100.9", "203.0.113.7"]).as_deref(),
            Some("203.0.113.7")
        );
    }
}
