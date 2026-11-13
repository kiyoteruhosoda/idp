//! Authentication of internal inter-service calls (`/internal/*`) (ADR-0007 §5).
//!
//! Shares the header name and the comparison between api (verifier) and web (presenter, and verifier
//! of its own `/internal/*`). Changing it on one side alone breaks every internal route, and rewriting
//! the comparison per service risks **one side no longer being constant-time**, so it lives in contracts.

/// Header name carrying the internal service auth token (lowercase; `HeaderMap` lookups ignore case).
pub const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

/// Decides in **constant time** whether the presented token matches the expected value.
///
/// A naive `==` takes time proportional to the matching prefix length, so repeated attempts can narrow
/// down the answer one byte at a time. A length mismatch may return early (the length itself is not
/// secret and could be inferred from response sizes etc. even if hidden).
pub fn service_token_matches(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_only_identical_tokens() {
        assert!(service_token_matches("secret-token", "secret-token"));
        assert!(!service_token_matches("secret-token", "secret-tokeN"));
        assert!(!service_token_matches("secret", "secret-token"));
        assert!(!service_token_matches("", "x"));
        assert!(service_token_matches("", ""));
    }
}
