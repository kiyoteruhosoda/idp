//! PKCE (RFC 7636, S256 only) verification logic (design spec §4.4).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Allowed length of `code_verifier` (RFC 7636 §4.1).
const MIN_VERIFIER_LEN: usize = 43;
const MAX_VERIFIER_LEN: usize = 128;

/// Format check of `code_verifier`: length 43–128, characters `A-Z a-z 0-9 - . _ ~`.
pub fn is_valid_code_verifier(verifier: &str) -> bool {
    (MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Builds the S256 `code_challenge` from a `code_verifier`.
///
/// assay also acts as an RP (external IdP login; AP10), so it needs the generating side, not just
/// verification. Keeps the same transform as verification ([`verify_s256`]) in one place so the two
/// never diverge.
pub fn s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// S256 verification: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge`.
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    s256_challenge(code_verifier) == code_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from RFC 7636 Appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// Generation and verification use the same transform (pinned with the RFC 7636 Appendix B
    /// vector).
    #[test]
    fn generates_the_rfc7636_challenge() {
        assert_eq!(s256_challenge(VERIFIER), CHALLENGE);
        assert!(verify_s256(VERIFIER, &s256_challenge(VERIFIER)));
    }

    #[test]
    fn verifies_rfc7636_test_vector() {
        assert!(verify_s256(VERIFIER, CHALLENGE));
        assert!(!verify_s256(
            "wrong-verifier-wrong-verifier-wrong-verifier",
            CHALLENGE
        ));
    }

    #[test]
    fn validates_verifier_length_and_charset() {
        assert!(is_valid_code_verifier(VERIFIER));
        // 42 characters (too short)
        assert!(!is_valid_code_verifier(&"a".repeat(42)));
        assert!(is_valid_code_verifier(&"a".repeat(43)));
        assert!(is_valid_code_verifier(&"a".repeat(128)));
        assert!(!is_valid_code_verifier(&"a".repeat(129)));
        // Invalid characters
        assert!(!is_valid_code_verifier(&format!("{}!", "a".repeat(43))));
    }
}
