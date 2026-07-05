//! PKCE（RFC 7636、S256 のみ）の検証ロジック（設計仕様 §4.4）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// `code_verifier` の許容長（RFC 7636 §4.1）。
const MIN_VERIFIER_LEN: usize = 43;
const MAX_VERIFIER_LEN: usize = 128;

/// `code_verifier` の形式検証。長さ 43〜128、文字種 `A-Z a-z 0-9 - . _ ~`。
pub fn is_valid_code_verifier(verifier: &str) -> bool {
    (MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// S256 検証: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge`。
pub fn verify_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest) == code_challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7636 Appendix B のテストベクタ。
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
        // 42 文字（短すぎ）
        assert!(!is_valid_code_verifier(&"a".repeat(42)));
        assert!(is_valid_code_verifier(&"a".repeat(43)));
        assert!(is_valid_code_verifier(&"a".repeat(128)));
        assert!(!is_valid_code_verifier(&"a".repeat(129)));
        // 不正文字
        assert!(!is_valid_code_verifier(&format!("{}!", "a".repeat(43))));
    }
}
