//! CSRF synchronizer tokens for the login and consent screens (contract: web generates, api verifies).
//!
//! The HMAC-SHA256 of `auth_session_id` (an unguessable random value that exists only in an HttpOnly
//! cookie) is embedded in the form, and on POST the api service recomputes it and compares (synchronizer
//! token pattern; no extra server-side storage). Using the server-side secret key (`CSRF_SECRET`) as the
//! HMAC key means an attacker cannot forge a token even knowing session_id and the derivation (SEC7).
//! Lives in this crate so derivation matches between web (form rendering) and api (verification).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Compares a derived token with the presented value in **constant time**.
///
/// A CSRF token is an HMAC output, so leaking the matching prefix length would in theory leave room
/// to assemble it by brute force one byte at a time (`==` returns at the first mismatch). Measuring
/// the timing difference is hard in practice, but with the comparison in one place, preventing it costs nothing.
/// Different lengths yield `false` (the length is not secret: always 64 hex characters).
pub fn verify(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    expected
        .bytes()
        .zip(provided.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Derives the login screen CSRF token bound to `auth_session_id`.
/// Pass `CSRF_SECRET` (`[u8; 32]`) as `key`.
pub fn login_csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    hmac_sha256_hex(key, &format!("csrf:{auth_session_id}"))
}

/// Derives the consent screen CSRF token bound to `auth_session_id`.
/// Uses a prefix (`consent-csrf:`) different from the login one to avoid collisions.
/// Pass `CSRF_SECRET` (`[u8; 32]`) as `key`.
pub fn consent_csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    hmac_sha256_hex(key, &format!("consent-csrf:{auth_session_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"test-key-for-unit-tests-32bytes!";

    #[test]
    fn login_csrf_is_deterministic_and_session_bound() {
        let a = login_csrf_token("session-a", TEST_KEY);
        assert_eq!(a, login_csrf_token("session-a", TEST_KEY));
        assert_ne!(a, login_csrf_token("session-b", TEST_KEY));
        // HMAC-SHA256 hex (64 chars): only characters safe to embed in a form.
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn login_csrf_is_key_bound() {
        // Same session_id with a different key gives a different token.
        let key1 = b"key1-for-test-32-bytes-xxxxxxxxx";
        let key2 = b"key2-for-test-32-bytes-xxxxxxxxx";
        assert_ne!(
            login_csrf_token("session", key1),
            login_csrf_token("session", key2)
        );
    }

    #[test]
    fn verify_accepts_only_an_exact_match() {
        let token = login_csrf_token("session", TEST_KEY);
        assert!(verify(&token, &token));
        assert!(!verify(&token, &login_csrf_token("other", TEST_KEY)));
        // A different length (truncated or appended) is also rejected.
        assert!(!verify(&token, &token[..63]));
        assert!(!verify(&token, &format!("{token}0")));
        assert!(!verify(&token, ""));
    }

    #[test]
    fn consent_csrf_is_distinct_from_login_csrf() {
        let login = login_csrf_token("abc", TEST_KEY);
        let consent = consent_csrf_token("abc", TEST_KEY);
        assert_ne!(login, consent);
        assert_eq!(consent.len(), 64);
        assert!(consent.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
