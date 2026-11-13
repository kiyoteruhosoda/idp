//! CSRF synchronizer tokens of the admin console (generated and verified within web. ADR-0007 §4).
//!
//! The admin console's CSRF is handled entirely in web (both generation and verification).
//! - [`admin_csrf_token`]: login form (unauthenticated). An HMAC of an unguessable random value issued on GET
//!   (HttpOnly cookie `admin_csrf_id`) is embedded in the form and recomputed from the cookie on POST for comparison.
//! - [`console_csrf_token`]: state-changing forms after login. A synchronizer token derived from the SSO session id
//!   (HttpOnly cookie) (separated from `admin_csrf_token` by namespace).
//!
//! **Verification is done only by this module's `*_valid`** (task #143). All go through a constant-time comparison
//! ([`assay_contracts::csrf::verify`]) and reject when the seed (cookie) is missing or empty. Previously each admin
//! screen handler had its own `csrf_valid`, and some compared with `==` (returning early at the first mismatch).

use axum::http::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_hex(key: &[u8], input: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Derives the admin login form's CSRF token from the cookie seed.
pub fn admin_csrf_token(csrf_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("admin-csrf:{csrf_id}"))
}

/// Derives the CSRF token for the post-login admin console (state-changing forms) from the SSO session id.
pub fn console_csrf_token(sso_session_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("console-csrf:{sso_session_id}"))
}

/// Derives the CSRF token for the end-user portal's login/TOTP forms from the cookie seed
/// (same mechanism as `admin_csrf_token`, separate namespace).
pub fn portal_csrf_token(csrf_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("portal-csrf:{csrf_id}"))
}

/// Compares the presented token with the token derived from the seed in constant time. `false` if the seed is
/// missing or empty (a token derived from an empty seed is not accepted).
fn seeded_valid(
    seed: Option<&str>,
    submitted: &str,
    key: &[u8],
    derive: fn(&str, &[u8]) -> String,
) -> bool {
    seed.filter(|s| !s.is_empty())
        .is_some_and(|s| assay_contracts::csrf::verify(&derive(s, key), submitted))
}

/// Verifies the CSRF of the admin login and forced password change forms against the seed cookie (`admin_csrf_id`).
pub fn admin_csrf_valid(csrf_id: Option<&str>, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(csrf_id, submitted, key, admin_csrf_token)
}

/// Verifies the CSRF of the end-user portal's login, forced password change and TOTP forms against the seed cookie
/// (`portal_csrf_id`).
pub fn portal_csrf_valid(csrf_id: Option<&str>, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(csrf_id, submitted, key, portal_csrf_token)
}

/// Verifies the CSRF of the login screen form in the middle of authorization ("Continue in the app"; task #892) against `auth_session_id`.
/// The token is the same as the login form's (`assay_contracts::csrf::login_csrf_token`).
pub fn login_csrf_valid(auth_session_id: &str, submitted: &str, key: &[u8]) -> bool {
    assay_contracts::csrf::verify(
        &assay_contracts::csrf::login_csrf_token(auth_session_id, key),
        submitted,
    )
}

/// Verifies the CSRF of post-login state-changing forms (admin console, account settings, logout) against the SSO
/// session id. For handlers that have already extracted the SSO session id.
pub fn console_csrf_valid(sso_session_id: &str, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(Some(sso_session_id), submitted, key, console_csrf_token)
}

/// Version of [`console_csrf_valid`] reading from the SSO cookie. `false` if there is no SSO cookie.
pub fn console_csrf_valid_in(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(
        crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).as_deref(),
        submitted,
        key,
        console_csrf_token,
    )
}

/// Derives the [`console_csrf_token`] to embed in forms from the SSO cookie. Empty string if there is no SSO cookie
/// (an empty token is always rejected by [`console_csrf_valid_in`]).
pub fn console_csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE)
        .filter(|s| !s.is_empty())
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

    #[test]
    fn tokens_are_deterministic_and_namespaced() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        assert_eq!(admin_csrf_token("s", key), admin_csrf_token("s", key));
        assert_ne!(admin_csrf_token("a", key), admin_csrf_token("b", key));
        assert_eq!(console_csrf_token("s", key), console_csrf_token("s", key));
        // With a different namespace, even the same seed does not match.
        assert_ne!(admin_csrf_token("x", key), console_csrf_token("x", key));
        assert_eq!(admin_csrf_token("x", key).len(), 64);
        // With a different key, even the same input does not match.
        let other_key = b"other-key-for-csrf-32-bytes-xxxx";
        assert_ne!(admin_csrf_token("x", key), admin_csrf_token("x", other_key));
    }

    fn sso_headers(sso: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={sso}", crate::cookies::SSO_SESSION_COOKIE)
                .parse()
                .unwrap(),
        );
        headers
    }

    /// Verification passes only on an exact match with the derived token (rejected if namespace, seed, key or length
    /// differ). If the seed is missing or empty, even a token derived from an empty seed is rejected.
    #[test]
    fn valid_accepts_only_the_token_derived_from_the_seed() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        let token = console_csrf_token("sso-1", key);
        assert!(console_csrf_valid("sso-1", &token, key));
        assert!(!console_csrf_valid("sso-2", &token, key));
        assert!(!console_csrf_valid("sso-1", "", key));
        assert!(!console_csrf_valid("sso-1", &token[..63], key));
        assert!(!console_csrf_valid("sso-1", &format!("{token}0"), key));
        assert!(!console_csrf_valid(
            "sso-1",
            &token,
            b"other-key-for-csrf-32-bytes-xxxx"
        ));
        // A value derived from an empty seed is not accepted when the seed is empty.
        assert!(!console_csrf_valid("", &console_csrf_token("", key), key));
        // A token of another namespace (for admin login) does not pass even with the same seed.
        assert!(!console_csrf_valid(
            "sso-1",
            &admin_csrf_token("sso-1", key),
            key
        ));

        let admin = admin_csrf_token("seed", key);
        assert!(admin_csrf_valid(Some("seed"), &admin, key));
        assert!(!admin_csrf_valid(None, &admin, key));
        assert!(!admin_csrf_valid(Some(""), &admin_csrf_token("", key), key));
        let portal = portal_csrf_token("seed", key);
        assert!(portal_csrf_valid(Some("seed"), &portal, key));
        assert!(!portal_csrf_valid(Some("seed"), &admin, key));
        assert!(!portal_csrf_valid(None, &portal, key));
    }

    /// The cookie-reading version uses the SSO cookie value as the seed. Without the cookie the embedded token is empty
    /// and verification always fails.
    #[test]
    fn valid_in_reads_the_sso_cookie() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        let headers = sso_headers("sso-1");
        let token = console_csrf_from(&headers, key);
        assert_eq!(token, console_csrf_token("sso-1", key));
        assert!(console_csrf_valid_in(&headers, &token, key));
        assert!(!console_csrf_valid_in(&headers, "", key));
        assert!(!console_csrf_valid_in(&sso_headers("sso-2"), &token, key));

        let none = HeaderMap::new();
        assert_eq!(console_csrf_from(&none, key), "");
        assert!(!console_csrf_valid_in(&none, "", key));
        assert!(!console_csrf_valid_in(&none, &token, key));
    }

    /// Verification must always go through this module (task #143). Writing verification back into a handler or comparing tokens
    /// with `==` / `!=` (returning early at the first mismatch) fails here immediately.
    #[test]
    fn handlers_do_not_compare_tokens_by_themselves() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/handlers");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read handlers dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read handler source");
            for (n, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("assert") {
                    continue;
                }
                let compares =
                    code.contains("csrf") && (code.contains("==") || code.contains("!="));
                let own_helper = code.contains("fn csrf_valid") || code.contains("fn csrf_from");
                if compares || own_helper {
                    offenders.push(format!("{}:{}: {code}", path.display(), n + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "CSRF verification must use crate::csrf's *_valid:\n{}",
            offenders.join("\n")
        );
    }
}
