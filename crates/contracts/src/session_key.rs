//! Values that break unless web and api agree, for binding the SSO session to a device key (DBSC) (task #887, ADR-0074).
//!
//! - **challenge**: a one-time value web hands to Chrome, which signs it with the key and returns it. An HMAC of
//!   "which SSO session, issued when"; not stored in the DB. web creates it (registration request, refresh 403), api verifies it.
//! - **Short cookie** ([`BOUND_COOKIE`]): a mark that the bound login state "just signed with the key". An HMAC of
//!   "SSO session, expiry"; not stored in the DB. web issues it and web verifies it at the entrance.
//!
//! The HMAC keys are derived from `CSRF_SECRET` separately per purpose (so the same value cannot make CSRF tokens).

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Name of the short cookie of a bound login state (over HTTPS it is set with a `__Host-` prefix).
pub const BOUND_COOKIE: &str = "sso_bound";
/// Lifetime of the short cookie (seconds). Chrome signs with the key and refreshes it every time it expires.
pub const BOUND_COOKIE_MAX_AGE_SECS: i64 = 600;
/// How long a challenge is accepted (seconds).
pub const CHALLENGE_MAX_AGE_SECS: i64 = 300;
/// Registration route (web). Put in the header's `path`.
pub const REGISTRATION_PATH: &str = "/dbsc/register";
/// Refresh route (web). Put in the registration response's `refresh_url`.
pub const REFRESH_PATH: &str = "/dbsc/refresh";
/// Accepted signature algorithms (the two key-based ones defined by the DBSC draft).
pub const ALGORITHMS: &[&str] = &["ES256", "RS256"];
/// `typ` of the signature JWT.
pub const PROOF_TYPE: &str = "dbsc+jwt";

/// Header asking for a login state (read by Chrome).
pub const REGISTRATION_HEADER: &str = "secure-session-registration";
/// Header passing a new challenge on refresh.
pub const CHALLENGE_HEADER: &str = "secure-session-challenge";
/// Header where Chrome puts the signature (JWT).
pub const RESPONSE_HEADER: &str = "secure-session-response";
/// Binding identifier Chrome sends on refresh.
pub const SESSION_ID_HEADER: &str = "sec-secure-session-id";

fn mac(key: &[u8], purpose: &str, message: &str) -> Vec<u8> {
    let mut derived = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    derived.update(purpose.as_bytes());
    let derived = derived.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&derived).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn session_ref(sso_session_id: &str) -> String {
    hex::encode(Sha256::digest(sso_session_id.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Creates a value of the form `{issued_at}.{HMAC}`.
fn stamp(key: &[u8], purpose: &str, sso_session_id: &str, at: i64) -> String {
    let tag = mac(
        key,
        purpose,
        &format!("{}:{at}", session_ref(sso_session_id)),
    );
    format!("{at}.{}", hex::encode(tag))
}

/// Verifies a [`stamp`] value and returns the embedded time.
fn read_stamp(key: &[u8], purpose: &str, sso_session_id: &str, value: &str) -> Option<i64> {
    let (at, tag) = value.split_once('.')?;
    if at.len() > 20 || tag.len() != 64 {
        return None;
    }
    let at: i64 = at.parse().ok()?;
    let provided = hex::decode(tag).ok()?;
    let expected = mac(
        key,
        purpose,
        &format!("{}:{at}", session_ref(sso_session_id)),
    );
    constant_time_eq(&expected, &provided).then_some(at)
}

/// Creates a challenge bound to the SSO session (`now` is UNIX seconds).
pub fn challenge(key: &[u8], sso_session_id: &str, now: i64) -> String {
    stamp(key, "dbsc-challenge", sso_session_id, now)
}

/// Whether the challenge belongs to this SSO session and is within [`CHALLENGE_MAX_AGE_SECS`] of issuance.
pub fn challenge_is_fresh(key: &[u8], sso_session_id: &str, value: &str, now: i64) -> bool {
    read_stamp(key, "dbsc-challenge", sso_session_id, value)
        .is_some_and(|at| at <= now + 5 && now - at <= CHALLENGE_MAX_AGE_SECS)
}

/// Value of the short cookie (expiry `expires_at` in UNIX seconds).
pub fn bound_cookie(key: &[u8], sso_session_id: &str, expires_at: i64) -> String {
    stamp(key, "dbsc-bound-cookie", sso_session_id, expires_at)
}

/// Whether the short cookie belongs to this SSO session and has not expired yet.
pub fn bound_cookie_is_valid(key: &[u8], sso_session_id: &str, value: &str, now: i64) -> bool {
    read_stamp(key, "dbsc-bound-cookie", sso_session_id, value)
        .is_some_and(|expires_at| now < expires_at && expires_at - now <= BOUND_COOKIE_MAX_AGE_SECS)
}

/// If the short cookie belongs to this SSO session and has not expired yet, its expiry (UNIX seconds).
/// For showing in the user's "status" (task #896).
pub fn bound_cookie_expires_at(
    key: &[u8],
    sso_session_id: &str,
    value: &str,
    now: i64,
) -> Option<i64> {
    bound_cookie_is_valid(key, sso_session_id, value, now)
        .then(|| read_stamp(key, "dbsc-bound-cookie", sso_session_id, value))
        .flatten()
}

/// Value of `Secure-Session-Registration` put on the login response.
pub fn registration_header(challenge: &str) -> String {
    format!(
        "({});path=\"{REGISTRATION_PATH}\";challenge=\"{challenge}\"",
        ALGORITHMS.join(" ")
    )
}

/// Value of `Secure-Session-Challenge` put on the refresh 403.
pub fn challenge_header(challenge: &str, session_identifier: &str) -> String {
    format!("\"{challenge}\";id=\"{session_identifier}\"")
}

/// Checks `DBSC_ALLOWED_REFRESH_INITIATORS` (task #934). Goes into `allowed_refresh_initiators` of registration/refresh responses.
///
/// In the DBSC draft (§8.3, §8.4), the binding scope is only assay's origin (`include_site: false`), so
/// when the requesting origin is not assay (e.g. `prompt=none` in each app's hidden frame), Chrome does not
/// re-obtain the short cookie unless the host matches an entry here.
///
/// Only space-separated `*.<name>` and `<name>` (host names only) may be written. The draft matches host strings,
/// so scheme, port and path cannot be written. `*` (matches anything) and a single label after `*.` (`*.com`) are rejected.
/// `*.example.com` does not match `example.com` itself (write both if needed). If even one entry is invalid, the whole value is rejected.
pub fn parse_refresh_initiators(raw: &str) -> Result<Vec<String>, String> {
    raw.split_whitespace()
        .map(parse_refresh_initiator)
        .collect()
}

fn parse_refresh_initiator(raw: &str) -> Result<String, String> {
    let refuse = |why: &str| {
        Err(format!(
            "DBSC_ALLOWED_REFRESH_INITIATORS: `{raw}` {why} (write `*.example.com` or `app.example.com`)"
        ))
    };
    let (wildcard, host) = match raw.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return refuse("is not a lowercase host name");
    }
    if host.split('.').any(str::is_empty) {
        return refuse("is not a host name");
    }
    if wildcard && !host.contains('.') {
        return refuse("is too broad");
    }
    Ok(raw.to_string())
}

/// Whether it has the accepted shape of a binding identifier (32 hex characters; created by assay).
pub fn is_session_identifier(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-for-unit-tests-32bytes!";

    #[test]
    fn refresh_initiators_accept_host_patterns() {
        assert_eq!(
            parse_refresh_initiators(" *.nolumia.com  nolumia.com ").unwrap(),
            vec!["*.nolumia.com".to_string(), "nolumia.com".to_string()]
        );
        assert!(parse_refresh_initiators("").unwrap().is_empty());
        assert_eq!(
            parse_refresh_initiators("localhost").unwrap(),
            vec!["localhost".to_string()]
        );
    }

    #[test]
    fn refresh_initiators_refuse_what_the_draft_cannot_match() {
        for raw in [
            "*",
            "*.com",
            "https://*.nolumia.com",
            "*.nolumia.com:443",
            "*.nolumia.com/",
            "*.Nolumia.com",
            "a..nolumia.com",
            "*.",
            "**.nolumia.com",
        ] {
            assert!(
                parse_refresh_initiators(raw).is_err(),
                "{raw} must be refused"
            );
        }
        // If even one entry is invalid, the whole value is rejected
        assert!(parse_refresh_initiators("*.nolumia.com *").is_err());
    }
    const SESSION: &str = "session-a";

    #[test]
    fn the_bound_cookie_reveals_its_expiry_only_when_valid() {
        let value = bound_cookie(KEY, SESSION, 1_000);
        assert_eq!(
            bound_cookie_expires_at(KEY, SESSION, &value, 900),
            Some(1_000)
        );
        assert_eq!(bound_cookie_expires_at(KEY, SESSION, &value, 1_000), None);
        assert_eq!(bound_cookie_expires_at(KEY, "session-b", &value, 900), None);
    }

    #[test]
    fn a_challenge_is_bound_to_the_session_and_expires() {
        let c = challenge(KEY, SESSION, 1_000);
        assert!(challenge_is_fresh(KEY, SESSION, &c, 1_000));
        assert!(challenge_is_fresh(KEY, SESSION, &c, 1_300));
        assert!(!challenge_is_fresh(KEY, SESSION, &c, 1_301));
        assert!(!challenge_is_fresh(KEY, "session-b", &c, 1_000));
        assert!(!challenge_is_fresh(
            b"another-key-for-unit-tests-32by!",
            SESSION,
            &c,
            1_000
        ));
        // A value stamped with a future time (beyond clock skew) is not accepted.
        assert!(!challenge_is_fresh(
            KEY,
            SESSION,
            &challenge(KEY, SESSION, 2_000),
            1_000
        ));
    }

    #[test]
    fn a_challenge_is_not_a_bound_cookie() {
        let c = challenge(KEY, SESSION, 1_000);
        assert!(!bound_cookie_is_valid(KEY, SESSION, &c, 900));
        let b = bound_cookie(KEY, SESSION, 1_000);
        assert!(!challenge_is_fresh(KEY, SESSION, &b, 1_000));
    }

    #[test]
    fn a_bound_cookie_is_bound_to_the_session_and_expires() {
        let b = bound_cookie(KEY, SESSION, 1_600);
        assert!(bound_cookie_is_valid(KEY, SESSION, &b, 1_000));
        assert!(bound_cookie_is_valid(KEY, SESSION, &b, 1_599));
        assert!(!bound_cookie_is_valid(KEY, SESSION, &b, 1_600));
        assert!(!bound_cookie_is_valid(KEY, "session-b", &b, 1_000));
        // A value stamped with an expiry beyond the lifetime (impossible without the key, but just in case) is not accepted.
        assert!(!bound_cookie_is_valid(
            KEY,
            SESSION,
            &bound_cookie(KEY, SESSION, 5_000),
            1_000
        ));
    }

    #[test]
    fn broken_values_are_rejected() {
        for value in [
            "",
            ".",
            "1000",
            "1000.zz",
            "abc.0000",
            &format!("1000.{}", "0".repeat(64)),
        ] {
            assert!(!challenge_is_fresh(KEY, SESSION, value, 1_000), "{value}");
            assert!(!bound_cookie_is_valid(KEY, SESSION, value, 900), "{value}");
        }
    }

    #[test]
    fn headers_follow_the_draft() {
        assert_eq!(
            registration_header("c1"),
            "(ES256 RS256);path=\"/dbsc/register\";challenge=\"c1\""
        );
        assert_eq!(challenge_header("c2", "abc"), "\"c2\";id=\"abc\"");
    }

    #[test]
    fn session_identifiers_are_32_hex() {
        assert!(is_session_identifier(&"a".repeat(32)));
        assert!(!is_session_identifier(&"a".repeat(31)));
        assert!(!is_session_identifier(&"g".repeat(32)));
    }
}
