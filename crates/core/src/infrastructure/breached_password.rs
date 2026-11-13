//! Implementation of `BreachedPasswordChecker` (AP7; k-anonymity range API).
//!
//! # How matching works without sending the plaintext out
//!
//! Takes the password's SHA-1 and sends **only the first 5 hex digits** to the service. The service returns the
//! remaining 35 digits of hundreds of hashes starting with that prefix, and matching happens in this process.
//! So all that leaves is "one of some hundreds of thousands starting with the same 5 digits";
//! neither the password itself nor which account it concerns is handed over (same contract as the Pwned Passwords
//! range API; when hosting a compatible mirror yourself, point `PASSWORD_BREACH_API_BASE_URL` at it).
//!
//! SHA-1 is used here because **the matching protocol is defined in terms of SHA-1**, not for storage or
//! authentication (storage stays argon2).
//!
//! # Let it through when unreachable (fail-open)
//!
//! Blocking password changes while the external service is down would prevent rotation in **exactly the situation**
//! where credentials have leaked. Undecidable is `Ok(false)` (= don't reject) and is recorded in a warning log.
//! This choice reflects the judgment that "blocking changes" is more dangerous than "occasionally missing a leaked value",
//! and it is also written in the domain trait definition (`BreachedPasswordChecker`).

use crate::domain::error::Result;
use crate::domain::password_policy::BreachedPasswordChecker;
use async_trait::async_trait;
use sha1::{Digest, Sha1};

/// `User-Agent` presented to the matching service.
///
/// **Cannot be omitted.** Pwned Passwords rejects requests without a `User-Agent` with 403, and reqwest does not set
/// this header by default. Rejected responses pass through the non-success branch below as "could not decide",
/// so forgetting it makes **the breach check you thought was enabled let everything through** (with no sign other than warning logs).
const USER_AGENT: &str = "idp-oidc-provider";

pub struct RangeApiBreachedPasswordChecker {
    http: reqwest::Client,
    base_url: String,
}

impl RangeApiBreachedPasswordChecker {
    /// `base_url` is the base the prefix is appended to (GETs `{base_url}/{prefix}`).
    pub fn new(base_url: impl Into<String>, timeout: std::time::Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| {
                crate::domain::error::DomainError::InvalidValue(format!(
                    "failed to build breached password http client: {e}"
                ))
            })?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }
}

/// Returns the password's SHA-1 in upper-case hex, split into the prefix sent out (5 digits) and the rest matched locally (35 digits).
fn split_hash(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/// Whether the range API body (lines of `SUFFIX:COUNT`) contains the given suffix.
///
/// The occurrence count is ignored. A value that appeared in a breach list even once is not allowed.
fn body_contains_suffix(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        line.split(':')
            .next()
            .is_some_and(|candidate| candidate.trim().eq_ignore_ascii_case(suffix))
    })
}

#[async_trait]
impl BreachedPasswordChecker for RangeApiBreachedPasswordChecker {
    async fn is_breached(&self, password: &str) -> Result<bool> {
        let (prefix, suffix) = split_hash(password);
        let url = format!("{}/{prefix}", self.base_url);
        // `Add-Padding` asks for dummy rows so the prefix can't be guessed from the number of results
        // (mirrors that don't support it silently ignore it).
        let response = match self
            .http
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "breached password check unavailable; accepting the password"
                );
                return Ok(false);
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "breached password check returned an error status; accepting the password"
            );
            return Ok(false);
        }
        match response.text().await {
            Ok(body) => Ok(body_contains_suffix(&body, &suffix)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "breached password check response unreadable; accepting the password"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_hash_into_a_five_digit_prefix_and_the_rest() {
        // SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (a well-known range API example).
        let (prefix, suffix) = split_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn finds_the_suffix_regardless_of_case_and_ignores_the_count() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:37359195\r\n";
        assert!(body_contains_suffix(
            body,
            "1e4c9b93f3f0682250b6cf8331b7ee68fd8"
        ));
        assert!(!body_contains_suffix(
            body,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        ));
    }

    #[test]
    fn does_not_match_a_count_field() {
        // Don't pick up a value that happens to match on the count side instead of the suffix.
        let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:12345\r\n";
        assert!(!body_contains_suffix(body, "12345"));
    }
}
