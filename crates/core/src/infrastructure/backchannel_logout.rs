//! reqwest implementation of `BackchannelLogoutSender` (G5).
//!
//! POSTs `application/x-www-form-urlencoded` `logout_token=<JWT>` to the RP's
//! `backchannel_logout_uri` (OpenID Connect Back-Channel Logout 1.0 §2.5).
//! Failure reasons are built in the **operational language (English)** (they are stored in `last_error` and read as
//! operational information, not audit; outside the scope of CLAUDE.md "Internationalization").

use crate::application::backchannel_logout::BackchannelLogoutSender;
use crate::domain::outbound_uri::OutboundTrust;
use crate::infrastructure::outbound_http::guarded_client_builder;
use async_trait::async_trait;

/// Upper bound so we don't wait forever on an unresponsive RP endpoint.
const REQUEST_TIMEOUT_SECS: u64 = 5;
/// Maximum number of response body characters put in `last_error` (keeps the row small even if the RP returns huge HTML).
const BODY_SNIPPET_MAX_CHARS: usize = 200;

pub struct ReqwestBackchannelLogoutSender {
    client: reqwest::Client,
}

impl ReqwestBackchannelLogoutSender {
    pub fn new() -> Self {
        Self::with_trust(OutboundTrust::none())
    }

    /// Builds it with names that may be sent to even if they resolve to internal addresses (task #585).
    pub fn with_trust(trust: OutboundTrust) -> Self {
        Self {
            // Check the addresses resolved right before connecting (don't send if internal; `outbound_http`).
            client: guarded_client_builder(trust)
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                // Don't follow redirects, so the logout_token is never handed to anything but the registered URI
                // (if the RP has a redirect configured, it fails as a misconfiguration of the registration).
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }
}

impl Default for ReqwestBackchannelLogoutSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Joins an error with its causes into one line (task #585).
///
/// reqwest's `Display` only gives the outermost layer (`error sending request for url (...)`), so
/// `last_error` can't tell whether the name resolved to an internal address (refused by the `outbound_http` resolver)
/// or the connection failed. The chain of causes is kept, joined with `: `.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        source = cause.source();
    }
    message
}

#[async_trait]
impl BackchannelLogoutSender for ReqwestBackchannelLogoutSender {
    async fn post(&self, uri: &str, logout_token: &str) -> Result<(), String> {
        let response = self
            .client
            .post(uri)
            .form(&[("logout_token", logout_token)])
            .send()
            .await
            .map_err(|e| format!("request failed: {}", error_chain(&e)))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        // The body is a diagnostic clue, so keep only its start (the status code is recorded even if reading it fails).
        let snippet = response
            .text()
            .await
            .map(|body| {
                body.chars()
                    .take(BODY_SNIPPET_MAX_CHARS)
                    .collect::<String>()
            })
            .unwrap_or_default();
        Err(format!("endpoint returned {status}: {snippet}"))
    }
}

#[cfg(test)]
mod error_chain_tests {
    use super::*;
    use crate::domain::outbound_uri::OutboundTrust;

    /// When refused because the name resolved to an internal address, the reason is kept in `last_error` too (task #585).
    #[tokio::test]
    async fn a_refused_internal_destination_says_why() {
        let sender = ReqwestBackchannelLogoutSender::with_trust(OutboundTrust::none());
        let err = sender
            .post("http://localhost:9/bc", "t")
            .await
            .expect_err("must not be sent");
        assert!(err.starts_with("request failed:"), "{err}");
        assert!(err.contains("internal address"), "{err}");
    }
}
