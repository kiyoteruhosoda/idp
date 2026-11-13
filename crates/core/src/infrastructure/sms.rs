//! HTTP gateway implementation of `SmsSender` (AP13).
//!
//! A generic implementation that just **POSTs one JSON request** per send. Differences between providers' APIs
//! are absorbed by an operator-side relay (function, webhook) (see the module documentation of [`crate::domain::sms`]
//! for why). The body sent looks like:
//!
//! ```json
//! { "to": "+819012345678", "text": "Your verification code is 123456.", "from": "IDP" }
//! ```
//!
//! `from` is included only when a sender display (`sender_id`) is configured.
//!
//! # What is not logged
//!
//! Destination (PII), body (one-time code) and auth token. Errors carry **not even the destination host name**;
//! only a fixed context and the underlying error kind are kept. Send success/failure is tracked via the audit event
//! (`sms_otp.sent`).

use crate::domain::error::{DomainError, Result};
use crate::domain::outbound_uri::{is_internal_destination, OutboundTrust};
use crate::domain::sms::{OutgoingSms, SmsGatewayConfig, SmsSender};
use crate::infrastructure::outbound_http::guarded_client_builder;
use async_trait::async_trait;
use std::time::Duration;

/// Upper bound for connecting to and waiting on the gateway. Kept short so logging-in users are not kept waiting.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpSmsGateway {
    client: reqwest::Client,
}

impl HttpSmsGateway {
    pub fn new() -> Self {
        Self::with_trust(OutboundTrust::none())
    }

    /// Builds it with names that may be sent to even if they resolve to internal addresses (task #740).
    pub fn with_trust(trust: OutboundTrust) -> Self {
        Self {
            // Check the addresses resolved right before connecting (don't send if internal; `outbound_http`).
            client: guarded_client_builder(trust)
                .timeout(REQUEST_TIMEOUT)
                // Don't follow redirects, so the destination and one-time code are never handed to anything but the configured URL.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                // A configuration that fails with the default TLS backend (rustls) is a build configuration error
                // and cannot be caused by runtime input.
                .expect("reqwest client builds with the compiled-in TLS backend"),
        }
    }
}

impl Default for HttpSmsGateway {
    fn default() -> Self {
        Self::new()
    }
}

/// Attach only a fixed context, so no secrets or destinations leak into the error.
fn sms_err<E: std::fmt::Display>(context: &'static str) -> impl FnOnce(E) -> DomainError {
    move |e| DomainError::Repository(format!("sms gateway {context}: {e}"))
}

#[async_trait]
impl SmsSender for HttpSmsGateway {
    async fn send(&self, gateway: &SmsGatewayConfig, sms: &OutgoingSms) -> Result<()> {
        let url = gateway.endpoint_url.trim();
        // The configured URL is called as is, so internal destinations (localhost, private addresses, metadata
        // endpoints) are rejected. Uses the same check as client registration's outbound URI
        // (doesn't let an attacker able to rewrite settings POST into the internal network).
        if is_internal_destination(url) {
            return Err(DomainError::InvalidValue(
                "sms gateway url must not point at an internal destination".to_string(),
            ));
        }

        let mut body = serde_json::json!({
            "to": sms.to,
            "text": sms.body_text,
        });
        if !gateway.sender_id.trim().is_empty() {
            body["from"] = serde_json::json!(gateway.sender_id.trim());
        }

        let mut request = self.client.post(url).json(&body);
        if !gateway.auth_header.trim().is_empty() && !gateway.auth_token.is_empty() {
            request = request.header(gateway.auth_header.trim(), &gateway.auth_token);
        }

        let response = request.send().await.map_err(sms_err("request failed"))?;
        if !response.status().is_success() {
            // The body is not put in the error (if the provider reflects the request back, the destination and code would
            // leak into logs). Only the status is needed for the decision.
            return Err(DomainError::Repository(format!(
                "sms gateway rejected the request with status {}",
                response.status()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn gateway(url: String) -> SmsGatewayConfig {
        SmsGatewayConfig {
            endpoint_url: url,
            auth_header: String::new(),
            auth_token: String::new(),
            sender_id: String::new(),
        }
    }

    fn sms() -> OutgoingSms {
        OutgoingSms {
            to: "+819012345678".to_string(),
            body_text: "code".to_string(),
        }
    }

    /// Doesn't connect to names resolving internally (`localhost` is also refused textually, so the client is checked directly).
    #[tokio::test]
    async fn the_client_refuses_a_name_that_resolves_inside() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let sender = HttpSmsGateway::new();
        let result = sender
            .client
            .post(format!("http://localhost:{port}/"))
            .send()
            .await;
        assert!(result.is_err());
    }

    /// Doesn't follow redirects (the destination and code are not handed to the redirect target).
    #[tokio::test]
    async fn the_client_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 1024];
            let _ = socket.read(&mut buffer).await;
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://localhost:1/next\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let sender = HttpSmsGateway::with_trust(OutboundTrust::parse("localhost"));
        let response = sender
            .client
            .post(format!("http://localhost:{port}/"))
            .send()
            .await
            .expect("the first response comes back");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.expect("server task");
    }

    /// Textually internal URLs are not sent to even if trusted names are specified.
    #[tokio::test]
    async fn an_internal_url_is_refused() {
        let sender = HttpSmsGateway::with_trust(OutboundTrust::parse("localhost"));
        let err = sender
            .send(&gateway("http://localhost:1/".to_string()), &sms())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("internal destination"), "{err}");
    }
}
