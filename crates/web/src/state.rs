//! web's shared state (axum `State`). Holds the API client and the settings.

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::cookies::SetCookies;
use crate::service_restart::ServiceRestart;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebState {
    pub config: Arc<Config>,
    pub api: ApiClient,
    /// Process start time. Kept so `/internal/health` can report uptime (ADR-0031).
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Restart request from the settings screen (ADR-0017). The graceful shutdown in `run()` waits on this value.
    /// In tests nobody waits on the value created by `build`, so requesting does nothing.
    pub restart: ServiceRestart,
    /// Short-lived memo of "is the SSO session bound to the device key" (task #887).
    pub session_keys: crate::session_key::SessionKeyCache,
}

impl WebState {
    pub fn build(config: Arc<Config>) -> Self {
        let api = ApiClient::new(
            config.api_base_url().to_string(),
            config.internal_service_token().to_string(),
        );
        Self {
            config,
            api,
            started_at: chrono::Utc::now(),
            restart: ServiceRestart::new(),
            session_keys: crate::session_key::SessionKeyCache::default(),
        }
    }

    /// Starts building a `Set-Cookie` for the response (attribute policy comes from settings; ADR-0012 §3).
    pub fn set_cookies(&self) -> SetCookies {
        SetCookies::new(self.config.cookie_policy().clone())
    }

    /// Actual name of an origin-bound web-local cookie (CSRF seed, MFA ticket, SAML progress state).
    ///
    /// Over HTTPS it is prefixed with `__Host-` to prevent overwriting/forcing from another subdomain of the
    /// same parent domain (SEC5). Route both reading and issuing through this (if only one side uses the
    /// bare name, the value cannot be read and every request becomes a CSRF mismatch).
    pub fn origin_bound_cookie(&self, base_name: &str) -> String {
        self.config.cookie_policy().origin_bound_name(base_name)
    }
}
