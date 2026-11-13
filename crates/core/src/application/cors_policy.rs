//! Deciding which origins to allow for cross-origin browser access (CORS) (G1).
//!
//! The default topology is `domain-split` (api and web on separate host names), so an SPA calling
//! `identity.example.com/{tenant}/token` is **always cross-origin**.
//! Since the DDL accepts `clients.client_type = 'public'` and `token_endpoint_auth_method = 'none'` and
//! PKCE is mandatory, SPAs are the intended users, but without `Access-Control-Allow-Origin`
//! the browser could not read responses, so they were effectively unreachable.
//!
//! # Why "the set of origins of public clients in the tenant"
//!
//! Whether the client can be identified depends on the endpoint:
//!
//! - `/.well-known/*` and `/saml/metadata` carry neither `client_id` nor a token (public metadata anyone
//!   can fetch, so `*` is fine. This is handled on the presentation side, not by [`ApiCorsPolicy`]).
//! - `/userinfo` is **always preflighted** because `Authorization: Bearer` is a non-safelisted header,
//!   but OPTIONS carries no token. So the client cannot be identified from the request.
//! - `/token`, `/revoke` and `/introspect` **can** be identified from the body's `client_id`.
//!
//! Being strict only on identifiable endpoints gains nothing, so the decision is made per tenant.
//! Even if one origin is allowed broadly, as long as `Access-Control-Allow-Credentials` is **not** sent
//! the browser sends no cookies; `/token` additionally requires the code and PKCE `code_verifier`, and
//! `/userinfo` an access token. So "responses readable from the origin of another public client in the
//! same tenant" has no real significance (it holds no credentials to read with).
//! A uniform decision also avoids accidents where preflight and actual request allow different sets.

use crate::domain::cache::Cache;
use crate::domain::repositories::ClientRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::ClientType;
use std::sync::Arc;

/// Decides which origins CORS allows.
pub struct ApiCorsPolicy {
    clients: Arc<dyn ClientRepository>,
    /// Origins explicitly allowed at the deployment level (`CORS_ALLOWED_ORIGINS`). Shared by all tenants.
    configured_origins: Vec<String>,
    /// Tenant -> allowed origin set. `/token` and `/userinfo` are hot paths, so no SELECT each time.
    cache: Arc<dyn Cache<TenantId, Arc<Vec<String>>>>,
}

impl ApiCorsPolicy {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        configured_origins: Vec<String>,
        cache: Arc<dyn Cache<TenantId, Arc<Vec<String>>>>,
    ) -> Self {
        Self {
            clients,
            configured_origins,
            cache,
        }
    }

    /// Whether `origin` is allowed in this tenant.
    ///
    /// Matching is **exact** (scheme, host, port). Same strictness as exact `redirect_uri` matching;
    /// no loose checks such as suffix matching.
    pub async fn allows(&self, tenant_id: TenantId, origin: &str) -> bool {
        if origin.is_empty() {
            return false;
        }
        if self.configured_origins.iter().any(|o| o == origin) {
            return true;
        }
        self.tenant_origins(tenant_id)
            .await
            .iter()
            .any(|o| o == origin)
    }

    /// Origin set derived from the `redirect_uris` of the tenant's public clients.
    async fn tenant_origins(&self, tenant_id: TenantId) -> Arc<Vec<String>> {
        if let Some(hit) = self.cache.get(&tenant_id) {
            return hit;
        }
        let origins = match self.clients.list(tenant_id).await {
            Ok(clients) => Arc::new(collect_public_client_origins(&clients)),
            Err(e) => {
                // On failure, treat the allowed set as "empty" (closing beats opening). Do not put it in
                // the cache (look it up again on the next request).
                tracing::error!(error = %e, "failed to load clients for the CORS allowlist");
                return Arc::new(Vec::new());
            }
        };
        self.cache.insert(tenant_id, origins.clone());
        origins
    }

    /// Drops the tenant's origin set when a client is updated (reflects `redirect_uris` changes in the admin UI).
    pub fn invalidate(&self, tenant_id: TenantId) {
        self.cache.invalidate(&tenant_id);
    }
}

/// Collects origins (`scheme://host[:port]`) from the `redirect_uris` of public clients.
///
/// Confidential clients are excluded because they do not call `/token` directly from the browser
/// (client_secret cannot live in a browser). Disabled clients are excluded too.
fn collect_public_client_origins(clients: &[crate::domain::client::Client]) -> Vec<String> {
    let mut origins: Vec<String> = clients
        .iter()
        .filter(|c| c.client_type == ClientType::Public && c.is_active())
        .flat_map(|c| c.redirect_uris.iter())
        .filter_map(|uri| origin_of(uri))
        .collect();
    origins.sort();
    origins.dedup();
    origins
}

/// From a URI to the form a browser puts in the `Origin` header (`scheme://host[:port]`; default port omitted).
///
/// `http://localhost:3000/callback` → `http://localhost:3000`
/// Custom schemes (`myapp://...`, native app redirects) never appear in `Origin`, so they are excluded.
fn origin_of(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    match parsed.port() {
        // `Url::port()` returns `None` for the default ports (80/443), so only non-default ones get here.
        Some(port) => Some(format!("{}://{host}:{port}", parsed.scheme())),
        None => Some(format!("{}://{host}", parsed.scheme())),
    }
}

/// Turns the setting value (comma-separated) into a list of allowed origins. Whitespace and trailing slashes are dropped.
pub fn parse_configured_origins(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_omitted_like_the_browser_does() {
        assert_eq!(
            origin_of("https://app.example.com/callback").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin_of("https://app.example.com:443/callback").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            origin_of("http://localhost:3000/callback").as_deref(),
            Some("http://localhost:3000")
        );
    }

    /// Native app redirects (custom scheme, other than loopback) never appear in `Origin`, so they are
    /// not added to the allowed set. They would have no effect and would just list values of unclear intent.
    #[test]
    fn custom_schemes_are_not_origins() {
        assert_eq!(origin_of("com.example.app://callback"), None);
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn configured_origins_are_trimmed_and_normalised() {
        assert_eq!(
            parse_configured_origins(" https://a.example.com/ , https://b.example.com ,, "),
            vec!["https://a.example.com", "https://b.example.com"]
        );
        assert!(parse_configured_origins("").is_empty());
    }
}
