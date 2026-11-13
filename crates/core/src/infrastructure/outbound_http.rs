//! Name resolution for outbound HTTP (task #585; medium-5 of the 2026-10-20 vulnerability review).
//!
//! Destinations registered by tenant admins (back-channel logout, external IdP token / JWKS / discovery) can,
//! even after a textual check (`domain::outbound_uri`), reach internal hosts if **a public name resolving to an internal address**
//! is registered (authenticated blind SSRF, including DNS rebinding). So reqwest's name resolution is
//! replaced to **check every address resolved right before connecting**. If any one is internal, no connection is made.
//!
//! The only exception is names the operator explicitly named ([`OutboundTrust`], setting `OUTBOUND_TRUSTED_HOSTS`). This is for
//! setups like in-home split DNS, where a legitimate RP's public name resolves to an internal front end.
//!
//! ⚠ Destinations written as raw IPs don't go through name resolution (reqwest doesn't call the resolver). Those are
//! rejected by the textual check (`is_internal_destination`).

use crate::domain::outbound_uri::{is_internal_address, OutboundTrust};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;

/// Resolver that checks the resolved addresses before returning them.
pub struct GuardedResolver {
    trust: OutboundTrust,
}

impl GuardedResolver {
    pub fn new(trust: OutboundTrust) -> Self {
        Self { trust }
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let trusted = self.trust.trusts(&host);
        Box::pin(async move {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            check_resolved(&host, &addrs, trusted)?;
            Ok::<Addrs, Box<dyn std::error::Error + Send + Sync>>(Box::new(addrs.into_iter()))
        })
    }
}

/// Decision on resolved addresses (pure part).
pub(crate) fn check_resolved(
    host: &str,
    addrs: &[SocketAddr],
    trusted: bool,
) -> Result<(), String> {
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve to any address"));
    }
    if !trusted && addrs.iter().any(|a| is_internal_address(a.ip())) {
        return Err(format!(
            "{host} resolves to an internal address; refusing to connect \
             (add it to OUTBOUND_TRUSTED_HOSTS if this is intended)"
        ));
    }
    Ok(())
}

/// Common part of building outbound HTTP clients (replacing name resolution).
pub fn guarded_client_builder(trust: OutboundTrust) -> reqwest::ClientBuilder {
    reqwest::Client::builder().dns_resolver(GuardedResolver::new(trust))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 0)
    }

    #[test]
    fn a_name_that_resolves_inside_is_refused() {
        let err = check_resolved("rp.example.com", &[addr("10.10.2.11")], false).unwrap_err();
        assert!(err.contains("internal address"), "{err}");
        // Refuse if any internal address is mixed in (we can't choose which one gets connected).
        assert!(check_resolved(
            "rp.example.com",
            &[addr("104.16.0.1"), addr("169.254.169.254")],
            false
        )
        .is_err());
        assert!(check_resolved("rp.example.com", &[], false).is_err());
    }

    #[test]
    fn public_and_trusted_names_are_allowed() {
        assert!(check_resolved("rp.example.com", &[addr("104.16.0.1")], false).is_ok());
        // Names the operator named are sent to even if they resolve to an internal front end (split DNS).
        assert!(check_resolved("wiki.nolumia.com", &[addr("10.10.2.11")], true).is_ok());
    }

    #[tokio::test]
    async fn the_resolver_refuses_localhost_names() {
        let resolver = GuardedResolver::new(OutboundTrust::none());
        let result = resolver.resolve("localhost".parse().unwrap()).await;
        assert!(result.is_err());
        let resolver = GuardedResolver::new(OutboundTrust::parse("localhost"));
        assert!(resolver.resolve("localhost".parse().unwrap()).await.is_ok());
    }
}
