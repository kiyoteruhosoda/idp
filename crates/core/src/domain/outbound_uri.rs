//! Constraints on destinations the IdP sends server-side requests to (SEC2).
//!
//! Outbound POST URIs (currently `backchannel_logout_uri`) can be registered by tenant admins, so
//! unrestricted they would be an authenticated blind SSRF (reaching cloud instance metadata,
//! internal admin APIs).
//!
//! The check is in domain because **the same rule is used in two places: at registration
//! (`client_management`) and at send time (presentation's logout)**. A registration-only check
//! would let through rows registered before this feature existed or rows edited directly in the DB.
//!
//! Only the literal URI is examined here. **Name resolution results** are checked at the moment of
//! sending (the resolver in `infrastructure::outbound_http`; resolving at registration can be
//! overturned by DNS rebinding and diverges from resolution at send time; task #585). At the
//! literal stage, names that obviously point inside (dotless names, in-cluster names) are rejected
//! here too.

/// Whether the URI points inside (loopback, private, link-local, etc.).
///
/// Unparseable URIs fall to the "safe side" and are treated as internal (not sent).
pub fn is_internal_destination(uri: &str) -> bool {
    match url::Url::parse(uri.trim()) {
        Ok(url) => url_is_internal(&url),
        Err(_) => true,
    }
}

fn url_is_internal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ipv4_is_internal(ip),
        Some(url::Host::Ipv6(ip)) => ipv6_is_internal(ip),
        Some(url::Host::Domain(host)) => name_is_internal(host),
        None => true,
    }
}

/// Whether a host name (not a URL) is internal from its literal alone (SMTP destinations; task
/// #740).
pub fn is_internal_host(host: &str) -> bool {
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(ip) => is_internal_address(ip),
        Err(_) => name_is_internal(bare),
    }
}

/// Whether a name is internal from its literal alone (task #585).
///
/// - `localhost` / `*.localhost` (own host)
/// - **dotless names** (service names on the same network like `api` or `rp`; resolvable into the
///   cluster via search domains)
/// - reserved names for clusters / intranets (`*.svc`, `*.cluster.local`, `*.internal`, `*.local`)
fn name_is_internal(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost"
        || host.ends_with(".localhost")
        || !host.contains('.')
        || [".svc", ".cluster.local", ".internal", ".local"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
}

/// Whether a resolved address is internal (used by the resolver at send time; task #585).
pub fn is_internal_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => ipv4_is_internal(v4),
        std::net::IpAddr::V6(v6) => ipv6_is_internal(v6),
    }
}

/// Names allowed to be sent to even if they resolve to internal addresses (setting
/// `OUTBOUND_TRUSTED_HOSTS`; task #585).
///
/// In deployments (split DNS) where public names resolve to an inner front end at home or in the
/// office, legitimate RP destinations also become internal addresses. Rejecting those uniformly
/// means no logout notice is ever delivered. **Only names the operator named and their subdomains**
/// are exempt (tenant admins cannot touch this). Literal checks (dotless names etc.) are not
/// exempted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundTrust {
    suffixes: Vec<String>,
}

impl OutboundTrust {
    /// Trusts nothing (default).
    pub fn none() -> Self {
        Self::default()
    }

    /// Built from comma-separated domain names (`nolumia.com,example.org`). `nolumia.com` matches
    /// `nolumia.com` itself and `*.nolumia.com`. Empty or whitespace-only elements are dropped.
    pub fn parse(list: &str) -> Self {
        Self {
            suffixes: list
                .split(',')
                .map(|s| s.trim().trim_start_matches('.').trim_end_matches('.'))
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .collect(),
        }
    }

    /// Whether `host` is a trusted name.
    pub fn trusts(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.suffixes
            .iter()
            .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    }
}

fn ipv4_is_internal(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        // "This network" (0.0.0.0/8).
        || a == 0
        // CGNAT (100.64.0.0/10). Cloud metadata and internal LBs may live here.
        || (a == 100 && (64..128).contains(&b))
        // IETF protocol assignments (192.0.0.0/24; used e.g. for NAT64 discovery).
        || (a == 192 && b == 0 && c == 0)
        // Benchmarking (198.18.0.0/15). Sometimes used inside closed networks.
        || (a == 198 && (b == 18 || b == 19))
        // Reserved (240.0.0.0/4).
        || a >= 240
    // Documentation ranges (192.0.2.0/24 etc.) are not blocked. They merely have no route, are not
    // "internal", and test environments sometimes use them as stand-in RPs.
}

fn ipv6_is_internal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = embedded_ipv4(ip) {
        return ipv4_is_internal(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // unique local (fc00::/7) and link-local (fe80::/10).
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Forms embedding IPv4 inside IPv6 (task #585). Judged by the embedded IPv4.
///
/// - IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`; excluding `::` and `::1`)
/// - NAT64 (`64:ff9b::/96`; through a translator it reaches the embedded IPv4)
/// - 6to4 (`2002::/16`; bytes 2–5 are the IPv4)
fn embedded_ipv4(ip: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    let o = ip.octets();
    let tail = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if s[..6] == [0, 0, 0, 0, 0, 0] && !ip.is_unspecified() && !ip.is_loopback() {
        return Some(tail);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail);
    }
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_destinations_are_allowed() {
        assert!(!is_internal_destination("https://rp.example.com/bc"));
        assert!(!is_internal_destination("http://rp.example.com:3000/bc"));
        assert!(!is_internal_destination("http://203.0.113.10/bc"));
        assert!(!is_internal_destination("http://[2001:db8::1]/bc"));
    }

    #[test]
    fn internal_destinations_are_rejected() {
        for uri in [
            // Cloud instance metadata (link-local).
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080/internal",
            "http://localhost/internal",
            "http://app.LOCALHOST/internal",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/admin",
            "http://100.64.0.1/admin",
            "http://0.0.0.0/",
            "http://[::1]/internal",
            "http://[fd00::1]/internal",
            "http://[fe80::1]/internal",
            "http://[::ffff:127.0.0.1]/internal",
            // Names that are internal by their literal (task #585).
            "http://rp:3000/bc",
            "http://api:8080/internal",
            "http://api.idp-prod.svc/internal",
            "http://api.idp-prod.svc.cluster.local:8080/",
            "http://metadata.google.internal/",
            "http://printer.local/",
            // Gaps in the block list (task #585).
            "http://198.18.0.1/",
            "http://198.19.255.255/",
            "http://192.0.0.8/",
            "http://240.0.0.1/",
            "http://0.1.2.3/",
            "http://224.0.0.1/",
            "http://[64:ff9b::10.0.0.1]/",
            "http://[::127.0.0.1]/",
            "http://[2002:a9fe:a9fe::]/",
            "http://[ff02::1]/",
            // Unparseable values are not sent.
            "not a url",
            "",
        ] {
            assert!(
                is_internal_destination(uri),
                "{uri} must be treated as internal"
            );
        }
    }

    #[test]
    fn trusted_names_match_the_name_and_below_only() {
        let trust = OutboundTrust::parse(" nolumia.com, .Example.org ,,");
        assert!(trust.trusts("nolumia.com"));
        assert!(trust.trusts("wiki.nolumia.com"));
        assert!(trust.trusts("WIKI.nolumia.com."));
        assert!(trust.trusts("a.example.org"));
        // A different name that merely shares part of the name does not match.
        assert!(!trust.trusts("evilnolumia.com"));
        assert!(!trust.trusts("nolumia.com.evil.test"));
        assert!(!OutboundTrust::none().trusts("nolumia.com"));
    }

    #[test]
    fn resolved_addresses_are_judged_by_the_same_rules() {
        use std::net::IpAddr;
        for internal in [
            "10.10.2.11",
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "64:ff9b::a00:1",
        ] {
            assert!(
                is_internal_address(internal.parse::<IpAddr>().unwrap()),
                "{internal}"
            );
        }
        for public in ["104.16.0.1", "2606:4700::1"] {
            assert!(
                !is_internal_address(public.parse::<IpAddr>().unwrap()),
                "{public}"
            );
        }
    }
}
