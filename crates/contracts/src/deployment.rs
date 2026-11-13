//! Deployment posture (production-like or not) and minimum requirements for bootstrap secrets (SEC11).
//!
//! Both api and web fail fast ("do not start in production with development default secrets"), but if
//! the decision diverges you get a half state where **api starts and web does not** (or vice versa).
//! The derivation breaks unless api and web agree, so it is defined once here as a contract
//! (the role of contracts in `CLAUDE.md` "Directory layout").

/// Whether the public origin is production-like (i.e. whether startup with development default secrets must be refused).
///
/// The rule is "**exposes something other than local loopback**". Not only https: even http naming a
/// non-loopback host is treated as a production deployment with TLS terminated in front.
///
/// When the decision was by scheme alone, a deployment terminating TLS at a proxy with
/// `ISSUER=http://id.example.com` did not fail fast, and `/internal/*` was open with the known
/// `INTERNAL_SERVICE_TOKEN` embedded in the source (the only defense being the front proxy's `/internal/` 404).
pub fn requires_production_secrets(public_origin: &str) -> bool {
    let Ok(url) = url::Url::parse(public_origin.trim()) else {
        // Unparseable values are rejected separately at startup. Here, err on the safe side (treat as production).
        return true;
    };
    if url.scheme().eq_ignore_ascii_case("https") {
        return true;
    }
    !host_is_loopback(&url)
}

/// Whether the URL host is local loopback (self-access on a development machine).
fn host_is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            host == "localhost" || host.ends_with(".localhost")
        }
        None => false,
    }
}

/// Minimum length of `INTERNAL_SERVICE_TOKEN`.
///
/// `openssl rand -base64 32` yields 44 characters, so this floor does not hinder real generation procedures.
pub const INTERNAL_SERVICE_TOKEN_MIN_LEN: usize = 32;

/// Checks the minimum requirements of `INTERNAL_SERVICE_TOKEN` and returns the normalized (trimmed) value.
///
/// This token is the only credential guarding `/internal/*` (authentication, password change, MFA
/// verification), yet it used to start unchecked even with 1 character (`KEY_ENCRYPTION_KEY` / `CSRF_SECRET` require 32 bytes).
/// Any format is fine (anything works as long as api and web match), so it rejects only guessable
/// shortness and leftover placeholders from the `.env` template.
pub fn validate_internal_service_token(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.contains("CHANGE-ME") {
        return Err(
            "INTERNAL_SERVICE_TOKEN is still the .env template placeholder \"CHANGE-ME\"; \
             replace it with a real value (generate with `openssl rand -base64 32`)"
                .to_string(),
        );
    }
    if value.chars().count() < INTERNAL_SERVICE_TOKEN_MIN_LEN {
        return Err(format!(
            "INTERNAL_SERVICE_TOKEN must be at least {INTERNAL_SERVICE_TOKEN_MIN_LEN} characters \
             (it is the only credential protecting /internal/*); \
             generate one with `openssl rand -base64 32`"
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_is_development() {
        for origin in [
            "http://localhost:8080",
            "http://LOCALHOST:8080",
            "http://127.0.0.1:8070",
            "http://[::1]:8070",
            "http://api.localhost:8070",
        ] {
            assert!(
                !requires_production_secrets(origin),
                "{origin} should be treated as local development"
            );
        }
    }

    #[test]
    fn tls_terminated_upstream_still_counts_as_production() {
        // The core of SEC11: even over http, exposing a non-loopback host means production.
        for origin in [
            "http://id.example.com",
            "http://id.example.com:8080",
            "http://10.0.0.5:8080",
            "https://localhost:8443",
            "https://identity.example.com",
            "HTTPS://identity.example.com",
        ] {
            assert!(
                requires_production_secrets(origin),
                "{origin} must require production secrets"
            );
        }
    }

    #[test]
    fn unparseable_origins_fail_closed() {
        assert!(requires_production_secrets("not a url"));
        assert!(requires_production_secrets(""));
    }

    #[test]
    fn internal_service_token_must_be_long_enough_and_not_a_placeholder() {
        assert!(validate_internal_service_token("short").is_err());
        assert!(
            validate_internal_service_token("CHANGE-ME-CHANGE-ME-CHANGE-ME-CHANGE-ME").is_err()
        );
        let good = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            validate_internal_service_token(&format!("  {good}  ")).unwrap(),
            good
        );
    }
}
