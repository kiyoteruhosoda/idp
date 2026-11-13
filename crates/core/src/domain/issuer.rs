//! Building the per-tenant issuer (`iss`) (ADR-0009 §6).
//!
//! The canonical form of the `issuer` in issued tokens (ID Token / Access Token) and discovery is
//! `<base issuer>/<tenant_id>`. The base issuer (the `https://<host>` part) **comes from
//! configuration (`config.issuer()`)** and is never derived from the request's Host header (leaving
//! no room for host header injection).
//!
//! Resource servers verify `iss` by exact match, preventing tenant A's tokens from being reused at
//! tenant B. Therefore the issuing side (`TokenService`) and the verifying side
//! (`UserInfoService`/`IntrospectionService`) share the same composition rule through this
//! function. root is not special-cased; its `iss` follows the same rule.
//!
//! The WebAuthn RP ID and origin are **derived from the base issuer's host** and exclude the tenant
//! path (WebAuthn is per-host by protocol; §6). So this composition does not apply to WebAuthn.

use crate::domain::tenant::TenantId;

/// Builds the per-tenant issuer from the base issuer (no trailing slash) and the tenant ID.
pub fn tenant_issuer(base_issuer: &str, tenant_id: TenantId) -> String {
    format!("{base_issuer}/{tenant_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn composes_base_and_tenant_id() {
        let tenant: TenantId = Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001).into();
        assert_eq!(
            tenant_issuer("https://idp.example.com", tenant),
            format!("https://idp.example.com/{tenant}")
        );
    }
}
