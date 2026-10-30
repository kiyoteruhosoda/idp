//! 外へ出す HTTP の名前解決（task #585。脆弱性確認 2026-10-20 の中-5）。
//!
//! テナント管理者が登録する宛先（バックチャネルログアウト・外部 IdP の token / JWKS / discovery）は、
//! 字面だけ確かめても（`domain::outbound_uri`）、**引いた結果が内部の住所になる公開名**を登録されると
//! 内部へ届いてしまう（認証済みの blind SSRF。DNS rebinding も含む）。そこで reqwest の名前解決を
//! 差し替え、**繋ぐ直前に引いた住所を全部確かめる**。1 つでも内部なら繋がない。
//!
//! 例外は運用者が名指しした名前だけ（[`OutboundTrust`]。設定 `OUTBOUND_TRUSTED_HOSTS`）。宅内の
//! split DNS のように、正規の RP の公開名が内側の前段へ引ける配置のためである。
//!
//! ⚠ IP を直接書いた宛先は名前解決を通らない（reqwest が resolver を呼ばない）。それは字面の検査が
//! 弾く（`is_internal_destination`）。

use crate::domain::outbound_uri::{is_internal_address, OutboundTrust};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;

/// 引いた住所を確かめてから返す resolver。
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

/// 引いた住所の判定（純粋部分）。
pub(crate) fn check_resolved(host: &str, addrs: &[SocketAddr], trusted: bool) -> Result<(), String> {
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

/// 外へ出す HTTP クライアントの組み立ての共通部分（名前解決の差し替え）。
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
        // 1 つでも内部が混ざれば断る（どちらへ繋がるかは選べない）。
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
        // 運用者が名指しした名前は、内側の前段へ引けても送る（split DNS）。
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
