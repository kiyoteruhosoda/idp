//! テナント別 issuer（`iss`）の合成（ADR-0009 §6）。
//!
//! 発行トークン（ID Token / Access Token）および discovery の `issuer` は
//! `<基底 issuer>/<tenant_id>` を canonical 形式とする。基底 issuer（`https://<host>` 部分）は
//! **設定値（`config.issuer()`）由来**であり、リクエストの Host ヘッダから導出しない
//! （host header injection の余地を作らない）。
//!
//! リソースサーバは `iss` の厳密一致を検証し、A テナント発行トークンの B テナントへの流用を防ぐ。
//! そのため、発行側（`TokenService`）と検証側（`UserInfoService`/`IntrospectionService`）は
//! 本関数で同一の合成規則を共有する。root も特別扱いせず、同じ規則で `iss` を合成する。
//!
//! WebAuthn の RP ID・origin は**基底 issuer のホストから導出**し、テナントパスを含めない
//! （WebAuthn はプロトコル上ホスト単位。§6）。したがって本合成は WebAuthn には適用しない。

use crate::domain::tenant::TenantId;

/// 基底 issuer（末尾スラッシュ無し）とテナント ID から per-tenant issuer を合成する。
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
