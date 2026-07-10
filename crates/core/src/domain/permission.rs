//! 利用者権限（permission code）の値表現（ADR-0006）。
//!
//! OIDC scope（`domain::values::Scope`、claim 制御）とは**別軸**の「利用者が保有する権限」。
//! 権限コードは運用に応じて増える**マスタ駆動＝データ**のため、Rust の固定 enum にはしない
//! （ADR-0006 §5）。値オブジェクトは `String` ラッパとし、名前空間付きコードを表す。
#![allow(dead_code)]

use crate::domain::error::DomainError;

/// 名前空間付き権限コード（例: `idp.tenant.admin`, 将来 `idp.clients:read`）。
///
/// 許可値の単一出所は `permissions` マスタテーブル（seed マイグレーション）であり、
/// この型は「空でない文字列」という最小限の不変条件のみを保証する。存在検証は
/// リポジトリ（`UserPermissionRepository`）と FK 制約が担う。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionCode(String);

impl PermissionCode {
    /// 文字列から権限コードを構築する。空文字列は拒否する。
    pub fn parse(s: impl Into<String>) -> Result<Self, DomainError> {
        let s = s.into();
        if s.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "permission code must not be empty".to_string(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PermissionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_non_empty_code() {
        let code = PermissionCode::parse("idp.tenant.admin").unwrap();
        assert_eq!(code.as_str(), "idp.tenant.admin");
        assert_eq!(code.to_string(), "idp.tenant.admin");
    }

    #[test]
    fn rejects_empty_or_blank_code() {
        assert!(PermissionCode::parse("").is_err());
        assert!(PermissionCode::parse("   ").is_err());
    }
}
