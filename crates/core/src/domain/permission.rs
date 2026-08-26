//! 利用者・クライアントが保有する権限（permission code）の値表現と含意関係（ADR-0006 / ADR-0037）。
//!
//! OIDC scope（`domain::values::Scope`、claim 制御）とは**別軸**の「主体が保有する権限」。
//! 権限コードは運用に応じて増える**マスタ駆動＝データ**のため、Rust の固定 enum にはしない
//! （ADR-0006 §5）。値オブジェクトは `String` ラッパとし、名前空間付きコードを表す。
//!
//! 一方で**コード同士の含意**（`idp.tenant.admin` は `idp.users:read` を含む、`:write` は `:read` を
//! 含む）は判定ロジックであってデータではない。DB に含意表を持たせると判定が DB とアプリの 2 か所に
//! 分かれるため、本モジュールを単一の出所とする（ADR-0037）。
#![allow(dead_code)]

use crate::domain::error::DomainError;

/// テナント管理権限コード（scope = 当該テナント）。管理コンソールへのログインと管理操作に必要。
/// 細粒度コード（[`TENANT_MANAGEMENT_CODES`]）をすべて含意する上位コード。
pub const TENANT_ADMIN: &str = "idp.tenant.admin";
/// システム管理権限コード（scope = root テナントのみ）。root テナント自身の管理を含み、
/// すべての権限コードを含意する（ADR-0009 §4）。
pub const SYSTEM_ADMIN: &str = "idp.system.admin";

/// 読み取り操作を表す動作サフィックス（`idp.users:read` の `read`）。
pub const ACTION_READ: &str = "read";
/// 変更操作を表す動作サフィックス（`idp.users:write` の `write`）。`:read` を含意する。
pub const ACTION_WRITE: &str = "write";

pub const USERS_READ: &str = "idp.users:read";
pub const USERS_WRITE: &str = "idp.users:write";
pub const CLIENTS_READ: &str = "idp.clients:read";
pub const CLIENTS_WRITE: &str = "idp.clients:write";
pub const MEMBERS_READ: &str = "idp.members:read";
pub const MEMBERS_WRITE: &str = "idp.members:write";
pub const PERMISSIONS_READ: &str = "idp.permissions:read";
pub const PERMISSIONS_WRITE: &str = "idp.permissions:write";
pub const AUDIT_READ: &str = "idp.audit:read";
pub const KEYS_READ: &str = "idp.keys:read";
pub const KEYS_WRITE: &str = "idp.keys:write";
pub const TENANT_SETTINGS_READ: &str = "idp.tenant-settings:read";
pub const TENANT_SETTINGS_WRITE: &str = "idp.tenant-settings:write";
pub const AUTHENTICATION_POLICIES_READ: &str = "idp.authentication-policies:read";
pub const AUTHENTICATION_POLICIES_WRITE: &str = "idp.authentication-policies:write";
pub const EXTERNAL_IDPS_READ: &str = "idp.external-idps:read";
pub const EXTERNAL_IDPS_WRITE: &str = "idp.external-idps:write";
pub const SAML_SERVICE_PROVIDERS_READ: &str = "idp.saml-service-providers:read";
pub const SAML_SERVICE_PROVIDERS_WRITE: &str = "idp.saml-service-providers:write";

/// `idp.tenant.admin` が含意する細粒度コードの集合（ADR-0037）。
///
/// **システム管理操作（テナントの作成・削除、システム設定、再起動、テナント横断のログ参照）は
/// ここに含めない。** それらは引き続き `idp.system.admin` の完全一致だけが通る。細粒度化の目的は
/// 「テナントの中の運用を分担させること」であって、root の権限を切り売りすることではない。
pub const TENANT_MANAGEMENT_CODES: &[&str] = &[
    USERS_READ,
    USERS_WRITE,
    CLIENTS_READ,
    CLIENTS_WRITE,
    MEMBERS_READ,
    MEMBERS_WRITE,
    PERMISSIONS_READ,
    PERMISSIONS_WRITE,
    AUDIT_READ,
    KEYS_READ,
    KEYS_WRITE,
    TENANT_SETTINGS_READ,
    TENANT_SETTINGS_WRITE,
    AUTHENTICATION_POLICIES_READ,
    AUTHENTICATION_POLICIES_WRITE,
    EXTERNAL_IDPS_READ,
    EXTERNAL_IDPS_WRITE,
    SAML_SERVICE_PROVIDERS_READ,
    SAML_SERVICE_PROVIDERS_WRITE,
];

/// 保有コード `held` が要求コード `required` を満たすか（含意関係。ADR-0037）。
///
/// 1. 完全一致
/// 2. `idp.system.admin` はすべてを含意する（root scope でしか存在し得ない）
/// 3. `idp.tenant.admin` は [`TENANT_MANAGEMENT_CODES`] を含意する
/// 4. 同一リソースの `:write` は `:read` を含意する
///
/// `idp.tenant.admin` が `idp.system.admin` を含意しないことが本関数の要である。含意を
/// 「上位コードなら何でも通す」と書くと、テナント管理者が root 操作へ届いてしまう。
pub fn implies(held: &str, required: &str) -> bool {
    if held == required {
        return true;
    }
    if held == SYSTEM_ADMIN {
        return true;
    }
    if held == TENANT_ADMIN {
        return TENANT_MANAGEMENT_CODES.contains(&required);
    }
    // 同一リソースの :write → :read。`split_once` で「最後の 1 つ」ではなく最初の `:` を境にする
    // （リソース名に `:` を含めない前提。マスタもその形で seed している）。
    match (held.split_once(':'), required.split_once(':')) {
        (Some((held_resource, ACTION_WRITE)), Some((required_resource, ACTION_READ))) => {
            held_resource == required_resource
        }
        _ => false,
    }
}

/// 保有コード集合のいずれかが要求コードを満たすか（[`implies`] の集合版）。
pub fn satisfies<S: AsRef<str>>(held: &[S], required: &str) -> bool {
    held.iter().any(|code| implies(code.as_ref(), required))
}

/// クライアント（システム用クライアント）へ付与してよいコードか（ADR-0037）。
///
/// 包括的な管理権限（`idp.system.admin` / `idp.tenant.admin`）は付与させない。機械の資格情報は
/// 人の資格情報より寿命が長く失効の導線も弱いため、「とりあえず上位コードを付ける」を塞いで
/// 細粒度コードを選ばせる。DB 側にも同じ CHECK 制約があり、判定は二重に効く。
pub fn is_grantable_to_client(code: &str) -> bool {
    code != SYSTEM_ADMIN && code != TENANT_ADMIN
}

/// 名前空間付き権限コード（例: `idp.tenant.admin`, `idp.clients:read`）。
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

    #[test]
    fn exact_match_implies() {
        assert!(implies(USERS_READ, USERS_READ));
        assert!(implies(SYSTEM_ADMIN, SYSTEM_ADMIN));
    }

    #[test]
    fn system_admin_implies_everything() {
        assert!(implies(SYSTEM_ADMIN, TENANT_ADMIN));
        assert!(implies(SYSTEM_ADMIN, USERS_WRITE));
        for code in TENANT_MANAGEMENT_CODES {
            assert!(implies(SYSTEM_ADMIN, code));
        }
    }

    /// 既存の `idp.tenant.admin` 保有者は、細粒度化後も管理 API を今までどおり通る。
    #[test]
    fn tenant_admin_implies_every_tenant_management_code() {
        for code in TENANT_MANAGEMENT_CODES {
            assert!(implies(TENANT_ADMIN, code), "{code} not implied");
        }
    }

    /// 本モジュールの要: テナント管理者は root 操作へ届かない。
    #[test]
    fn tenant_admin_does_not_imply_system_admin() {
        assert!(!implies(TENANT_ADMIN, SYSTEM_ADMIN));
    }

    #[test]
    fn write_implies_read_of_the_same_resource() {
        assert!(implies(USERS_WRITE, USERS_READ));
        assert!(implies(CLIENTS_WRITE, CLIENTS_READ));
        // 別リソースへは及ばない。
        assert!(!implies(USERS_WRITE, CLIENTS_READ));
        // 逆向き（read → write）は含意しない。
        assert!(!implies(USERS_READ, USERS_WRITE));
    }

    #[test]
    fn satisfies_scans_the_held_set() {
        let held = vec![USERS_WRITE.to_string(), AUDIT_READ.to_string()];
        assert!(satisfies(&held, USERS_READ));
        assert!(satisfies(&held, AUDIT_READ));
        assert!(!satisfies(&held, CLIENTS_WRITE));
        assert!(!satisfies::<String>(&[], USERS_READ));
    }

    #[test]
    fn blanket_admin_codes_are_not_grantable_to_clients() {
        assert!(!is_grantable_to_client(SYSTEM_ADMIN));
        assert!(!is_grantable_to_client(TENANT_ADMIN));
        for code in TENANT_MANAGEMENT_CODES {
            assert!(is_grantable_to_client(code));
        }
    }
}
