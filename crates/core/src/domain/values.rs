//! 列挙型（DB では VARCHAR + CHECK 制約に対応）と値オブジェクト。
//!
//! 許可値はここで集中管理する。DB ネイティブ ENUM は使わない（`CLAUDE.md`「DB モデリング」）。
//! sqlx への依存はドメインに持ち込まないため、文字列変換（`as_str` / `parse`）のみを定義し、
//! DB との相互変換は infrastructure 層のリポジトリが担う。
#![allow(dead_code)]

use crate::domain::error::DomainError;

/// 文字列許可値を持つ enum を、`as_str` / `parse` 付きで定義するマクロ。
macro_rules! string_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }

            pub fn parse(s: &str) -> Result<Self, DomainError> {
                match s {
                    $($value => Ok(Self::$variant),)+
                    other => Err(DomainError::InvalidValue(format!(
                        concat!(stringify!($name), ": {}"), other
                    ))),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

string_enum!(
    /// ユーザーのアカウント状態。
    UserStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
        Locked => "LOCKED",
    }
);

string_enum!(
    /// テナントの状態（ADR-0009 §1）。各テナント独立で、親の DISABLED は子へ伝播しない。
    TenantStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
    }
);

string_enum!(
    /// テナントメンバーシップの種別（ADR-0009 §3）。HOME は所属元（解除不可）、GUEST は招待による参加。
    MembershipType {
        Home => "HOME",
        Guest => "GUEST",
    }
);

string_enum!(
    /// テナントメンバーシップの状態（ADR-0009 §3）。INVITED は招待中（未承諾）。
    MembershipStatus {
        Invited => "INVITED",
        Active => "ACTIVE",
    }
);

string_enum!(
    /// クライアント種別。
    ClientType {
        Public => "public",
        Confidential => "confidential",
    }
);

string_enum!(
    /// クライアントの状態。
    ClientStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
    }
);

string_enum!(
    /// トークンエンドポイントのクライアント認証方式。
    TokenEndpointAuthMethod {
        ClientSecretBasic => "client_secret_basic",
        None => "none",
    }
);

string_enum!(
    /// 署名鍵の状態。
    SigningKeyStatus {
        Active => "ACTIVE",
        Retired => "RETIRED",
    }
);

string_enum!(
    /// 署名アルゴリズム（DB algorithm カラムの許可値）。
    SigningAlgorithm {
        Rs256 => "RS256",
        Es256 => "ES256",
    }
);

string_enum!(
    /// PKCE の code_challenge_method。本 IdP は S256 のみ。
    CodeChallengeMethod {
        S256 => "S256",
    }
);

string_enum!(
    /// OIDC scope。要求 scope は `Clients.scopes` の部分集合であること。
    /// `offline_access` は Refresh Token 発行を要求する（設計仕様 §9.1）。
    Scope {
        OpenId => "openid",
        Profile => "profile",
        Email => "email",
        OfflineAccess => "offline_access",
    }
);

/// メールアドレスの簡易バリデーション（MVP）。
///
/// 空でなく、`@` を挟んで両側に文字があることを検証する。
/// `register` と `user_management` で共通の基準として使う。
pub fn validate_email(email: &str) -> Result<(), DomainError> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok(())
    } else {
        Err(DomainError::InvalidValue(
            "invalid email format".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_values_and_roundtrips() {
        assert_eq!(UserStatus::parse("ACTIVE").unwrap(), UserStatus::Active);
        assert_eq!(UserStatus::Locked.as_str(), "LOCKED");
        assert_eq!(ClientType::parse("public").unwrap(), ClientType::Public);
        assert_eq!(
            CodeChallengeMethod::parse("S256").unwrap(),
            CodeChallengeMethod::S256
        );
    }

    #[test]
    fn rejects_unknown_values() {
        assert!(UserStatus::parse("BANNED").is_err());
        assert!(CodeChallengeMethod::parse("plain").is_err());
    }

    #[test]
    fn email_validation_accepts_valid_and_rejects_invalid() {
        assert!(validate_email("a@b").is_ok());
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("@b").is_err());
        assert!(validate_email("a@").is_err());
        assert!(validate_email("").is_err());
    }
}
