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
    /// OIDC scope（MVP で扱う 3 種）。要求 scope は `Clients.scopes` の部分集合であること。
    Scope {
        OpenId => "openid",
        Profile => "profile",
        Email => "email",
    }
);

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
}
