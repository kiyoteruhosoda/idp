//! 列挙型（DB では VARCHAR + CHECK 制約に対応）と値オブジェクト。
//!
//! 許可値はここで集中管理する。DB ネイティブ ENUM は使わない（`CLAUDE.md`「DB モデリング」）。
//! sqlx への依存はドメインに持ち込まないため、文字列変換（`as_str` / `parse`）のみを定義し、
//! DB との相互変換は infrastructure 層のリポジトリが担う。
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;

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
    /// テナントメンバーシップの状態（ADR-0009 §3）。
    ///
    /// - `INVITED`: 招待中（未承諾）。
    /// - `ACTIVE`: 参加中。`is_active_member` が true になる唯一の状態。
    /// - `SUSPENDED`: 一時停止（GUEST のみ。MT24）。メンバーシップ行と当該テナント scope の権限行を
    ///   残したままアクセスだけを止める。`ACTIVE` ではないため `is_active_member` は false を返し、
    ///   再開すれば停止前の状態（権限を含む）に戻る。解除（削除）との違いはここ。
    MembershipStatus {
        Invited => "INVITED",
        Active => "ACTIVE",
        Suspended => "SUSPENDED",
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

/// `users.email` の格納先カラム上限（`VARCHAR(320)`）。
pub const EMAIL_MAX_LEN: usize = 320;

/// メールアドレスの簡易バリデーション（MVP）。
///
/// 空でなく、`@` を挟んで両側に文字があり、カラム長（`VARCHAR(320)`）に収まることを検証する。
/// `register` と `user_management`・`user_lifecycle`（管理者による編集）で共通の基準として使う。
/// 長さを見ないと、上限超過が永続化時の内部エラー（500）として現れ、入力エラーとして返せない。
///
/// エラーは利用者へそのまま返るため、訳文ではなく**翻訳キー**を返す（MT19。訳出は Presentation 層）。
pub fn validate_email(email: &str) -> Result<(), MessageKey> {
    if email.chars().count() > EMAIL_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-email-too-long",
            EMAIL_MAX_LEN.to_string(),
        ));
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok(())
    } else {
        Err(MessageKey::new("api-email-invalid"))
    }
}

/// `preferred_username`（ログイン識別子）が格納先カラムの上限に収まるか検証する。
///
/// `users.preferred_username` は `VARCHAR(255)`、`users.email` は `VARCHAR(320)` であり、未指定時に
/// email を既定値へ採用する経路（`register` / `user_management`）で長い email がカラム長を超えると
/// 永続化時に内部エラーになる。それを防ぐため、採用前に文字数上限を検証する。
pub const PREFERRED_USERNAME_MAX_LEN: usize = 255;

pub fn validate_preferred_username(value: &str) -> Result<(), MessageKey> {
    if value.chars().count() > PREFERRED_USERNAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-username-too-long",
            PREFERRED_USERNAME_MAX_LEN.to_string(),
        ));
    }
    Ok(())
}

/// `users.name`（表示名）の格納先カラム上限。
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// 表示名（`users.name`）が格納先カラムの上限に収まるか検証する。表示名は一意制約・書式制約を
/// 持たない自由入力のため、長さのみを検証する（空・空白のみは呼び出し側で解除＝`None` に正規化する）。
pub fn validate_display_name(value: &str) -> Result<(), MessageKey> {
    if value.chars().count() > DISPLAY_NAME_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-display-name-too-long",
            DISPLAY_NAME_MAX_LEN.to_string(),
        ));
    }
    Ok(())
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

    #[test]
    fn preferred_username_length_is_capped_at_column_limit() {
        assert!(validate_preferred_username("alice").is_ok());
        assert!(validate_preferred_username(&"x".repeat(PREFERRED_USERNAME_MAX_LEN)).is_ok());
        assert!(validate_preferred_username(&"x".repeat(PREFERRED_USERNAME_MAX_LEN + 1)).is_err());
    }
}
