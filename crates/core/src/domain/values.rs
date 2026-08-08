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
    /// 認可リクエストの `prompt`（OIDC Core §3.1.2.1 のうち本 IdP が解釈する値）。
    ///
    /// SSO 判定が `/authorize` から `/internal/authorize/resume` へ移った（ADR-0018 決定 2）ため、
    /// 評価時点まで auth_session に保存して持ち越す。未指定・未知の値は保存しない
    /// （`parse(...).ok()` で `None` に落とす。従来の「未知値は無視する」挙動を維持）。
    Prompt {
        None => "none",
        Login => "login",
        Consent => "consent",
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

string_enum!(
    /// `/token` が受け付ける grant_type（RFC 6749 / OIDC Core）。
    ///
    /// クライアントごとの許可は `clients.grant_types`（JSON 配列）が持ち、その許可値の単一の出所が
    /// 本 enum。`client_credentials`（G4）は利用者不在のサーバ間（M2M）用で、confidential client かつ
    /// 明示的に許可されたクライアントに限る。
    GrantType {
        AuthorizationCode => "authorization_code",
        RefreshToken => "refresh_token",
        ClientCredentials => "client_credentials",
    }
);

string_enum!(
    /// 認証セッションで実際に検証された認証方式（ユーザー認証・認証ポリシー仕様書 §14.3・§18.1）。
    ///
    /// 「どの認証器で本人確認したか」の記録であり、認証ポリシー（どの条件を課すか）とは別軸。
    /// `sso_sessions.authentication_methods` に JSON 配列として保存し、Step-up 認証（§15）と
    /// MFA 経過時間による再認証（§18.2）の判定材料にする。
    AuthenticationMethod {
        Password => "password",
        Totp => "totp",
        WebAuthn => "webauthn",
        RecoveryCode => "recovery_code",
        EmailOtp => "email_otp",
        SmsOtp => "sms_otp",
        ExternalIdp => "external_idp",
    }
);

impl AuthenticationMethod {
    /// OIDC `amr`（Authentication Methods References、RFC 8176）の対応値。
    /// ID Token へ載せる際の語彙は RFC 側に合わせる（内部の記録値は本 enum が単一の出所）。
    pub fn amr(&self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Totp => "otp",
            Self::WebAuthn => "hwk",
            Self::RecoveryCode => "rba",
            Self::EmailOtp | Self::SmsOtp => "otp",
            Self::ExternalIdp => "fed",
        }
    }

    /// この方式が第二要素（所持・生体）として数えられるか。
    ///
    /// パスワードは知識要素のため単独では多要素にならない。外部 IdP は「外部での認証結果の
    /// 引き受け」であり、外部側の MFA を信頼するかは認証ポリシーの判断（§13）に委ねるため、
    /// ここでは第二要素として数えない。
    pub fn is_second_factor(&self) -> bool {
        matches!(
            self,
            Self::Totp | Self::WebAuthn | Self::RecoveryCode | Self::EmailOtp | Self::SmsOtp
        )
    }
}

string_enum!(
    /// 認証セッションの認証強度（同仕様 §14.3）。
    ///
    /// 認証方式の集合から導出する派生値だが、判定のたびに数え直さなくて済むよう保存もする
    /// （導出規則の単一の出所は [`AuthenticationStrength::from_methods`]）。
    AuthenticationStrength {
        SingleFactor => "single_factor",
        MultiFactor => "multi_factor",
    }
);

impl AuthenticationStrength {
    /// 認証方式の集合から強度を導出する。第二要素を 1 つでも含めば `MultiFactor`。
    pub fn from_methods(methods: &[AuthenticationMethod]) -> Self {
        if methods.iter().any(|m| m.is_second_factor()) {
            Self::MultiFactor
        } else {
            Self::SingleFactor
        }
    }

    /// `required` 以上の強度か（`MultiFactor` は `SingleFactor` の要求を満たす）。
    pub fn satisfies(&self, required: Self) -> bool {
        match required {
            Self::SingleFactor => true,
            Self::MultiFactor => *self == Self::MultiFactor,
        }
    }
}

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

    #[test]
    fn strength_is_derived_from_the_second_factor() {
        use AuthenticationMethod::*;
        assert_eq!(
            AuthenticationStrength::from_methods(&[Password]),
            AuthenticationStrength::SingleFactor
        );
        assert_eq!(
            AuthenticationStrength::from_methods(&[Password, Totp]),
            AuthenticationStrength::MultiFactor
        );
        assert_eq!(
            AuthenticationStrength::from_methods(&[WebAuthn]),
            AuthenticationStrength::MultiFactor
        );
        // 外部 IdP 単体は多要素と数えない（外部 MFA の信頼は認証ポリシーの判断。仕様 §13）。
        assert_eq!(
            AuthenticationStrength::from_methods(&[ExternalIdp]),
            AuthenticationStrength::SingleFactor
        );
    }

    #[test]
    fn multi_factor_satisfies_single_factor_requirement_but_not_the_reverse() {
        assert!(AuthenticationStrength::MultiFactor
            .satisfies(AuthenticationStrength::SingleFactor));
        assert!(AuthenticationStrength::MultiFactor
            .satisfies(AuthenticationStrength::MultiFactor));
        assert!(AuthenticationStrength::SingleFactor
            .satisfies(AuthenticationStrength::SingleFactor));
        assert!(!AuthenticationStrength::SingleFactor
            .satisfies(AuthenticationStrength::MultiFactor));
    }
}
