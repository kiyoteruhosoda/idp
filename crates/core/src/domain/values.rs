//! 列挙型（DB では VARCHAR + CHECK 制約に対応）と値オブジェクト。
//!
//! 許可値はここで集中管理する。DB ネイティブ ENUM は使わない（`CLAUDE.md`「DB モデリング」）。
//! sqlx への依存はドメインに持ち込まないため、文字列変換（`as_str` / `parse`）のみを定義し、
//! DB との相互変換は infrastructure 層のリポジトリが担う。
#![allow(dead_code)]

use crate::domain::message::MessageKey;

/// 文字列許可値を持つ enum を、`as_str` / `parse` 付きで定義するマクロ。
///
/// バリアントにも doc コメント（属性）を書ける。状態遷移を持つ enum は「どの値が何を意味するか」を
/// 型の隣に置けないと、DB の CHECK 制約とコードのどちらが正なのか読み手に伝わらない。
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($(#[$vmeta:meta])* $variant:ident => $value:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($(#[$vmeta])* $variant),+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }

            pub fn parse(s: &str) -> Result<Self, $crate::domain::error::DomainError> {
                match s {
                    $($value => Ok(Self::$variant),)+
                    other => Err($crate::domain::error::DomainError::InvalidValue(format!(
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

// 許可値の定義形式を 1 つに保つため、他のドメインモジュールからも同じマクロを使う。
pub(crate) use string_enum;

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
    ///
    /// `Deleted` は論理削除（ADR-0035）。物理削除にしないのは、発行済みトークン・同意・監査ログが
    /// `client_id` で紐づいており、実体を消すと監査で追えなくなるため。認可・トークン・
    /// introspection は `Client::is_active()` で門番をしているので、この値を増やすだけで
    /// **新しい絞り込みを足さずに**全経路が削除済みを拒む。
    ClientStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
        Deleted => "DELETED",
    }
);

string_enum!(
    /// トークンエンドポイントのクライアント認証方式（RFC 6749 §2.3.1）。
    ///
    /// confidential クライアントの既定は `private_key_jwt`（ADR-0036。仕様の既定である
    /// `client_secret_basic` から意図的に外している）。`client_secret_basic` は RFC 6749 が
    /// 推奨する共有秘密の提示方式で、明示的に選んだときだけ使う。
    /// `client_secret_post`（body に `client_id` / `client_secret`）は多くの RP ライブラリ・
    /// SaaS 連携が既定にしているため受け入れる（G3）。1 リクエストで両方を提示することは
    /// 認められておらず（同 §2.3.1）、提示された場合は `invalid_request` で拒否する。
    TokenEndpointAuthMethod {
        ClientSecretBasic => "client_secret_basic",
        ClientSecretPost => "client_secret_post",
        /// システム（人ではない呼び出し元）向け。クライアントが秘密鍵で署名した JWT（client
        /// assertion）を提示し、IdP は登録済みの公開鍵（`Client.jwks`）で検証する。秘密は
        /// クライアント側にしか存在しない（ADR-0030。RFC 7523）。
        PrivateKeyJwt => "private_key_jwt",
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
        /// 本 IdP はブラウザごとに SSO セッションを 1 つしか持たないため「選ばせる別アカウント」が
        /// 存在しない。要求されたら **`login` と同じ扱い**（ログイン画面を必ず出す）にする。
        /// 現在のアカウントで続けるか別のアカウントで入り直すかを利用者が選べる状態にはなる、
        /// というのが単一セッションでの `select_account` の意味である（G12）。
        SelectAccount => "select_account",
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

/// 認証ポリシーの `effect_params`（JSON）で方式を指定できるよう、**保存値の文字列**で
/// シリアライズする（`Debug` のバリアント名ではない）。派生 derive を使わないのは、
/// 許可値の単一の出所を [`AuthenticationMethod::as_str`] / `parse` に保つためである。
impl serde::Serialize for AuthenticationMethod {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AuthenticationMethod {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

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
        assert!(AuthenticationStrength::MultiFactor.satisfies(AuthenticationStrength::SingleFactor));
        assert!(AuthenticationStrength::MultiFactor.satisfies(AuthenticationStrength::MultiFactor));
        assert!(
            AuthenticationStrength::SingleFactor.satisfies(AuthenticationStrength::SingleFactor)
        );
        assert!(
            !AuthenticationStrength::SingleFactor.satisfies(AuthenticationStrength::MultiFactor)
        );
    }
}

/// 認可要求の `prompt`（**空白区切りの集合**。OIDC Core §3.1.2.1）。
///
/// `prompt` は単一値ではない。`prompt=select_account consent` のように「アカウントを選ばせた
/// うえで同意も取り直す」と要求できる。値をひとつしか持てない形にすると、複数指定された要求は
/// どれかを取りこぼす —— しかも取りこぼしは**要求が無言で無視される**形で出る（有効な SSO が
/// あれば黙って現在のアカウントで続く）。
///
/// **未知の値は捨てる。** OIDC Core は未知の `prompt` 値をエラーにすることを求めておらず、
/// 拒否すると将来値を送る RP が使えなくなる。捨てた結果が空集合なら「未指定」と同じに扱う。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptSet(Vec<Prompt>);

impl PromptSet {
    /// 空白区切りの生値を解釈する（重複は 1 つに畳む。順序は入力順）。
    pub fn parse(raw: &str) -> Self {
        let mut values = Vec::new();
        for token in raw.split_whitespace() {
            if let Ok(prompt) = Prompt::parse(token) {
                if !values.contains(&prompt) {
                    values.push(prompt);
                }
            }
        }
        Self(values)
    }

    /// DB へ保存する形（正規化した空白区切り）。空集合は `None`（＝未指定）。
    pub fn to_storage(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| {
            self.0
                .iter()
                .map(Prompt::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
    }

    pub fn contains(&self, prompt: Prompt) -> bool {
        self.0.contains(&prompt)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod prompt_tests {
    use super::{Prompt, PromptSet};

    /// `select_account` は**既知の値**として解釈する（G12）。未知の値として落ちると「未指定」と
    /// 区別できず、有効な SSO で黙って続いてしまう。
    #[test]
    fn select_account_is_a_known_prompt() {
        assert_eq!(
            Prompt::parse("select_account").ok(),
            Some(Prompt::SelectAccount)
        );
        assert_eq!(Prompt::SelectAccount.as_str(), "select_account");
        assert!(Prompt::parse("switch_user").is_err());
    }

    /// 複数指定を取りこぼさない（`select_account consent` は両方の要求）。
    #[test]
    fn multiple_values_are_all_kept() {
        let set = PromptSet::parse("select_account consent");
        assert!(set.contains(Prompt::SelectAccount));
        assert!(set.contains(Prompt::Consent));
        assert!(!set.contains(Prompt::Login));
        assert_eq!(set.to_storage().as_deref(), Some("select_account consent"));
    }

    /// 未知の値は捨てるが、**同じ要求に含まれる既知の値は生かす**（未知の値ひとつで要求全体を
    /// 落とすと、将来値を送る RP が使えなくなる）。
    #[test]
    fn unknown_values_are_dropped_without_losing_the_known_ones() {
        let set = PromptSet::parse("create login");
        assert!(set.contains(Prompt::Login));
        assert_eq!(set.to_storage().as_deref(), Some("login"));

        let only_unknown = PromptSet::parse("create");
        assert!(only_unknown.is_empty());
        assert_eq!(only_unknown.to_storage(), None, "unspecified is NULL");
    }

    #[test]
    fn duplicates_and_odd_spacing_normalize() {
        let set = PromptSet::parse("  login   login  consent ");
        assert_eq!(set.to_storage().as_deref(), Some("login consent"));
    }

    #[test]
    fn an_empty_request_is_an_empty_set() {
        assert!(PromptSet::parse("").is_empty());
        assert!(PromptSet::default().is_empty());
    }
}
