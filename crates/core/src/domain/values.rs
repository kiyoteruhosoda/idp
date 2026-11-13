//! Enums (mapped to VARCHAR + CHECK constraints in the DB) and value objects.
//!
//! Allowed values are managed centrally here. DB-native ENUM is not used (`CLAUDE.md` "DB modeling").
//! sqlx dependencies are kept out of the domain, so only string conversion (`as_str` / `parse`) is defined;
//! conversion to and from the DB is done by repositories in the infrastructure layer.
#![allow(dead_code)]

use crate::domain::message::MessageKey;

/// Macro defining an enum with string allowed values, with `as_str` / `parse`.
///
/// Variants can carry doc comments (attributes) too. Unless an enum with state transitions can keep "what each value
/// means" next to the type, readers can't tell whether the DB CHECK constraint or the code is authoritative.
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

// Other domain modules use the same macro too, to keep a single form for defining allowed values.
pub(crate) use string_enum;

string_enum!(
    /// User account status.
    UserStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
        Locked => "LOCKED",
    }
);

string_enum!(
    /// Tenant status (ADR-0009 §1). Each tenant is independent; a parent's DISABLED does not propagate to children.
    TenantStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
    }
);

string_enum!(
    /// Tenant membership kind (ADR-0009 §3). HOME is the owning tenant (cannot be removed); GUEST is participation by invitation.
    MembershipType {
        Home => "HOME",
        Guest => "GUEST",
    }
);

string_enum!(
    /// Tenant membership status (ADR-0009 §3).
    ///
    /// - `INVITED`: invited (not yet accepted).
    /// - `ACTIVE`: participating. The only state in which `is_active_member` is true.
    /// - `SUSPENDED`: suspended (GUEST only; MT24). Keeps the membership row and the permission rows scoped to the
    ///   tenant and only stops access. Not `ACTIVE`, so `is_active_member` returns false, and
    ///   resuming restores the pre-suspension state (including permissions). This is the difference from removal (deletion).
    MembershipStatus {
        Invited => "INVITED",
        Active => "ACTIVE",
        Suspended => "SUSPENDED",
    }
);

string_enum!(
    /// Status of a protected resource (the audience placed in `aud`) (ADR-0042).
    ///
    /// `Disabled` means "keep the registration but don't allow it as the audience of new tokens". Deleting the row
    /// also deletes the app's naming (`application_bindings`) (ON DELETE CASCADE), and when restoring it
    /// you can no longer tell which app's audience it was. Already issued tokens still stay valid until they expire.
    ResourceStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
    }
);

string_enum!(
    /// Application status (ADR-0054).
    ///
    /// `Disabled` means "keep the registration and only stop usage". Stopping an app stops its bindings
    /// for both OIDC and SAML together -- not having to learn how to stop each protocol is one of
    /// the payoffs of having the application layer.
    ApplicationStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
    }
);

string_enum!(
    /// Who may use the app (decision 3 of ADR-0054).
    ///
    /// `Everyone` means **only within that tenant** (users of other tenants are not included).
    /// The default is `Individual`. With `Everyone` as the default, an app someone forgot to restrict stays open to all
    /// and **nobody notices it is open**.
    ///
    /// ⚠ `Individual` with an empty roster means "nobody can get in", not "everyone". Mixing them up cuts everyone off.
    AssignmentMode {
        Everyone => "EVERYONE",
        Individual => "INDIVIDUAL",
    }
);

string_enum!(
    /// How far to enforce the assignment check (staged rollout of ADR-0054).
    ///
    /// `RecordOnly` runs the check but **does not refuse**. "People who came without an assignment" accumulate
    /// in the audit log, so every migration gap shows up there. Switch to `Enforce` once the log is quiet.
    ///
    /// ⚠ The switch is a setting so that **reverting does not require a deploy**
    /// (decided per tenant, takes effect without waiting for a restart; ADR-0058 §4).
    AssignmentEnforcement {
        RecordOnly => "record_only",
        Enforce => "enforce",
    }
);

string_enum!(
    /// Client type.
    ClientType {
        Public => "public",
        Confidential => "confidential",
    }
);

string_enum!(
    /// Client status.
    ///
    /// `Deleted` is a logical delete (ADR-0035). It is not a physical delete because issued tokens, consents and audit logs
    /// are linked by `client_id`, and deleting the entity would make it untraceable in audits. Authorization, tokens and
    /// introspection are gated by `Client::is_active()`, so just adding this value makes every path
    /// reject deleted clients **without adding new filters**.
    ClientStatus {
        Active => "ACTIVE",
        Disabled => "DISABLED",
        Deleted => "DELETED",
    }
);

string_enum!(
    /// Client authentication method at the token endpoint (RFC 6749 §2.3.1).
    ///
    /// The default for confidential clients is `private_key_jwt` (ADR-0036; intentionally departs from the spec's default
    /// `client_secret_basic`). `client_secret_basic` is the shared-secret presentation method RFC 6749
    /// recommends, used only when explicitly chosen.
    /// `client_secret_post` (`client_id` / `client_secret` in the body) is accepted because many RP libraries and
    /// SaaS integrations default to it (G3). Presenting both in one request is
    /// not allowed (same §2.3.1) and is rejected with `invalid_request`.
    TokenEndpointAuthMethod {
        ClientSecretBasic => "client_secret_basic",
        ClientSecretPost => "client_secret_post",
        /// For systems (non-human callers). The client presents a JWT signed with its private key (client
        /// assertion), and the IdP verifies it with the registered public key (`Client.jwks`). The secret
        /// exists only on the client side (ADR-0030; RFC 7523).
        PrivateKeyJwt => "private_key_jwt",
        None => "none",
    }
);

string_enum!(
    /// Signing key status.
    SigningKeyStatus {
        Active => "ACTIVE",
        Retired => "RETIRED",
    }
);

string_enum!(
    /// Signing algorithm (allowed values of the DB algorithm column).
    SigningAlgorithm {
        Rs256 => "RS256",
        Es256 => "ES256",
    }
);

string_enum!(
    /// PKCE code_challenge_method. assay supports only S256.
    CodeChallengeMethod {
        S256 => "S256",
    }
);

string_enum!(
    /// `prompt` of the authorization request (the values of OIDC Core §3.1.2.1 that assay interprets).
    ///
    /// The SSO decision moved from `/authorize` to `/internal/authorize/resume` (ADR-0018 decision 2),
    /// so it is saved in auth_session and carried until evaluation. Unspecified/unknown values are not saved
    /// (dropped to `None` via `parse(...).ok()`, keeping the existing "ignore unknown values" behavior).
    Prompt {
        None => "none",
        Login => "login",
        Consent => "consent",
        /// assay has only one SSO session per browser, so there is no "other account to choose".
        /// When requested it is **treated like `login`** (the login screen is always shown).
        /// The user can then choose to continue with the current account or sign in again with another;
        /// that is what `select_account` means with a single session (G12).
        SelectAccount => "select_account",
    }
);

string_enum!(
    /// OIDC scope. Requested scopes must be a subset of `Clients.scopes`.
    /// `offline_access` requests issuing a Refresh Token (design spec §9.1).
    Scope {
        OpenId => "openid",
        Profile => "profile",
        Email => "email",
        OfflineAccess => "offline_access",
    }
);

string_enum!(
    /// grant_type accepted by `/token` (RFC 6749 / OIDC Core).
    ///
    /// Per-client permission is held in `clients.grant_types` (JSON array), and the single source of its allowed values
    /// is this enum. `client_credentials` (G4) is for server-to-server (M2M) use without a user, limited to confidential clients
    /// that are explicitly allowed it.
    GrantType {
        AuthorizationCode => "authorization_code",
        RefreshToken => "refresh_token",
        ClientCredentials => "client_credentials",
    }
);

string_enum!(
    /// Authentication methods actually verified in the authentication session (user authentication / authentication policy spec §14.3, §18.1).
    ///
    /// A record of "which authenticator verified identity", a separate axis from the authentication policy (which conditions to impose).
    /// Stored as a JSON array in `sso_sessions.authentication_methods`, and used for Step-up authentication (§15) and
    /// re-authentication by elapsed MFA time (§18.2).
    AuthenticationMethod {
        Password => "password",
        Totp => "totp",
        WebAuthn => "webauthn",
        RecoveryCode => "recovery_code",
        EmailOtp => "email_otp",
        SmsOtp => "sms_otp",
        ExternalIdp => "external_idp",
        // Approval with a registered authenticator app (Keystore key, fingerprint on each use) (task #892, ADR-0077).
        AppApproval => "app_approval",
    }
);

/// Serialized as the **stored string value** (not the `Debug` variant name) so that methods can be specified in the
/// authentication policy's `effect_params` (JSON). Derives are not used to keep the single source
/// of allowed values in [`AuthenticationMethod::as_str`] / `parse`.
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
    /// Corresponding OIDC `amr` value (Authentication Methods References, RFC 8176).
    /// The vocabulary in the ID Token follows the RFC (this enum is the single source of internally recorded values).
    pub fn amr(&self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Totp => "otp",
            Self::WebAuthn => "hwk",
            Self::RecoveryCode => "rba",
            Self::EmailOtp | Self::SmsOtp => "otp",
            Self::ExternalIdp => "fed",
            // Signed with a non-extractable key on the device (possession), unlocked by fingerprint (biometric).
            Self::AppApproval => "hwk",
        }
    }

    /// Whether this method counts as a second factor (possession, biometric).
    ///
    /// A password is a knowledge factor, so it is not multi-factor on its own. An external IdP is "accepting the result of
    /// external authentication", and whether to trust external MFA is left to the authentication policy (§13),
    /// so it is not counted as a second factor here.
    pub fn is_second_factor(&self) -> bool {
        matches!(
            self,
            Self::Totp
                | Self::WebAuthn
                | Self::RecoveryCode
                | Self::EmailOtp
                | Self::SmsOtp
                | Self::AppApproval
        )
    }

    /// All variants. When adding a method, add it here too (omissions are caught by tests).
    pub const ALL: [AuthenticationMethod; 8] = [
        Self::Password,
        Self::Totp,
        Self::WebAuthn,
        Self::RecoveryCode,
        Self::EmailOtp,
        Self::SmsOtp,
        Self::ExternalIdp,
        Self::AppApproval,
    ];

    /// Enumeration of all methods counted as second factors (those for which [`Self::is_second_factor`] is true).
    ///
    /// Kept in a form that can be passed directly to the authentication policy's "any one of" (OR). A predicate alone
    /// can't build the **requirement** "add one second factor", so the enumeration is needed too.
    /// Tests check that the two never disagree.
    pub const SECOND_FACTORS: [AuthenticationMethod; 6] = [
        Self::Totp,
        Self::WebAuthn,
        Self::RecoveryCode,
        Self::EmailOtp,
        Self::SmsOtp,
        Self::AppApproval,
    ];
}

/// Reserved words for exchanging authentication strength with RPs (ADR-0043).
///
/// Received as `acr_values` in requests, and asserted as the ID Token's `acr` in results. **It is vocabulary whose meaning
/// assay defines**, so it is not made configurable per tenant. That is also why the namespace is cut by product name
/// rather than the tenant's domain.
///
/// **Don't use names implying order (`level1` / `level2`).** Once published, RPs depend on them so they can't change,
/// and intermediate levels could not be inserted later.
pub const ACR_MULTI_FACTOR: &str = "urn:assay:ac:mfa";
/// Reserved word meaning single-factor authentication (sending it as a request enforces nothing).
pub const ACR_SINGLE_FACTOR: &str = "urn:assay:ac:single";

/// Values published in discovery's `acr_values_supported`.
///
/// **Only values that can be guaranteed are published.** Tenants can still write their own strings in the authentication
/// policy's `requested_acr` condition, but assay does not define their meaning, so they are not published
/// (ADR-0043 decision 5).
pub const SUPPORTED_ACR_VALUES: [&str; 2] = [ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR];

string_enum!(
    /// Authentication strength of the authentication session (same spec §14.3).
    ///
    /// A value derived from the set of authentication methods, but also stored so it need not be recounted on every check
    /// (the single source of the derivation rule is [`AuthenticationStrength::from_methods`]).
    AuthenticationStrength {
        SingleFactor => "single_factor",
        MultiFactor => "multi_factor",
    }
);

impl AuthenticationStrength {
    /// Derives the strength from the set of authentication methods. `MultiFactor` if it contains at least one second factor.
    pub fn from_methods(methods: &[AuthenticationMethod]) -> Self {
        if methods.iter().any(|m| m.is_second_factor()) {
            Self::MultiFactor
        } else {
            Self::SingleFactor
        }
    }

    /// Whether the strength is at least `required` (`MultiFactor` satisfies a `SingleFactor` requirement).
    pub fn satisfies(&self, required: Self) -> bool {
        match required {
            Self::SingleFactor => true,
            Self::MultiFactor => *self == Self::MultiFactor,
        }
    }

    /// `acr` value used when asserting this strength to RPs (ADR-0043).
    ///
    /// The two strength values originally existed as internal derived values; the reserved words are merely their **public names**.
    /// Introducing no new concept is why the vocabulary can stay at two.
    pub fn acr(&self) -> &'static str {
        match self {
            Self::SingleFactor => ACR_SINGLE_FACTOR,
            Self::MultiFactor => ACR_MULTI_FACTOR,
        }
    }
}

/// Column size limit for `users.email` (`VARCHAR(320)`).
pub const EMAIL_MAX_LEN: usize = 320;

/// Simple email address validation (MVP).
///
/// Checks it is non-empty, has characters on both sides of `@`, and fits the column length (`VARCHAR(320)`).
/// Used as the common criterion by `register`, `user_management` and `user_lifecycle` (edits by admins).
/// Without the length check, exceeding the limit would surface as an internal error (500) on persistence instead of an input error.
///
/// Errors go back to users as is, so this returns a **translation key** rather than translated text (MT19; translation happens in Presentation).
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

/// Checks that `preferred_username` (login identifier) fits within the column limit.
///
/// `users.preferred_username` is `VARCHAR(255)` and `users.email` is `VARCHAR(320)`; on paths that adopt the email
/// as the default when unspecified (`register` / `user_management`), a long email would exceed the column length and
/// cause an internal error on persistence. To prevent that, the character limit is checked before adoption.
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

/// Column size limit for `users.name` (display name).
pub const DISPLAY_NAME_MAX_LEN: usize = 255;

/// Checks that the display name (`users.name`) fits within the column limit. Display names are free input with no
/// uniqueness or format constraints, so only length is checked (empty/whitespace-only is normalized to unset = `None` by callers).
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
    fn second_factors_matches_the_predicate() {
        // If the enumeration and the predicate disagree, the requirement "add one second factor" diverges
        // from the actual check (the requirement can be met but strength doesn't rise, or vice versa).
        let derived: Vec<AuthenticationMethod> = AuthenticationMethod::ALL
            .into_iter()
            .filter(|m| m.is_second_factor())
            .collect();
        assert_eq!(derived, AuthenticationMethod::SECOND_FACTORS.to_vec());
    }

    #[test]
    fn acr_names_the_strength() {
        assert_eq!(
            AuthenticationStrength::from_methods(&[AuthenticationMethod::Password]).acr(),
            ACR_SINGLE_FACTOR
        );
        assert_eq!(
            AuthenticationStrength::from_methods(&[AuthenticationMethod::WebAuthn]).acr(),
            ACR_MULTI_FACTOR
        );
        // External IdPs are not counted as a second factor (ADR-0008). The asserted value follows that.
        assert_eq!(
            AuthenticationStrength::from_methods(&[AuthenticationMethod::ExternalIdp]).acr(),
            ACR_SINGLE_FACTOR
        );
        // Only two words of vocabulary are published (ADR-0043 decision 5).
        assert_eq!(
            SUPPORTED_ACR_VALUES.to_vec(),
            vec![ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR]
        );
    }

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
        // An external IdP alone does not count as multi-factor (trusting external MFA is up to the authentication policy; spec §13).
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

/// `prompt` of the authorization request (a **space-separated set**; OIDC Core §3.1.2.1).
///
/// `prompt` is not a single value. One can request "have the user choose an account and also
/// re-obtain consent", like `prompt=select_account consent`. A form that holds only one value drops
/// some of a multi-valued request -- and the drop shows up as **the request being silently ignored** (with a valid SSO
/// it silently continues with the current account).
///
/// **Unknown values are discarded.** OIDC Core does not require unknown `prompt` values to be errors, and
/// rejecting them would break RPs sending future values. If the result after discarding is empty, it is treated as "unspecified".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptSet(Vec<Prompt>);

impl PromptSet {
    /// Interprets the raw space-separated value (duplicates folded into one; order as input).
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

    /// Form stored in the DB (normalized, space-separated). The empty set is `None` (= unspecified).
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

    /// `select_account` is interpreted as a **known value** (G12). If it fell through as unknown it would be
    /// indistinguishable from "unspecified" and silently continue with a valid SSO.
    #[test]
    fn select_account_is_a_known_prompt() {
        assert_eq!(
            Prompt::parse("select_account").ok(),
            Some(Prompt::SelectAccount)
        );
        assert_eq!(Prompt::SelectAccount.as_str(), "select_account");
        assert!(Prompt::parse("switch_user").is_err());
    }

    /// Multiple values are not dropped (`select_account consent` requests both).
    #[test]
    fn multiple_values_are_all_kept() {
        let set = PromptSet::parse("select_account consent");
        assert!(set.contains(Prompt::SelectAccount));
        assert!(set.contains(Prompt::Consent));
        assert!(!set.contains(Prompt::Login));
        assert_eq!(set.to_storage().as_deref(), Some("select_account consent"));
    }

    /// Unknown values are discarded, but **known values in the same request are kept** (dropping the whole request
    /// for one unknown value would break RPs sending future values).
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
