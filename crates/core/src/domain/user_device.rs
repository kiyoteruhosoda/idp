//! A user's devices (task #872, ADR-0071).
//!
//! Type that holds the list of "my devices" so that **logins from other devices can be noticed**.
//! Devices are told apart by a long-lived cookie (the device mark) that web places in the browser. The plaintext
//! of the mark exists only between web and the browser; assay keeps only its SHA-256 ([`DeviceRef`]).
//!
//! # What the device mark tells and what it does not
//!
//! The mark only shows "came from the same browser profile". Clearing cookies, a private
//! window or another browser all make a **new device**. Conversely, a stolen mark lets another device claim
//! to be a registered one (binding the mark to a device key is task #875). What can be noticed here is the case where
//! a password or passkey was stolen and **a new login was made from another device**.
//!
//! # What is not used for the decision
//!
//! The browser's self-description (User-Agent) and the country are kept only for display and notices. Both can be
//! freely written by the sender, so "is it registered" is decided by the mark alone.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::domain::crypto;
use crate::domain::sso_session::SsoSession;
use crate::domain::values::AuthenticationMethod;

/// A device that goes unused for this many days after registration has its registration expire.
pub const UNUSED_DEVICE_EXPIRY_DAYS: i64 = 180;

/// A device can be registered only within this many seconds after verifying identity with a passkey.
pub const REGISTRATION_PASSKEY_MAX_AGE_SECS: i64 = 300;

/// Seconds after a login state is created during which a device may be bound to it.
///
/// web requests the binding right as it returns the login response, so it normally takes under a second. Prevents
/// binding another device to an old session later (someone who learned another's session id cannot overwrite it with their own mark).
pub const OBSERVATION_WINDOW_SECS: i64 = 120;

/// Maximum device name length (characters).
pub const MAX_DEVICE_NAME_CHARS: usize = 100;

/// Plaintext length of the device mark (cookie value) in hex characters. web creates it from 32 bytes of [`crypto::random_hex`].
pub const DEVICE_TOKEN_HEX_LEN: usize = 64;

/// SHA-256 of the device mark (the value stored in the DB).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceRef(String);

impl DeviceRef {
    /// Built from the mark plaintext received from web. Values of the wrong shape (length, non-hex) are rejected.
    ///
    /// ⚠ The plaintext is a random value anyone can make, so checking its shape is only to "keep broken or huge values out of the DB".
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        if token.len() != DEVICE_TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(crypto::sha256_hex(&token.to_ascii_lowercase())))
    }

    /// Wraps a fingerprint read from the DB.
    pub fn from_hash(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Country code (Cloudflare `CF-IPCountry`; ISO 3166-1 alpha-2, `XX` = unknown, `T1` = Tor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryCode(String);

impl CountryCode {
    /// Accepts only 2 alphanumeric characters (upper-cased). Anything else and "unknown" (`XX`) give `None`.
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.len() != 2 || !raw.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        let upper = raw.to_ascii_uppercase();
        if upper == "XX" {
            return None;
        }
        Some(Self(upper))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Normalizes a name. Trims surrounding whitespace; empty, too long or containing control characters gives `None`.
pub fn normalize_device_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.chars().count() > MAX_DEVICE_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return None;
    }
    Some(name.to_string())
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDevice {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device: DeviceRef,
    pub name: String,
    pub user_agent: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub last_country: Option<CountryCode>,
    pub last_ip: Option<String>,
}

impl UserDevice {
    /// A newly registered device. The registration time is used as the "last used" time.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        id: Uuid,
        user_id: Uuid,
        device: DeviceRef,
        name: String,
        user_agent: Option<String>,
        country: Option<CountryCode>,
        ip: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            device,
            name,
            user_agent,
            registered_at: now,
            last_used_at: now,
            last_country: country,
            last_ip: ip,
        }
    }

    /// When the registration expires ([`UNUSED_DEVICE_EXPIRY_DAYS`] days after last use).
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.last_used_at + Duration::days(UNUSED_DEVICE_EXPIRY_DAYS)
    }
}

/// Whether within [`REGISTRATION_PASSKEY_MAX_AGE_SECS`] seconds of verifying identity with a passkey.
///
/// Either right after logging in with a passkey (the session methods include `WebAuthn` and `auth_time` is recent),
/// or right after a later passkey verification (`passkey_verified_at`). ⚠ `step_up_at` is not consulted -- it also
/// advances on password re-verification, so it cannot tell "was it verified with a passkey".
pub fn passkey_verified_recently(
    session: &SsoSession,
    passkey_verified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let max_age = Duration::seconds(REGISTRATION_PASSKEY_MAX_AGE_SECS);
    (session.used_method(AuthenticationMethod::WebAuthn) && now - session.auth_time <= max_age)
        || passkey_verified_at.is_some_and(|at| now - at <= max_age)
}

/// Devices not used since before this time have expired registrations.
pub fn unused_device_cutoff(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::days(UNUSED_DEVICE_EXPIRY_DAYS)
}

/// Verdict on the device used to log in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInDevice {
    /// A registered device (name).
    Registered { device_id: Uuid, name: String },
    /// An unregistered device (has a mark).
    Unregistered,
    /// No mark arrived (web could not set it, or the value was broken). Treated as an unregistered device.
    Unknown,
}

/// Device mark of the current request's browser (plaintext web attached to the internal call; task #916).
///
/// Looked up by what decides whether a login may complete in organizations limited to registered devices
/// ([`crate::application::device_enrollment::DeviceGate`]). `None` outside a request (sweeps etc.) or for requests that hit the api directly.
pub trait RequestDevice: Send + Sync {
    fn current(&self) -> Option<DeviceRef>;
}

/// No device mark (tests, outside a request).
pub struct NoRequestDevice;

impl RequestDevice for NoRequestDevice {
    fn current(&self) -> Option<DeviceRef> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_tokens_must_be_64_hex_characters() {
        let token = "a".repeat(64);
        let reference = DeviceRef::from_token(&token).expect("valid token");
        assert_eq!(reference.as_str().len(), 64);
        assert_ne!(reference.as_str(), token, "only the digest is kept");
        assert!(DeviceRef::from_token(&"a".repeat(63)).is_none());
        assert!(DeviceRef::from_token(&"g".repeat(64)).is_none());
        assert!(DeviceRef::from_token("").is_none());
    }

    #[test]
    fn device_tokens_are_case_insensitive() {
        assert_eq!(
            DeviceRef::from_token(&"AB".repeat(32)),
            DeviceRef::from_token(&"ab".repeat(32))
        );
    }

    #[test]
    fn country_codes_are_two_characters_and_unknown_is_dropped() {
        assert_eq!(CountryCode::parse("jp").unwrap().as_str(), "JP");
        assert_eq!(CountryCode::parse("T1").unwrap().as_str(), "T1");
        assert!(CountryCode::parse("XX").is_none());
        assert!(CountryCode::parse("JPN").is_none());
        assert!(CountryCode::parse("J-").is_none());
        assert!(CountryCode::parse("").is_none());
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_device_name("  kyon-pc ").as_deref(),
            Some("kyon-pc")
        );
        assert!(normalize_device_name("   ").is_none());
        assert!(normalize_device_name(&"あ".repeat(MAX_DEVICE_NAME_CHARS + 1)).is_none());
        assert!(normalize_device_name(&"あ".repeat(MAX_DEVICE_NAME_CHARS)).is_some());
        assert!(normalize_device_name("a\nb").is_none());
    }

    #[test]
    fn devices_expire_after_being_unused_for_180_days() {
        let now = Utc::now();
        let device = UserDevice::register(
            Uuid::now_v7(),
            Uuid::now_v7(),
            DeviceRef::from_token(&"a".repeat(64)).unwrap(),
            "pc".to_string(),
            None,
            None,
            None,
            now,
        );
        assert_eq!(device.expires_at(), now + Duration::days(180));
        assert_eq!(unused_device_cutoff(now), now - Duration::days(180));
    }
}
