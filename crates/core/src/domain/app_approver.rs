//! Sign-in approved in the authenticator app ("Continue in app". task #892. ADR-0077).
//!
//! Holds three things:
//!
//! | Thing | What | Lifetime |
//! |---|---|---|
//! | [`ApproverKey`] | The user's authenticator app key (inside Android Keystore; fingerprint on every use). Listed under "My devices" | Until revoked |
//! | [`ApproverEnrollment`] | Key registration intake. Key Attestation -> verify the user with a passkey -> activated by the app's signature | 10 minutes |
//! | [`ApprovalRequest`] | A "Continue in app" request. Bound to a mark (Cookie) held only by the browser that started it | 5 minutes |
//!
//! The app holds no token. It signs [`signed_message`] with the key on every call.
//!
//! # Attack: getting a request started on another device approved
//!
//! On approval, assay returns a one-time code (30 seconds) **to the app**, and the app opens it in the browser on the same phone.
//! Sign-in completes only when both that code and the mark of the browser that started the request are present. Even if
//! someone is tricked into approving a request started on another person's device, the code goes to the owner's phone browser, which has no mark.
//! **No endpoint is made** for the browser that started the request to wait for "approved" and complete (making one would remove this protection).

use crate::domain::crypto;
use crate::domain::key_attestation::KeySecurityLevel;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Lifetime of a key registration intake.
pub const ENROLLMENT_TTL_SECS: i64 = 600;
/// Lifetime of the code from the registration check (passkey) until the app activates it.
pub const ENROLLMENT_CODE_TTL_SECS: i64 = 120;
/// Lifetime of a "Continue in app" request.
pub const REQUEST_TTL_SECS: i64 = 300;
/// Lifetime of the code returned on approval (owner's decision: 30 seconds).
pub const APPROVAL_CODE_TTL_SECS: i64 = 30;
/// Allowed window for the time in a revocation signature.
pub const SIGNED_AT_TOLERANCE_SECS: i64 = 300;
/// Max length (characters) of the device model name. Self-reported by the app; used only for display.
pub const MAX_DEVICE_NAME_CHARS: usize = 64;
/// Prefix (version) of the signed message.
pub const SIGNED_MESSAGE_VERSION: &str = "assay-app-approver-v1";
/// Number of random bytes for identifiers, challenges and codes.
pub const RANDOM_BYTES: usize = 32;

/// Operations the app signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedAction {
    Activate,
    Approve,
    Deny,
    Revoke,
}

impl SignedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Revoke => "revoke",
        }
    }
}

/// The message the app signs (UTF-8).
///
/// `assay-app-approver-v1\n<operation>\n<organization>\n<target>\n<one-time value>`. Operation, target and organization are included
/// so a signature for one operation cannot be reused for another operation, another request, or another organization.
pub fn signed_message(action: SignedAction, tenant_id: &str, target: &str, nonce: &str) -> String {
    format!(
        "{SIGNED_MESSAGE_VERSION}\n{}\n{tenant_id}\n{target}\n{nonce}",
        action.as_str()
    )
}

/// Key number: base64url of the SHA-256 of the SubjectPublicKeyInfo (DER) (no padding, 43 chars).
pub fn key_id_of(public_key_spki: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key_spki))
}

/// Random value used for identifiers, challenges and codes (base64url, 43 chars).
pub fn random_value() -> String {
    crypto::random_token(RANDOM_BYTES)
}

/// The user's authenticator app key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverKey {
    pub id: Uuid,
    pub user_id: Uuid,
    /// [`key_id_of`]. The app identifies its own key with this value.
    pub key_id: String,
    pub public_key_spki: Vec<u8>,
    pub security_level: KeySecurityLevel,
    /// The app's self-reported device model name (display only).
    pub device_name: String,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Stage of a key registration intake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentStage {
    /// Challenge issued. Waiting for the certificate chain.
    AwaitingKey,
    /// Key attestation passed. Waiting for the user's passkey confirmation.
    AwaitingConfirmation {
        public_key_spki: Vec<u8>,
        security_level: KeySecurityLevel,
        device_name: String,
    },
    /// The user confirmed. Waiting for the app to activate by signing with the key (holds only the code's SHA-256).
    Confirmed {
        public_key_spki: Vec<u8>,
        security_level: KeySecurityLevel,
        device_name: String,
        user_id: Uuid,
        code_hash: String,
        code_expires_at: DateTime<Utc>,
    },
}

/// Key registration intake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverEnrollment {
    pub id: String,
    pub tenant_id: Uuid,
    /// The value to be included in Key Attestation (base64url).
    pub challenge: String,
    pub stage: EnrollmentStage,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApproverEnrollment {
    pub fn start(tenant_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            id: random_value(),
            tenant_id,
            challenge: random_value(),
            stage: EnrollmentStage::AwaitingKey,
            created_at: now,
            expires_at: now + Duration::seconds(ENROLLMENT_TTL_SECS),
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Challenge bytes (the value expected to be in the Key Attestation).
    pub fn challenge_bytes(&self) -> Option<Vec<u8>> {
        URL_SAFE_NO_PAD.decode(self.challenge.as_bytes()).ok()
    }
}

/// State of a "Continue in app" request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Completed,
    /// Completion was attempted from a browser whose mark does not match (suspected approval of a request started on another device).
    Refused,
}

impl ApprovalState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Completed => "completed",
            Self::Refused => "refused",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "completed" => Some(Self::Completed),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }
}

/// A "Continue in app" request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: String,
    pub tenant_id: Uuid,
    /// SHA-256 of the starting browser's mark (Cookie).
    pub browser_binding_hash: String,
    /// If coming from the middle of authorization, that AuthSession (its SHA-256).
    pub auth_session_hash: Option<String>,
    /// If coming from the middle of authorization, that RP (for display and audit).
    pub client_id: Option<String>,
    /// The value the app includes in the signature (per request).
    pub challenge: String,
    pub state: ApprovalState,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    /// The approving key and user (after approval).
    pub approver_key: Option<Uuid>,
    pub user_id: Option<Uuid>,
    /// SHA-256 and expiry of the code returned on approval.
    pub code_hash: Option<String>,
    pub code_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ApprovalRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// Creates the mark given to the browser that started the request (plaintext and SHA-256).
pub fn new_browser_binding() -> (String, String) {
    let binding = random_value();
    let hash = crypto::sha256_hex(&binding);
    (binding, hash)
}

/// Whether the time in a revocation signature (`YYYY-MM-DDTHH:MM:SSZ`) is within the allowed window from now.
pub fn signed_at_is_fresh(signed_at: &str, now: DateTime<Utc>) -> bool {
    let Ok(at) = DateTime::parse_from_rfc3339(signed_at) else {
        return false;
    };
    (now - at.with_timezone(&Utc)).num_seconds().abs() <= SIGNED_AT_TOLERANCE_SECS
}

/// Makes a model name usable for display (trims whitespace, removes control characters, truncates). `None` if empty.
pub fn normalize_device_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DEVICE_NAME_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn signed_message_names_the_action_tenant_target_and_nonce() {
        assert_eq!(
            signed_message(SignedAction::Approve, "t", "r", "c"),
            "assay-app-approver-v1\napprove\nt\nr\nc"
        );
        assert_ne!(
            signed_message(SignedAction::Approve, "t", "r", "c"),
            signed_message(SignedAction::Deny, "t", "r", "c")
        );
    }

    #[test]
    fn key_id_is_43_characters_of_base64url() {
        let id = key_id_of(b"spki");
        assert_eq!(id.len(), 43);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn enrollment_challenge_is_32_bytes() {
        let now = Utc.with_ymd_and_hms(2026, 11, 4, 0, 0, 0).unwrap();
        let e = ApproverEnrollment::start(Uuid::nil(), now);
        assert_eq!(e.challenge_bytes().map(|b| b.len()), Some(32));
        assert!(!e.is_expired_at(now + Duration::seconds(599)));
        assert!(e.is_expired_at(now + Duration::seconds(600)));
    }

    #[test]
    fn signed_at_must_be_within_five_minutes() {
        let now = Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap();
        assert!(signed_at_is_fresh("2026-11-04T11:56:00Z", now));
        assert!(signed_at_is_fresh("2026-11-04T12:04:59Z", now));
        assert!(!signed_at_is_fresh("2026-11-04T11:54:59Z", now));
        assert!(!signed_at_is_fresh("yesterday", now));
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_device_name("  Pixel 9\u{0007} "),
            Some("Pixel 9".to_string())
        );
        assert_eq!(normalize_device_name("   "), None);
        assert_eq!(
            normalize_device_name(&"x".repeat(100)).map(|n| n.chars().count()),
            Some(MAX_DEVICE_NAME_CHARS)
        );
    }

    #[test]
    fn states_round_trip() {
        for s in [
            ApprovalState::Pending,
            ApprovalState::Approved,
            ApprovalState::Denied,
            ApprovalState::Completed,
            ApprovalState::Refused,
        ] {
            assert_eq!(ApprovalState::parse(s.as_str()), Some(s));
        }
    }
}
