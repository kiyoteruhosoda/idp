//! Self-registration use case for TOTP (Time-based One-Time Password).
//!
//! MFA is optional; users set it up and delete it themselves. Registration flow:
//! 1. `setup()`: generate a secret, store it provisionally, return the QR URI and the raw secret (base32).
//! 2. `confirm()`: verify a 6-digit code and activate the secret.
//! 3. `delete()`: delete the TOTP settings (disable MFA).
//!
//! The secret is encrypted with AES-256-GCM via `crypto::encrypt` and stored in the DB,
//! and decrypted only for verification (same scheme as signing_keys).

use crate::application::authenticator_management::AuthenticatorManagementService;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::repositories::{SsoSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::totp_secret::TotpSecret;
use std::sync::Arc;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;

/// Number of TOTP digits (6, the RFC 6238 standard).
const TOTP_DIGITS: u8 = 6;
/// TOTP step (seconds. RFC 4226 default of 30 seconds).
const TOTP_STEP: u64 = 30;
/// Allowed clock skew (1 step either way = ±30 seconds).
const TOTP_SKEW: u16 = 1;
/// Number of bytes of the generated secret (160 bit = 20 bytes, matching the HMAC-SHA1 output length).
const SECRET_BYTES: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum TotpRegistrationError {
    #[error("totp already configured and confirmed")]
    AlreadyConfigured,
    #[error("invalid totp code")]
    InvalidCode,
    #[error("no pending totp setup found")]
    NotFound,
    #[error("sso session expired or not found")]
    SessionExpired,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DomainError> for TotpRegistrationError {
    fn from(e: DomainError) -> Self {
        TotpRegistrationError::Internal(e.to_string())
    }
}

/// Data returned when starting TOTP setup.
pub struct TotpSetupData {
    /// `otpauth://totp/...` URI (used to generate the QR code).
    pub totp_uri: String,
    /// base32-encoded secret (shown directly for users who cannot use the QR code).
    pub secret_base32: String,
}

pub struct TotpRegistrationService {
    /// Authenticator registry (AP9). The secret stays in this service's table, while the state is reflected in the registry.
    authenticators: Arc<AuthenticatorManagementService>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    /// For looking up the label (user name) placed in the QR. It is the only clue for telling "which account" in
    /// the authenticator app's list, so it cannot be left empty.
    users: Arc<dyn UserRepository>,
    key_encryption_key: [u8; 32],
    /// **The heading shown in the authenticator app**. Different from the OIDC issuer URL; it cannot contain `:`
    /// (see [`totp_issuer_label`]). `None` if it cannot be derived (the URI then has no heading).
    totp_issuer: Option<String>,
    clock: Arc<dyn Clock>,
}

impl TotpRegistrationService {
    /// The OIDC issuer (URL) may be passed to `issuer` as is. **Conversion to the heading happens here**:
    /// leaving it to callers means one forgotten call site makes registration fail entirely (that actually happened).
    pub fn new(
        authenticators: Arc<AuthenticatorManagementService>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        key_encryption_key: [u8; 32],
        issuer: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authenticators,
            totp_secrets,
            sso_sessions,
            users,
            key_encryption_key,
            totp_issuer: totp_issuer_label(&issuer.into()),
            clock,
        }
    }

    /// Starts TOTP setup. Generates and stores a provisional secret, and returns the QR URI and the raw secret.
    ///
    /// - If a valid (confirmed) TOTP already exists, returns `AlreadyConfigured`.
    /// - `sso_session_id` is the raw Cookie value (looked up in the DB by SHA-256 hash).
    pub async fn setup(
        &self,
        sso_session_id: &str,
    ) -> Result<TotpSetupData, TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;
        let account_name = self.account_name(user_id).await?;

        // Refuse if a valid TOTP is already configured.
        if let Some(existing) = self.totp_secrets.find_by_user_id(user_id).await? {
            if existing.is_confirmed() {
                return Err(TotpRegistrationError::AlreadyConfigured);
            }
        }

        // Generate a new secret.
        let secret_bytes = generate_secret();
        let secret_base32 = to_base32(&secret_bytes);
        let totp_uri = build_totp_uri(&secret_bytes, &account_name, self.totp_issuer.as_deref())?;
        let secret_encrypted = crypto::encrypt(&secret_bytes, &self.key_encryption_key)
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;

        let now = self.clock.now();
        let record = TotpSecret {
            user_id,
            secret_encrypted,
            confirmed_at: None,
            created_at: now,
            updated_at: now,
        };
        // **Create the registry row first.** The shared key is stored in that row (AP11b), so in the reverse order
        // there would be nowhere to put it, and the key would be discarded without a row (and the row created right after would be empty).
        self.authenticators
            .register_totp_pending(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
        self.totp_secrets.upsert(&record).await?;

        Ok(TotpSetupData {
            totp_uri,
            secret_base32,
        })
    }

    /// Confirms TOTP. Verifies the 6-digit code the user presented and sets `confirmed_at`.
    pub async fn confirm(
        &self,
        sso_session_id: &str,
        code: &str,
    ) -> Result<(), TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;

        let record = self
            .totp_secrets
            .find_by_user_id(user_id)
            .await?
            .ok_or(TotpRegistrationError::NotFound)?;

        // Only a provisional secret can be confirmed.
        if record.is_confirmed() {
            return Err(TotpRegistrationError::AlreadyConfigured);
        }

        let secret_bytes = crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key)
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;

        let Some(step) = verify_totp_code(&secret_bytes, code)? else {
            return Err(TotpRegistrationError::InvalidCode);
        };

        let now = self.clock.now();
        // Record the step of the code used for confirmation so the same code cannot be reused in the sign-in right after
        // (blocks replay across the registration -> first sign-in window. RFC 6238 §5.2).
        self.totp_secrets
            .record_totp_step_if_newer(user_id, step as i64, now)
            .await?;
        self.totp_secrets.confirm(user_id, now).await?;
        self.authenticators
            .activate_totp(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Deletes the TOTP settings (disables MFA).
    pub async fn delete(&self, sso_session_id: &str) -> Result<(), TotpRegistrationError> {
        let user_id = self.resolve_user(sso_session_id).await?;
        self.totp_secrets.delete(user_id).await?;
        self.authenticators
            .revoke_totp(user_id)
            .await
            .map_err(|e| TotpRegistrationError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Resolves the user ID from the SSO session Cookie value.
    async fn resolve_user(&self, sso_session_id: &str) -> Result<Uuid, TotpRegistrationError> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = self
            .sso_sessions
            .find_by_hash(&hash)
            .await?
            .ok_or(TotpRegistrationError::SessionExpired)?;
        let now = self.clock.now();
        if session.idle_expires_at <= now || session.absolute_expires_at <= now {
            return Err(TotpRegistrationError::SessionExpired);
        }
        Ok(session.user_id)
    }

    /// The label placed in the QR. Authenticator apps show it in their list, so use a value by which the user recognizes their own account.
    /// Falls back to email if there is no `preferred_username`. `:` is removed since it is the URI separator.
    async fn account_name(&self, user_id: Uuid) -> Result<String, TotpRegistrationError> {
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(TotpRegistrationError::SessionExpired)?;
        let name = user
            .preferred_username
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(user.email);
        Ok(name.replace(':', ""))
    }
}

/// Derives the heading shown in authenticator apps from the OIDC issuer.
///
/// The separator in `otpauth://totp/{issuer}:{account}` is `:`, so **the issuer cannot contain `:`**
/// (totp-rs rejects it). Passing a URL like `https://identity.example.com` as is makes TOTP
/// registration fail every time. Only the host name is taken; scheme, credentials, port and path are dropped.
/// `None` if no characters usable as a heading remain (registration itself still works without a heading).
fn totp_issuer_label(issuer: &str) -> Option<String> {
    let after_scheme = issuer.split_once("://").map_or(issuer, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Drop the `user:pass@host` credentials part before dropping the port (in the reverse order the
    // credentials' `:` would be mistaken for the port separator).
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next().unwrap_or("").trim();
    (!host.is_empty()).then(|| host.to_string())
}

// --- TOTP utilities ---

/// Generates a 20-byte cryptographically random secret.
fn generate_secret() -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; SECRET_BYTES];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// base32-encodes bytes (Google Authenticator compatible. Uppercase letters + digits).
pub fn to_base32(bytes: &[u8]) -> String {
    Secret::from(bytes).to_base32()
}

/// Builds this service's TOTP (SHA-1, 6 digits, 30 seconds). `skew` is the number of steps allowed either way.
fn totp(
    secret_bytes: &[u8],
    skew: u16,
    issuer: Option<&str>,
    account_name: &str,
) -> Result<Totp, totp_rs::TotpError> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(TOTP_DIGITS)
        .with_skew(skew)
        .with_step_duration(TOTP_STEP)
        .with_secret(secret_bytes)
        .with_issuer(issuer)
        .with_account_name(account_name)
        .build()
}

/// Builds the `otpauth://totp/` URI. Used to generate the QR code.
fn build_totp_uri(
    secret_bytes: &[u8],
    account_name: &str,
    issuer: Option<&str>,
) -> Result<String, TotpRegistrationError> {
    totp(secret_bytes, TOTP_SKEW, issuer, account_name)
        .and_then(|totp| totp.to_url())
        .map_err(|e| TotpRegistrationError::Internal(format!("failed to build TOTP: {e}")))
}

/// Verifies a TOTP code and returns the matching **time-step** (unix seconds / `TOTP_STEP`). `None` if invalid.
///
/// It returns the step rather than a plain boolean to prevent **reuse** (replay) of accepted codes
/// (RFC 6238 §5.2). Callers record the returned step and do not re-accept codes of the same or an older step
/// (`TotpSecretRepository::record_totp_step_if_newer`). To allow skew, it checks `TOTP_SKEW` steps before and after
/// the current step, newest first, and returns the first matching step.
///
/// Like `totp-rs`'s `check_current`, it uses real time (`SystemTime`). TOTP is inherently bound to real time,
/// and the step computation uses the same clock (consolidated in this one place).
pub fn verify_totp_code(
    secret_bytes: &[u8],
    code: &str,
) -> Result<Option<u64>, TotpRegistrationError> {
    // Skew is handled here ourselves, so the TOTP itself is built with skew=0 (asking `check` about an exact step).
    let totp = totp(secret_bytes, 0, None, "")
        .map_err(|e| TotpRegistrationError::Internal(format!("failed to build TOTP: {e}")))?;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| TotpRegistrationError::Internal(format!("system clock before epoch: {e}")))?
        .as_secs();
    let base = (now_secs / TOTP_STEP) as i64;
    let skew = TOTP_SKEW as i64;
    // Return newer steps first (the same code never appears at several steps within the window, but fixing the order
    // makes the recorded step unique).
    for delta in (-skew..=skew).rev() {
        let step = base + delta;
        if step < 0 {
            continue;
        }
        let time = (step as u64) * TOTP_STEP;
        // With skew=0, `check` on this TOTP compares only the step of `time` (in constant time).
        if totp.check(code, time).is_some() {
            return Ok(Some(step as u64));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The URI can be built even when the OIDC issuer is passed as is.** If this breaks, TOTP registration
    /// becomes entirely impossible from the screen (the api returns internal, the web shows 500). That actually happened.
    #[test]
    fn an_issuer_url_still_produces_a_usable_uri() {
        let uri = build_totp_uri(
            &[7u8; SECRET_BYTES],
            "kyon",
            totp_issuer_label("https://identity.nolumia.com").as_deref(),
        )
        .expect("build uri");
        assert!(uri.starts_with("otpauth://totp/"), "{uri}");
        assert!(uri.contains("identity.nolumia.com"), "{uri}");
        assert!(uri.contains("kyon"), "{uri}");
    }

    /// The heading is only the host name. Scheme, credentials, port and path are dropped (a remaining `:` gets rejected).
    #[test]
    fn the_issuer_label_keeps_only_the_host() {
        assert_eq!(
            totp_issuer_label("https://identity.nolumia.com").as_deref(),
            Some("identity.nolumia.com")
        );
        assert_eq!(
            totp_issuer_label("http://localhost:8080").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            totp_issuer_label("https://u:p@idp.example.com:8443/realms/x").as_deref(),
            Some("idp.example.com")
        );
        // Already in heading form: as is.
        assert_eq!(totp_issuer_label("assay").as_deref(), Some("assay"));
        // If nothing remains, no heading (registration itself still works).
        assert_eq!(totp_issuer_label("https://"), None);
        assert_eq!(totp_issuer_label(""), None);
    }

    /// A derived heading is always accepted by totp-rs (no `:` remains).
    #[test]
    fn every_derived_label_is_accepted() {
        for issuer in [
            "https://identity.nolumia.com",
            "http://localhost:8080",
            "https://u:p@idp.example.com:8443/realms/x",
            "assay",
            "https://",
        ] {
            let label = totp_issuer_label(issuer);
            build_totp_uri(&[1u8; SECRET_BYTES], "someone", label.as_deref())
                .unwrap_or_else(|e| panic!("issuer={issuer:?} label={label:?}: {e}"));
        }
    }

    /// Generates the currently valid code with real time (same parameters as `verify_totp_code`).
    fn current_code(secret: &[u8]) -> (String, u64) {
        let totp = totp(secret, 0, None, "").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (totp.generate(now).to_string(), now / TOTP_STEP)
    }

    #[test]
    fn a_valid_code_returns_the_matching_step() {
        let secret = [7u8; SECRET_BYTES];
        let (code, step) = current_code(&secret);
        assert_eq!(verify_totp_code(&secret, &code).unwrap(), Some(step));
    }

    #[test]
    fn a_wrong_code_returns_none() {
        let secret = [7u8; SECRET_BYTES];
        // Build a 6-digit code that always differs from the current correct code (shift the last digit).
        let (code, _) = current_code(&secret);
        let last: u32 = code[5..6].parse().unwrap();
        let tampered = format!("{}{}", &code[..5], (last + 1) % 10);
        assert_eq!(verify_totp_code(&secret, &tampered).unwrap(), None);
    }

    /// The returned step is "the current time-step" (the value that serves as the basis for recording and reuse checks).
    #[test]
    fn the_returned_step_is_the_current_time_step() {
        let secret = [42u8; SECRET_BYTES];
        let (code, step) = current_code(&secret);
        let matched = verify_totp_code(&secret, &code).unwrap().unwrap();
        // Crossing a boundary between generation and verification can shift it by 1, so ±1 is allowed.
        assert!(
            matched == step || matched == step + 1 || matched + 1 == step,
            "matched={matched} step={step}"
        );
    }
}
