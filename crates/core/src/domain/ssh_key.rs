//! SSH public keys users register themselves (task #885; ADR-0072).
//!
//! So SSH keys cannot be stolen even if the owner's PC is taken over by malware, only **sk-type**
//! keys can be registered (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`). The
//! private key of an sk-type key lives inside a security key, TPM (Windows Hello), or a phone
//! passkey; the PC's file holds only a "key handle". Each use requires confirmation on the device
//! (touch, fingerprint, PIN).
//!
//! # What is checked here
//!
//! - The shape of one authorized_keys line (`type blob [comment]`; lines with leading options are
//!   not accepted)
//! - The blob (base64) opens and reads as an OpenSSH public key sequence (a series of strings per
//!   RFC 4253 §6.6), the type written inside matches the first field, key lengths match the type,
//!   and nothing is left over
//! - Anything that looks like a private key (`-----BEGIN … PRIVATE KEY-----`) is refused **without
//!   reading its content**
//!
//! The fingerprint is `SHA256:` + base64 (no padding) of the blob's SHA-256, same as
//! `ssh-keygen -l`.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::tenant::TenantId;

/// Upper bound on key name length (characters).
pub const MAX_SSH_KEY_NAME_CHARS: usize = 100;

/// Upper bound on keys one person can register in one organization (keeps the distributed
/// authorized_keys small).
pub const MAX_SSH_KEYS_PER_USER: usize = 10;

/// Upper bound on the pasted string length (bytes). An sk-type public key line is under 300 bytes.
const MAX_INPUT_BYTES: usize = 4096;

/// Upper bound on the decoded blob length (bytes).
const MAX_BLOB_BYTES: usize = 300;

/// Upper bound on the length (bytes) of an sk-type `application` (FIDO rp id; default `ssh:`).
const MAX_APPLICATION_BYTES: usize = 128;

/// Accepted key types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyType {
    /// `ssh-keygen -t ed25519-sk` (security key).
    SkEd25519,
    /// `ssh-keygen -t ecdsa-sk` (Windows Hello, phone passkeys, many security keys).
    SkEcdsaP256,
}

impl SshKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "sk-ssh-ed25519@openssh.com" => Some(Self::SkEd25519),
            "sk-ecdsa-sha2-nistp256@openssh.com" => Some(Self::SkEcdsaP256),
            _ => None,
        }
    }
}

/// Why a public key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyRejection {
    /// Something that looks like a private key was pasted (its content is neither read nor stored).
    LooksLikePrivateKey,
    /// Not sk-type (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, etc., types with the private
    /// key in a file).
    NotSecurityKeyType,
    /// Malformed (not base64, unreadable sequence, mismatched type, wrong length, empty).
    Malformed,
}

/// A verified public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKey {
    key_type: SshKeyType,
    /// Blob (base64, normalized to the standard padded form).
    blob: String,
    fingerprint: String,
}

impl SshPublicKey {
    /// Checks one pasted authorized_keys line. The comment is dropped.
    pub fn parse(raw: &str) -> Result<Self, SshKeyRejection> {
        if raw.contains("PRIVATE KEY") {
            return Err(SshKeyRejection::LooksLikePrivateKey);
        }
        if raw.len() > MAX_INPUT_BYTES {
            return Err(SshKeyRejection::Malformed);
        }
        // Exactly one line (surrounding whitespace / newlines are dropped; two or more lines are
        // refused).
        let line = raw.trim();
        if line.is_empty() || line.contains('\n') || line.contains('\r') {
            return Err(SshKeyRejection::Malformed);
        }
        let mut fields = line.split_ascii_whitespace();
        let (Some(type_field), Some(blob_field)) = (fields.next(), fields.next()) else {
            return Err(SshKeyRejection::Malformed);
        };
        let Some(key_type) = SshKeyType::parse(type_field) else {
            return Err(if looks_like_key_type(type_field) {
                SshKeyRejection::NotSecurityKeyType
            } else {
                SshKeyRejection::Malformed
            });
        };
        let bytes = STANDARD
            .decode(blob_field)
            .map_err(|_| SshKeyRejection::Malformed)?;
        if bytes.is_empty() || bytes.len() > MAX_BLOB_BYTES {
            return Err(SshKeyRejection::Malformed);
        }
        check_blob(key_type, &bytes)?;
        Ok(Self {
            key_type,
            blob: STANDARD.encode(&bytes),
            fingerprint: fingerprint_of(&bytes),
        })
    }

    /// Wraps a value read from the DB (it was checked when stored).
    pub fn from_stored(key_type: SshKeyType, blob: String, fingerprint: String) -> Self {
        Self {
            key_type,
            blob,
            fingerprint,
        }
    }

    pub fn key_type(&self) -> SshKeyType {
        self.key_type
    }

    pub fn blob(&self) -> &str {
        &self.blob
    }

    /// `SHA256:…` (same as `ssh-keygen -l -E sha256`).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The form written to authorized_keys (`type blob`; no comment or options).
    pub fn authorized_key(&self) -> String {
        format!("{} {}", self.key_type.as_str(), self.blob)
    }
}

/// Whether it is the name of a type that keeps the private key in a file (to tell "not sk-type"
/// from "malformed").
fn looks_like_key_type(field: &str) -> bool {
    field.starts_with("ssh-")
        || field.starts_with("ecdsa-sha2-")
        || field.starts_with("sk-")
        || field.starts_with("rsa-sha2-")
}

/// Fingerprint (`SHA256:` + base64, no padding).
pub fn fingerprint_of(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// Reads the blob's sequence (RFC 4253 §6.6, OpenSSH PROTOCOL.u2f).
///
/// - `sk-ssh-ed25519@openssh.com`: string type, string public key (32 bytes), string application
/// - `sk-ecdsa-sha2-nistp256@openssh.com`: string type, string `nistp256`, string point
///   (uncompressed 65 bytes), string application
fn check_blob(key_type: SshKeyType, bytes: &[u8]) -> Result<(), SshKeyRejection> {
    let mut reader = WireReader(bytes);
    if reader.string()? != key_type.as_str().as_bytes() {
        return Err(SshKeyRejection::Malformed);
    }
    match key_type {
        SshKeyType::SkEd25519 => {
            if reader.string()?.len() != 32 {
                return Err(SshKeyRejection::Malformed);
            }
        }
        SshKeyType::SkEcdsaP256 => {
            if reader.string()? != b"nistp256" {
                return Err(SshKeyRejection::Malformed);
            }
            let point = reader.string()?;
            if point.len() != 65 || point[0] != 0x04 {
                return Err(SshKeyRejection::Malformed);
            }
        }
    }
    let application = reader.string()?;
    if application.is_empty()
        || application.len() > MAX_APPLICATION_BYTES
        || std::str::from_utf8(application).is_err()
    {
        return Err(SshKeyRejection::Malformed);
    }
    if !reader.0.is_empty() {
        return Err(SshKeyRejection::Malformed);
    }
    Ok(())
}

/// Reads an SSH wire-format string (4-byte length + content) from the front.
struct WireReader<'a>(&'a [u8]);

impl<'a> WireReader<'a> {
    fn string(&mut self) -> Result<&'a [u8], SshKeyRejection> {
        if self.0.len() < 4 {
            return Err(SshKeyRejection::Malformed);
        }
        let (len, rest) = self.0.split_at(4);
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        if rest.len() < len {
            return Err(SshKeyRejection::Malformed);
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

/// Tidies a name. Trims surrounding whitespace; empty, too long, or containing control characters
/// gives `None`.
pub fn normalize_ssh_key_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.chars().count() > MAX_SSH_KEY_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return None;
    }
    Some(name.to_string())
}

/// A registered SSH key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSshKey {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub name: String,
    pub key: SshPublicKey,
    pub created_at: DateTime<Utc>,
}

/// One line handed to distributing machines (with the user name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedSshKey {
    /// assay's user name (`preferred_username`).
    pub username: String,
    pub name: String,
    pub key: SshPublicKey,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
pub(crate) mod testing {
    //! Builds test keys (in the same sequence as real `ssh-keygen` output).
    use super::*;

    fn put(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    /// One `sk-ssh-ed25519@openssh.com` line (`seed` varies the key).
    pub fn ed25519_sk_line(seed: u8) -> String {
        let mut blob = Vec::new();
        put(&mut blob, b"sk-ssh-ed25519@openssh.com");
        put(&mut blob, &[seed; 32]);
        put(&mut blob, b"ssh:");
        format!(
            "sk-ssh-ed25519@openssh.com {} kyon@kyon-pc",
            STANDARD.encode(blob)
        )
    }

    /// One `sk-ecdsa-sha2-nistp256@openssh.com` line.
    pub fn ecdsa_sk_line(seed: u8) -> String {
        let mut point = vec![0x04];
        point.extend_from_slice(&[seed; 64]);
        let mut blob = Vec::new();
        put(&mut blob, b"sk-ecdsa-sha2-nistp256@openssh.com");
        put(&mut blob, b"nistp256");
        put(&mut blob, &point);
        put(&mut blob, b"ssh:");
        format!(
            "sk-ecdsa-sha2-nistp256@openssh.com {} windows-hello",
            STANDARD.encode(blob)
        )
    }

    /// One `ssh-ed25519` (file key) line.
    pub fn ed25519_file_line() -> String {
        let mut blob = Vec::new();
        put(&mut blob, b"ssh-ed25519");
        put(&mut blob, &[7; 32]);
        format!("ssh-ed25519 {} kyon@kyon-pc", STANDARD.encode(blob))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn security_key_types_are_accepted_and_comments_are_dropped() {
        let key = SshPublicKey::parse(&ed25519_sk_line(1)).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEd25519);
        assert!(key
            .authorized_key()
            .starts_with("sk-ssh-ed25519@openssh.com AAAA"));
        assert!(!key.authorized_key().contains("kyon@kyon-pc"));

        let key = SshPublicKey::parse(&format!("  {}\n", ecdsa_sk_line(2))).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEcdsaP256);
        assert!(!key.authorized_key().contains("windows-hello"));
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // ssh-keygen -l prefixes the base64 (no padding) of the SHA-256 with `SHA256:`.
        let key = SshPublicKey::parse(&ed25519_sk_line(1)).unwrap();
        let blob = STANDARD.decode(key.blob()).unwrap();
        let expected = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob)));
        assert_eq!(key.fingerprint(), expected);
        assert_eq!(key.fingerprint().len(), 50);
        assert_ne!(
            key.fingerprint(),
            SshPublicKey::parse(&ed25519_sk_line(2))
                .unwrap()
                .fingerprint()
        );
    }

    /// Fingerprint `ssh-keygen -l -E sha256` printed for the same line (measured with OpenSSH 10;
    /// the public key sequence is the same as [`ed25519_sk_line`] with `seed = 1`).
    #[test]
    fn fingerprint_is_the_one_ssh_keygen_prints() {
        let line = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAABHNzaDo= test";
        let key = SshPublicKey::parse(line).unwrap();
        assert_eq!(key.key_type(), SshKeyType::SkEd25519);
        assert_eq!(
            key.fingerprint(),
            "SHA256:1rYiSPZV2H9QsZrfrX/5nhreVmcpuSKQQYA/CKjnPfU"
        );
        assert_eq!(key, SshPublicKey::parse(&ed25519_sk_line(1)).unwrap());
    }

    #[test]
    fn file_keys_are_refused_as_not_security_keys() {
        assert_eq!(
            SshPublicKey::parse(&ed25519_file_line()),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
        assert_eq!(
            SshPublicKey::parse("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 kyon"),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
        assert_eq!(
            SshPublicKey::parse("ecdsa-sha2-nistp256 AAAAE2VjZHNh kyon"),
            Err(SshKeyRejection::NotSecurityKeyType)
        );
    }

    #[test]
    fn private_keys_are_refused_without_reading_them() {
        let pasted = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(
            SshPublicKey::parse(pasted),
            Err(SshKeyRejection::LooksLikePrivateKey)
        );
        assert_eq!(
            SshPublicKey::parse("-----BEGIN PRIVATE KEY-----"),
            Err(SshKeyRejection::LooksLikePrivateKey)
        );
    }

    #[test]
    fn broken_keys_are_refused() {
        let good = ed25519_sk_line(1);
        let blob = good.split(' ').nth(1).unwrap();
        for bad in [
            String::new(),
            "   ".to_string(),
            "sk-ssh-ed25519@openssh.com".to_string(),
            "sk-ssh-ed25519@openssh.com !!!notbase64".to_string(),
            // The first field and the inner type disagree
            format!("sk-ecdsa-sha2-nistp256@openssh.com {blob}"),
            // Truncated blob
            format!("sk-ssh-ed25519@openssh.com {}", &blob[..blob.len() - 8]),
            // Two lines
            format!("{good}\n{good}"),
            // Line with options
            format!("from=\"10.0.0.0/8\" {good}"),
            "hello world".to_string(),
        ] {
            assert!(SshPublicKey::parse(&bad).is_err(), "{bad:?}");
        }
        // Blob with trailing leftover bytes
        let mut bytes = STANDARD.decode(blob).unwrap();
        bytes.push(0);
        assert_eq!(
            SshPublicKey::parse(&format!(
                "sk-ssh-ed25519@openssh.com {}",
                STANDARD.encode(bytes)
            )),
            Err(SshKeyRejection::Malformed)
        );
    }

    #[test]
    fn key_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_ssh_key_name("  kyon-pc ").as_deref(),
            Some("kyon-pc")
        );
        assert!(normalize_ssh_key_name("").is_none());
        assert!(normalize_ssh_key_name("a\tb").is_none());
        assert!(normalize_ssh_key_name(&"あ".repeat(MAX_SSH_KEY_NAME_CHARS + 1)).is_none());
    }
}
