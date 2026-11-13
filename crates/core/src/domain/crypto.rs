//! Crypto utilities: random token generation, SHA-256, base64url, private-key encryption (AES-256-GCM).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};

const GCM_NONCE_LEN: usize = 12;

/// Generates `n_bytes` bytes from a cryptographic RNG and returns them as base64url (no padding).
/// Used to generate session IDs / authorization codes / auth_session ids, etc.
pub fn random_token(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Generates `n_bytes` bytes from a cryptographic RNG and returns them as lowercase hex.
/// Identifiers used as DB keys (`auth_sessions.id`, SSO session_id, etc.) are generated as lowercase hex
/// so they match exactly even under a ci collation.
pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Lowercase hex representation of SHA-256 (64 chars). Used for code_hash / session_hash.
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

/// Bytes to base64url (no padding). Used for JWK `n` / `e`, etc.
pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Encrypts plaintext with AES-256-GCM and returns `base64(nonce || ciphertext)`.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));

    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut combined = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(combined))
}

/// Inverse of [`encrypt`]. Decrypts `base64(nonce || ciphertext)` and returns the plaintext bytes.
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let combined = STANDARD
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("invalid base64 ciphertext: {e}"))?;
    if combined.len() < GCM_NONCE_LEN {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = combined.split_at(GCM_NONCE_LEN);

    // The length was checked above, so this only fails if GCM_NONCE_LEN and the type disagree.
    let nonce =
        Nonce::try_from(nonce_bytes).map_err(|_| anyhow::anyhow!("invalid nonce length"))?;

    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn random_token_has_expected_length() {
        // 32 bytes -> 43 chars in base64url (no padding).
        assert_eq!(random_token(32).len(), 43);
        // Differs on every generation.
        assert_ne!(random_token(32), random_token(32));
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let key = [7u8; 32];
        let secret = b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----";
        let ct = encrypt(secret, &key).unwrap();
        let pt = decrypt(&ct, &key).unwrap();
        assert_eq!(pt, secret);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let ct = encrypt(b"data", &[1u8; 32]).unwrap();
        assert!(decrypt(&ct, &[2u8; 32]).is_err());
    }
}
