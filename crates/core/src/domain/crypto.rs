//! 暗号ユーティリティ: 乱数トークン生成、SHA-256、base64url、秘密鍵の暗号化（AES-256-GCM）。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

const GCM_NONCE_LEN: usize = 12;

/// 暗号学的乱数から `n_bytes` バイトを生成し、base64url（パディング無し）で返す。
/// セッション ID / authorization code / auth_session id などの生成に使う。
pub fn random_token(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// 暗号学的乱数から `n_bytes` バイトを生成し、小文字 16 進で返す。
/// DB キーに使う識別子（`auth_sessions.id`・SSO session_id 等）は ci 照合下でも
/// 厳密一致となるよう小文字 16 進で生成する。
pub fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// SHA-256 の 16 進小文字表現（64 文字）。code_hash / session_hash に使う。
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

/// バイト列を base64url（パディング無し）へ。JWK の `n` / `e` などに使う。
pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 平文を AES-256-GCM で暗号化し、`base64(nonce || ciphertext)` を返す。
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut combined = Vec::with_capacity(GCM_NONCE_LEN + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(combined))
}

/// [`encrypt`] の逆。`base64(nonce || ciphertext)` を復号して平文バイト列を返す。
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let combined = STANDARD
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("invalid base64 ciphertext: {e}"))?;
    if combined.len() < GCM_NONCE_LEN {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = combined.split_at(GCM_NONCE_LEN);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
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
        // 32 バイト → base64url(パディング無し)で 43 文字。
        assert_eq!(random_token(32).len(), 43);
        // 生成のたびに異なる。
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
