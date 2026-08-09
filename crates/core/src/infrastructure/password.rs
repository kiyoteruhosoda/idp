//! argon2 による [`PasswordHasher`] 実装。
//!
//! パラメータは**明示する**（SEC12）。`Argon2::default()` に任せると、依存を更新したときに
//! 既定値が変わってコスト（＝耐総当たり性と CPU/メモリ使用量の両方）が黙って動く。値は
//! OWASP Password Storage Cheat Sheet の Argon2id 推奨（19 MiB・2 反復・並列度 1）に合わせた。
//!
//! **検証時はパラメータを使わない。** PHC 文字列（`$argon2id$v=19$m=...,t=...,p=...$salt$hash`）が
//! 自分のパラメータを持つため、ここを変えても既存のハッシュは検証し続けられる（新しいハッシュだけが
//! 新しいコストで作られる）。

use crate::domain::error::DomainError;
use crate::domain::password::PasswordHasher;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// メモリコスト（KiB）。OWASP 推奨の 19 MiB。
const MEMORY_KIB: u32 = 19 * 1024;
/// 反復回数。
const ITERATIONS: u32 = 2;
/// 並列度（レーン数）。
const PARALLELISM: u32 = 1;

#[derive(Default)]
pub struct Argon2PasswordHasher;

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }

    /// ハッシュ生成に使う Argon2id インスタンス（パラメータ明示）。
    fn hasher() -> Argon2<'static> {
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
            .expect("argon2 parameters are compile-time constants within the allowed range");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, password: &str) -> Result<String, DomainError> {
        let salt = SaltString::generate(&mut OsRng);
        Self::hasher()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| DomainError::Repository(format!("password hashing failed: {e}")))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| DomainError::Repository(format!("invalid password hash: {e}")))?;
        // 検証側は PHC 文字列に埋まったパラメータで動くため、既定インスタンスでよい
        // （パラメータを変更しても既存ハッシュが検証できなくならない）。
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_succeeds_and_rejects_wrong_password() {
        let hasher = Argon2PasswordHasher::new();
        let hash = hasher.hash("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(hasher
            .verify("correct horse battery staple", &hash)
            .unwrap());
        assert!(!hasher.verify("wrong password", &hash).unwrap());
    }

    /// パラメータを明示していること自体を固定する（依存更新で既定値が動いても気付けるように）。
    #[test]
    fn hashes_carry_the_explicit_parameters() {
        let hash = Argon2PasswordHasher::new().hash("pw").unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected PHC parameters: {hash}"
        );
    }

    /// 別パラメータで作られた既存ハッシュも検証できる（パラメータ変更が既存利用者を締め出さない）。
    #[test]
    fn verifies_hashes_made_with_other_parameters() {
        use argon2::password_hash::{PasswordHasher as _, SaltString};
        let salt = SaltString::from_b64("c29tZXNhbHR2YWx1ZQ").unwrap();
        let legacy = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password(b"pw", &salt)
        .unwrap()
        .to_string();
        assert!(Argon2PasswordHasher::new().verify("pw", &legacy).unwrap());
    }
}
