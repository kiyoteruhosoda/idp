//! argon2 による [`PasswordHasher`] 実装。

use crate::domain::error::DomainError;
use crate::domain::password::PasswordHasher;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString};
use argon2::Argon2;

#[derive(Default)]
pub struct Argon2PasswordHasher;

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, password: &str) -> Result<String, DomainError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| DomainError::Repository(format!("password hashing failed: {e}")))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| DomainError::Repository(format!("invalid password hash: {e}")))?;
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
}
