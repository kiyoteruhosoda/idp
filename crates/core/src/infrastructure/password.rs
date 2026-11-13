//! [`PasswordHasher`] implementation with argon2.
//!
//! Parameters are **explicit** (SEC12). Leaving it to `Argon2::default()` would let the defaults change when
//! dependencies are updated, silently shifting the cost (both brute-force resistance and CPU/memory usage). The values
//! follow the OWASP Password Storage Cheat Sheet's Argon2id recommendation (19 MiB, 2 iterations, parallelism 1).
//!
//! **Verification does not use the parameters.** The PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`)
//! carries its own parameters, so changing these keeps existing hashes verifiable (only new hashes
//! are created at the new cost).

use crate::domain::error::DomainError;
use crate::domain::password::PasswordHasher;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};

/// Memory cost (KiB). OWASP's recommended 19 MiB.
const MEMORY_KIB: u32 = 19 * 1024;
/// Number of iterations.
const ITERATIONS: u32 = 2;
/// Degree of parallelism (lanes).
const PARALLELISM: u32 = 1;

#[derive(Default)]
pub struct Argon2PasswordHasher;

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }

    /// Argon2id instance used for hashing (explicit parameters).
    fn hasher() -> Argon2<'static> {
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
            .expect("argon2 parameters are compile-time constants within the allowed range");
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }
}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, password: &str) -> Result<String, DomainError> {
        // The salt is generated automatically from OS randomness (`hash_password` of password-hash 0.6).
        Self::hasher()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| DomainError::Repository(format!("password hashing failed: {e}")))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| DomainError::Repository(format!("invalid password hash: {e}")))?;
        // Verification runs with the parameters embedded in the PHC string, so the default instance is fine
        // (changing parameters doesn't make existing hashes unverifiable).
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

    /// Pins the fact that parameters are explicit (so a default shift from a dependency update is noticed).
    #[test]
    fn hashes_carry_the_explicit_parameters() {
        let hash = Argon2PasswordHasher::new().hash("pw").unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected PHC parameters: {hash}"
        );
    }

    /// Existing hashes made with other parameters still verify (a parameter change doesn't lock out existing users).
    #[test]
    fn verifies_hashes_made_with_other_parameters() {
        use argon2::password_hash::PasswordHasher as _;
        let legacy = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8 * 1024, 1, 1, None).unwrap(),
        )
        .hash_password_with_salt(b"pw", b"somesaltvalue")
        .unwrap()
        .to_string();
        assert!(Argon2PasswordHasher::new().verify("pw", &legacy).unwrap());
    }
}
