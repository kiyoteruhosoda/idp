//! Abstraction for password hashing (DIP boundary). Implemented in the infrastructure layer
//! (argon2).
//!
//! The requirements for "may this password be accepted" live in
//! [`crate::domain::password_policy`] (length, breaches, reuse, expiry).

use crate::domain::error::DomainError;

pub trait PasswordHasher: Send + Sync {
    /// Hashes a plaintext password and returns a PHC string.
    fn hash(&self, password: &str) -> Result<String, DomainError>;
    /// Verifies whether a plaintext password matches a stored hash.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;
}

/// For a nonexistent (or ambiguous, unresolved) user, runs one password verification with
/// **the same cost** as for a real user, so response time does not reveal whether the user exists
/// (anti-enumeration; "uniform timing" in the OWASP Authentication Cheat Sheet).
///
/// The reference hash is generated once with the real hasher on first use and reused (hashing every
/// time would double the cost). The plaintext used is not secret and the value never affects the
/// result — callers discard the return value and always return a credentials error. If generation
/// fails, it gives up silently (best-effort; uniform timing is an added defense, not the deciding
/// check).
pub fn verify_against_dummy(hasher: &dyn PasswordHasher, presented_password: &str) {
    use std::sync::OnceLock;
    static DUMMY_HASH: OnceLock<Option<String>> = OnceLock::new();
    let dummy = DUMMY_HASH.get_or_init(|| hasher.hash("timing-equalizer.not-a-credential").ok());
    if let Some(hash) = dummy {
        // The result is unused. The only purpose is to spend the same argon2 work as `verify` for a
        // real user.
        let _ = hasher.verify(presented_password, hash);
    }
}
