//! Abstraction for entity ID generation (a boundary for swapping in fixed values in tests; ADR-0009
//! §12).
//!
//! Production ID generation always goes through this trait (`CLAUDE.md` "Tests"; injected like time
//! and randomness). Generated UUIDs are UUIDv7 (time-ordered). Volatile tokens such as `jti`,
//! `correlation_id`, `csrf_id` are outside this abstraction; callers use `Uuid::new_v4()` directly
//! (time ordering is not needed and we do not want to expose the creation time).

use uuid::Uuid;

pub trait IdGenerator: Send + Sync {
    /// Generates a UUID (UUIDv7) for an entity primary key.
    fn new_id(&self) -> Uuid;
}
