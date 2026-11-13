//! Abstraction over reading the time (a boundary so tests can swap in a fixed implementation).
//!
//! Real time must always be read through this trait (`CLAUDE.md` "Tests"). Implemented in the infrastructure layer.

use chrono::{DateTime, Utc};

pub trait Clock: Send + Sync {
    /// Current time (always UTC).
    fn now(&self) -> DateTime<Utc>;
}
