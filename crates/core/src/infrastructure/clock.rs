//! Real-time `Clock` implementation.

use crate::domain::clock::Clock;
use chrono::{DateTime, Utc};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
