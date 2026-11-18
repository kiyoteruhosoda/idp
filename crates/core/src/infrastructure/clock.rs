//! Real-time `Clock` implementation.

use crate::domain::clock::Clock;
use time::OffsetDateTime;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
