//! Bulk GC of expired records (G2).
//!
//! Tables of in-progress state and one-time tokens "lose meaning once they expire", but deleting them belongs
//! to no use case. Growing a cleanup loop per table means one is missed with every addition, so
//! cleaners implementing [`crate::domain::repositories::ExpiringRecordStore`] are bundled into one task.
//!
//! The list of cleaners is in [`crate::infrastructure::repositories::expired_records`].

use crate::domain::clock::Clock;
use crate::domain::repositories::ExpiringRecordStore;
use std::sync::Arc;

pub struct ExpiredRecordPurgeService {
    stores: Vec<Arc<dyn ExpiringRecordStore>>,
    clock: Arc<dyn Clock>,
}

impl ExpiredRecordPurgeService {
    pub fn new(stores: Vec<Arc<dyn ExpiringRecordStore>>, clock: Arc<dyn Clock>) -> Self {
        Self { stores, clock }
    }

    /// Makes one pass over every target table deleting expired rows, and returns the total number deleted.
    ///
    /// **A failure in one table does not stop the rest.** If a lock wait or deadlock in one table stopped
    /// the whole pass, unrelated tables would grow without bound (having no cleanup at all was the G2 symptom).
    /// Failures are logged with the table name and retried on the next cycle.
    pub async fn purge_once(&self) -> u64 {
        let now = self.clock.now();
        let mut total = 0;
        for store in &self.stores {
            let table = store.table_name();
            match store.purge_expired(now).await {
                Ok(0) => {}
                Ok(deleted) => {
                    total += deleted;
                    tracing::debug!(table, deleted, "purged expired rows");
                }
                Err(e) => {
                    tracing::error!(table, error = %e, "expired record purge failed");
                }
            }
        }
        total
    }

    /// Names of the tables to clean (for the startup log and tests).
    pub fn table_names(&self) -> Vec<&'static str> {
        self.stores.iter().map(|s| s.table_name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::{DomainError, Result};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
        }
    }

    struct FakeStore {
        table: &'static str,
        deleted: u64,
        fail: bool,
        calls: AtomicU64,
    }
    #[async_trait]
    impl ExpiringRecordStore for FakeStore {
        fn table_name(&self) -> &'static str {
            self.table
        }
        async fn purge_expired(&self, _now: DateTime<Utc>) -> Result<u64> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(DomainError::Repository("boom".to_string()));
            }
            Ok(self.deleted)
        }
    }

    /// Even if one table fails, the tables after it are cleaned. If this stopped, "uncleaned tables"
    /// would quietly keep growing, back to the G2 symptom.
    #[tokio::test]
    async fn a_failing_table_does_not_stop_the_rest() {
        let failing = Arc::new(FakeStore {
            table: "first",
            deleted: 0,
            fail: true,
            calls: AtomicU64::new(0),
        });
        let healthy = Arc::new(FakeStore {
            table: "second",
            deleted: 3,
            fail: false,
            calls: AtomicU64::new(0),
        });
        let service = ExpiredRecordPurgeService::new(
            vec![failing.clone(), healthy.clone()],
            Arc::new(FixedClock),
        );

        assert_eq!(service.purge_once().await, 3);
        assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
        assert_eq!(healthy.calls.load(Ordering::SeqCst), 1);
    }
}
