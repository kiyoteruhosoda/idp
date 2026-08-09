//! 期限切れレコードの一括 GC（G2）。
//!
//! 進行状態・使い捨てトークンの表は「期限が来たら意味を失う」が、消す主体はどのユースケースにも
//! 属さない。表ごとに掃除ループを生やすと追加のたびに漏れるため、
//! [`crate::domain::repositories::ExpiringRecordStore`] を実装した掃除口を 1 本のタスクへ束ねる。
//!
//! 掃除口の一覧は [`crate::infrastructure::repositories::expired_records`] にある。

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

    /// 全対象表を 1 巡して期限切れ行を削除し、削除できた合計件数を返す。
    ///
    /// **1 つの表の失敗で残りを止めない。** ある表のロック待ちやデッドロックで巡回全体が
    /// 止まると、無関係な表が無限に伸び続ける（そもそも掃除が無かったのが G2 の症状である）。
    /// 失敗は表名付きで記録し、次の周期で再試行する。
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

    /// 掃除対象の表名（起動ログ・テスト用）。
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

    /// 1 つの表が失敗しても、その後ろの表は掃除される。ここが止まると「掃除されない表」が
    /// 静かに増え続け、G2 の症状に戻る。
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
