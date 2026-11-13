//! Channel handing `tracing` WARN / ERROR events to the DB write task (CLAUDE.md "Logging").
//!
//! `tracing` event handling runs synchronously on request-processing threads, so **this never blocks**.
//! It does `try_send` into a bounded channel and silently drops when full (the information is in the stdout
//! structured log, so nothing is lost; DB write latency dragging requests down would be worse).
//!
//! The number dropped is counted, and the write task records it as a one-line warning with the next batch
//! (logging "dropped" itself would recurse, so only the count goes to the DB).

use assay_contracts::application_log::{ApplicationLogPayload, CapturedLogSink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Channel capacity. Absorbs bursts, but drops when full by policy, so it is not oversized.
pub const CHANNEL_CAPACITY: usize = 1_024;

/// Sending end from the `tracing` layer to the write task.
#[derive(Clone)]
pub struct ChannelLogSink {
    tx: mpsc::Sender<ApplicationLogPayload>,
    dropped: Arc<AtomicU64>,
}

impl CapturedLogSink for ChannelLogSink {
    fn submit(&self, record: ApplicationLogPayload) {
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Receiving end on the write task side. Take items with [`ApplicationLogReceiver::recv_batch`].
pub struct ApplicationLogReceiver {
    rx: mpsc::Receiver<ApplicationLogPayload>,
    dropped: Arc<AtomicU64>,
}

impl ApplicationLogReceiver {
    /// Waits until at least one item is queued, then takes up to `max` items at once. `None` when the channel is closed.
    pub async fn recv_batch(&mut self, max: usize) -> Option<Vec<ApplicationLogPayload>> {
        let first = self.rx.recv().await?;
        let mut batch = Vec::with_capacity(max.min(CHANNEL_CAPACITY));
        batch.push(first);
        while batch.len() < max {
            match self.rx.try_recv() {
                Ok(record) => batch.push(record),
                Err(_) => break,
            }
        }
        Some(batch)
    }

    /// Takes the number dropped so far and resets the counter to 0.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Creates a sender/receiver pair.
pub fn channel() -> (ChannelLogSink, ApplicationLogReceiver) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));
    (
        ChannelLogSink {
            tx,
            dropped: dropped.clone(),
        },
        ApplicationLogReceiver { rx, dropped },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(message: &str) -> ApplicationLogPayload {
        ApplicationLogPayload {
            occurred_at: "2026-07-27T00:00:00Z".to_string(),
            level: "ERROR".to_string(),
            service: "api".to_string(),
            target: "assay_api::test".to_string(),
            message: message.to_string(),
            correlation_id: None,
            tenant_id: None,
            traceback: None,
        }
    }

    #[tokio::test]
    async fn batches_available_records() {
        let (sink, mut rx) = channel();
        sink.submit(payload("one"));
        sink.submit(payload("two"));
        let batch = rx.recv_batch(10).await.expect("batch");
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].message, "one");
    }

    #[tokio::test]
    async fn caps_batch_size() {
        let (sink, mut rx) = channel();
        for i in 0..5 {
            sink.submit(payload(&i.to_string()));
        }
        assert_eq!(rx.recv_batch(2).await.expect("batch").len(), 2);
        assert_eq!(rx.recv_batch(10).await.expect("batch").len(), 3);
    }

    #[tokio::test]
    async fn drops_and_counts_when_full() {
        let (sink, rx) = channel();
        for _ in 0..(CHANNEL_CAPACITY + 7) {
            sink.submit(payload("x"));
        }
        assert_eq!(rx.take_dropped(), 7);
        // The counter resets once taken.
        assert_eq!(rx.take_dropped(), 0);
    }

    #[tokio::test]
    async fn returns_none_after_senders_drop() {
        let (sink, mut rx) = channel();
        drop(sink);
        assert!(rx.recv_batch(10).await.is_none());
    }
}
