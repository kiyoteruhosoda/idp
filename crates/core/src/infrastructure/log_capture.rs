//! `tracing` の WARN / ERROR を DB 書き込みタスクへ渡すチャネル（CLAUDE.md「ログ」）。
//!
//! `tracing` のイベント処理はリクエスト処理スレッド上で同期に走るため、**ここでは決してブロックしない**。
//! 有界チャネルへ `try_send` し、詰まっていれば黙って捨てる（stdout の構造化ログには出ているので
//! 情報は失われない。DB 書き込みの遅延がリクエストを巻き込む方が有害）。
//!
//! 捨てた件数は数えておき、書き込みタスクが次のバッチと一緒に 1 行の警告として残す
//! （「捨てた」こと自体をログに出すと再帰するので、DB 側には数だけを載せる）。

use assay_contracts::application_log::{ApplicationLogPayload, CapturedLogSink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// チャネル容量。バーストを吸収しつつ、詰まったら捨てる方針なので過大にしない。
pub const CHANNEL_CAPACITY: usize = 1_024;

/// `tracing` 層から書き込みタスクへの送信端。
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

/// 書き込みタスク側の受信端。取り出しは [`ApplicationLogReceiver::recv_batch`] で行う。
pub struct ApplicationLogReceiver {
    rx: mpsc::Receiver<ApplicationLogPayload>,
    dropped: Arc<AtomicU64>,
}

impl ApplicationLogReceiver {
    /// 1 件以上たまるまで待ち、最大 `max` 件をまとめて取り出す。チャネルが閉じたら `None`。
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

    /// 直前までに捨てた件数を取り出してカウンタを 0 に戻す。
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// 送信端と受信端の対を作る。
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
        // 取り出したらカウンタは戻る。
        assert_eq!(rx.take_dropped(), 0);
    }

    #[tokio::test]
    async fn returns_none_after_senders_drop() {
        let (sink, mut rx) = channel();
        drop(sink);
        assert!(rx.recv_batch(10).await.is_none());
    }
}
