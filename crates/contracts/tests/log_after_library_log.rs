//! ライブラリが `log` クレートを呼んだ直後の WARN / ERROR が、stdout と取り込み層の両方へ届くこと
//! （task #801）。
//!
//! `.init()` は `LogTracer` も入れるので、`log` の呼び出しは購読者の `enabled` へ届く。どの層も
//! 欲しがらないレコード（本番の `RUST_LOG` での sqlx の `log_enabled!` など）だと、層ごとのフィルタの
//! 「無効」の印が event を伴わないまま、そのスレッドに残る。
//!
//! ⚠ **この試験はこのファイルに 1 つだけ置く。** グローバルな購読者と `LogTracer` は 1 プロセスに
//! 1 回しか入らず、同じプロセスで別の購読者が並ぶと呼び出しごとの `Interest` が混ざって、再現しなくなる。

use assay_contracts::application_log::{
    capture_filter, ApplicationLogCaptureLayer, ApplicationLogPayload, CapturedLogSink, SERVICE_API,
};
use std::sync::{Arc, Mutex};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Clone, Default)]
struct CollectingSink(Arc<Mutex<Vec<ApplicationLogPayload>>>);

impl CapturedLogSink for CollectingSink {
    fn submit(&self, record: ApplicationLogPayload) {
        self.0.lock().expect("sink").push(record);
    }
}

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedBuffer;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn warn_and_error_after_an_unwanted_library_log_reach_both_layers() {
    let sink = CollectingSink::default();
    let stdout = SharedBuffer::default();
    // 本番（`telemetry::init`）と同じ層の重ね方・同じ `RUST_LOG`。
    tracing_subscriber::registry()
        .with(
            ApplicationLogCaptureLayer::new(SERVICE_API, sink.clone())
                .with_filter(capture_filter()),
        )
        .with(
            fmt::layer()
                .json()
                .flatten_event(true)
                .with_writer(stdout.clone())
                .with_filter(EnvFilter::new("info,assay=info")),
        )
        .init();

    let delivered = |message: &str| {
        let printed = String::from_utf8_lossy(&stdout.0.lock().expect("buffer")).contains(message);
        let captured = sink
            .0
            .lock()
            .expect("sink")
            .iter()
            .any(|r| r.message == message);
        (printed, captured)
    };

    // sqlx が問い合わせのたびに呼ぶ形（`QueryLogger::finish`）。
    assert!(!log::log_enabled!(target: "sqlx::query", log::Level::Debug));
    tracing::warn!("warn after log_enabled");
    assert_eq!(delivered("warn after log_enabled"), (true, true));

    // ライブラリの普通の `log::debug!` も同じ。
    log::debug!(target: "some_library", "nobody wants this");
    tracing::error!("error after log debug");
    assert_eq!(delivered("error after log debug"), (true, true));
}
