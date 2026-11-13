//! WARN / ERROR right after a library calls the `log` crate reach both stdout and the ingestion layer
//! (task #801).
//!
//! `.init()` also installs `LogTracer`, so `log::log_enabled!` reaches the subscriber's `enabled`, and for a
//! record no layer wants, the per-layer filter's "disabled" mark stays on that thread without an event.
//! With the production `RUST_LOG` this happens after every sqlx query.
//!
//! ⚠ **Keep only one test in this file.** The global subscriber and `LogTracer` can be installed only
//! once per process; with other subscribers in the same process, per-callsite `Interest` mixes and it no longer reproduces.

use assay_contracts::application_log::{
    ApplicationLogCaptureLayer, ApplicationLogPayload, CaptureFilter, CapturedLogSink, SERVICE_API,
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
fn warn_and_error_after_sqlx_asked_log_enabled_reach_both_layers() {
    let sink = CollectingSink::default();
    let stdout = SharedBuffer::default();
    // Same layer stacking and same `RUST_LOG` as production (`telemetry::init`).
    tracing_subscriber::registry()
        .with(ApplicationLogCaptureLayer::new(SERVICE_API, sink.clone()).with_filter(CaptureFilter))
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

    // The shape sqlx calls on every query (`QueryLogger::finish`). The answer is ignored. `log_enabled!`
    // returns with every layer's filter marked disabled, and the following DEBUG event goes to no listener.
    let _ = log::log_enabled!(target: "sqlx::query", log::Level::Debug);
    tracing::warn!("warn after log_enabled");
    assert_eq!(delivered("warn after log_enabled"), (true, true));

    let _ = log::log_enabled!(target: "sqlx::query", log::Level::Debug);
    tracing::error!("error after log_enabled");
    assert_eq!(delivered("error after log_enabled"), (true, true));
}
