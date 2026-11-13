//! Structured log initialization with `tracing`.
//!
//! JSON output by default (for production). `LOG_FORMAT=pretty` switches to human-readable output for development.
//! The filter prefers the `RUST_LOG` env var, defaulting to `info,assay=debug` when unset.
//!
//! It also inserts an ingestion layer for asynchronously writing WARN / ERROR to the `log` table
//! (CLAUDE.md "Logging"). This only returns the receiving end; DB writes are done by a background task once the caller
//! has prepared a pool (due to startup order: log init is needed before the DB connection).
//!
//! **`RUST_LOG` narrows only stdout output and does not affect DB ingestion** (per-layer filters).
//! A global filter would, with `RUST_LOG=warn`, drop the request spans (INFO) too, so WARN / ERROR
//! would be captured but lose `correlation_id`. We avoid having an operational filter setting silently
//! remove the tracking key shown on screen.

use crate::config::{Config, LogFormat};
use crate::infrastructure::log_capture::{self, ApplicationLogReceiver};
use assay_contracts::application_log::{ApplicationLogCaptureLayer, CaptureFilter, SERVICE_API};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Excluded target so logs emitted by the DB write path itself are not ingested. Breaks the recursion of
/// "a write-failure log triggering another write".
const EXCLUDED_TARGETS: &[&str] = &[
    "assay_core::infrastructure::log_capture",
    "assay_core::infrastructure::repositories::application_log",
    "assay_core::application::application_log",
];

/// Initializes logging and returns the receiving end for writing to the `log` table.
///
/// If the receiving end is dropped, the ingestion layer's sends just back up and are silently dropped, while the stdout
/// structured log is emitted as usual (DB writes are best-effort; CLAUDE.md "Logging").
pub fn init(config: &Config) -> ApplicationLogReceiver {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,assay=debug"));

    let (sink, receiver) = log_capture::channel();
    let mut capture = ApplicationLogCaptureLayer::new(SERVICE_API, sink);
    for target in EXCLUDED_TARGETS {
        capture = capture.exclude_target(*target);
    }

    let registry = tracing_subscriber::registry().with(capture.with_filter(CaptureFilter));

    // `RUST_LOG` applies only to the output layer (see the module comment above).
    match config.log_format() {
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true).with_filter(filter))
            .init(),
        LogFormat::Pretty => registry
            .with(fmt::layer().pretty().with_filter(filter))
            .init(),
    }

    receiver
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Even when stdout is narrowed with `RUST_LOG=warn`, the `correlation_id` from the request span
    /// remains on the ingestion side (a global filter would drop the INFO span and make it NULL).
    #[tokio::test]
    async fn keeps_request_spans_when_stdout_filter_silences_info() {
        let (sink, mut receiver) = log_capture::channel();
        let capture = ApplicationLogCaptureLayer::new(SERVICE_API, sink);
        let subscriber = tracing_subscriber::registry()
            .with(capture.with_filter(CaptureFilter))
            .with(fmt::layer().with_filter(EnvFilter::new("warn")));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http_request", correlation_id = "corr-1");
            let _guard = span.enter();
            tracing::info!("not captured");
            tracing::error!("boom");
        });

        let batch = receiver.recv_batch(10).await.expect("batch");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].message, "boom");
        assert_eq!(batch[0].correlation_id.as_deref(), Some("corr-1"));
    }

    /// Sink for verifying what was written to stdout.
    #[derive(Clone, Default)]
    struct SharedBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("buffer")).into_owned()
        }
    }

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// With **the same layer stacking and the same `RUST_LOG` as production**, an ERROR emitted by app code
    /// reaches both stdout and DB ingestion.
    ///
    /// In a configuration stacking per-layer filters, one filter may decide the callsite's `Interest`
    /// and drag the other along, causing missed events. Existing tests only looked at one layer
    /// at a time, and nobody exercised the same shape as `init()`.
    #[tokio::test]
    async fn an_application_error_reaches_both_stdout_and_the_capture_sink() {
        let (sink, mut receiver) = log_capture::channel();
        let capture = ApplicationLogCaptureLayer::new(SERVICE_API, sink);
        let buffer = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry()
            .with(capture.with_filter(CaptureFilter))
            .with(
                fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_writer(buffer.clone())
                    // Same value as production (`RUST_LOG_API` in `idp-env`).
                    .with_filter(EnvFilter::new("info,assay=info")),
            );

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http_request", correlation_id = "corr-1");
            let _guard = span.enter();
            tracing::info!(target: "assay_api", "IdP server started");
            tracing::error!(
                target: "assay_api::presentation::handlers::mfa",
                error = "internal error: failed to build TOTP",
                "totp setup internal error"
            );
        });

        let stdout = buffer.contents();
        assert!(
            stdout.contains("IdP server started"),
            "if the startup log is missing, the test is set up wrong: {stdout}"
        );
        assert!(
            stdout.contains("totp setup internal error"),
            "the app error did not reach stdout: {stdout}"
        );

        let batch = receiver.recv_batch(10).await.expect("batch");
        let messages: Vec<_> = batch.iter().map(|r| r.message.as_str()).collect();
        assert!(
            messages.contains(&"totp setup internal error"),
            "the app error did not reach the log table: {messages:?}"
        );
    }
}
