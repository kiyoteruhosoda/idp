//! Logging initialization of the web service (`tracing`; JSON structured logs by default, like the api).
//!
//! It also plugs in an ingestion layer so WARN / ERROR are visible from the admin console
//! (CLAUDE.md "Logging"). web has no DB, so collected records are sent in batches to the api's `POST /internal/logs`,
//! and the api writes them to the `log` table.
//!
//! **Sending is best-effort.** The ingestion layer never blocks (`try_send` to a bounded channel), and send
//! failures are not logged (a log about a send failure would trigger another send, endlessly). They still appear
//! in the stdout structured logs as usual, so the information itself is not lost even if it never reaches the DB.
//!
//! **`RUST_LOG` narrows only the stdout output, not DB ingestion** (per-layer filters).
//! A global filter would, with `RUST_LOG=warn`, drop request spans (INFO) entirely, so WARN / ERROR
//! could be captured but lose `correlation_id` (same treatment as the api's `assay_core::telemetry`).

use crate::api_client::ApiClient;
use crate::config::LogFormat;
use assay_contracts::application_log::{
    ApplicationLogCaptureLayer, ApplicationLogPayload, CaptureFilter, CapturedLogSink, SERVICE_WEB,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Channel capacity. Absorbs bursts, but since the policy is to drop when full, not oversized.
const CHANNEL_CAPACITY: usize = 512;
/// Maximum number of records per send.
const BATCH_SIZE: usize = 64;
/// Try sending at this interval even if few have accumulated (so a few errors are not delayed in reaching the screen).
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Upper time limit per send. If the api accepts the connection but never responds and the single forwarding task
/// stays stuck there, subsequent WARN / ERROR keep being dropped by channel overflow, so always cut it off.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Excluded target so the send path's own logs are not ingested (prevents recursion).
///
/// **`assay_web::api_client` as a whole is not excluded.** It includes failures of api calls used by screens
/// (unreachable, decode failure, unexpected status), which are exactly the logs operators most want to see.
/// The log send path (`push_application_logs` and [`spawn_forwarder`] that drives it) **emits no logs itself**
/// (failures are dropped with `let _ =`), so excluding this module is enough.
const EXCLUDED_TARGETS: &[&str] = &["assay_web::telemetry"];

struct ChannelSink(mpsc::Sender<ApplicationLogPayload>);

impl CapturedLogSink for ChannelSink {
    fn submit(&self, record: ApplicationLogPayload) {
        // Drop if full (do not block the request-handling thread).
        let _ = self.0.try_send(record);
    }
}

/// Receiving end used to start the task forwarding records to the api. Passed to [`spawn_forwarder`].
pub struct ApplicationLogForwarder {
    rx: mpsc::Receiver<ApplicationLogPayload>,
}

/// Initializes logging and returns the receiving end used to forward logs to the api.
///
/// Takes only the output format (not the whole `Config`). web must start logging **before** fetching the shared
/// settings from the api, and at that point only [`crate::config::Bootstrap`] is at hand.
/// For the same reason, the forwarding task is started by [`spawn_forwarder`] once the `ApiClient` is built.
pub fn init(log_format: LogFormat) -> ApplicationLogForwarder {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,assay_web=info"));

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let mut capture = ApplicationLogCaptureLayer::new(SERVICE_WEB, ChannelSink(tx));
    for target in EXCLUDED_TARGETS {
        capture = capture.exclude_target(*target);
    }

    let registry = tracing_subscriber::registry().with(capture.with_filter(CaptureFilter));
    // `RUST_LOG` applies only to the output layer (see the module comment above).
    match log_format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_filter(filter),
            )
            .init(),
        LogFormat::Pretty => registry
            .with(tracing_subscriber::fmt::layer().with_filter(filter))
            .init(),
    }

    ApplicationLogForwarder { rx }
}

/// Starts a task that periodically sends ingested WARN / ERROR to the api in batches.
///
/// Send failures are swallowed (prevents recursion; see the module comment above).
pub fn spawn_forwarder(api: ApiClient, mut forwarder: ApplicationLogForwarder) {
    tokio::spawn(async move {
        let mut batch: Vec<ApplicationLogPayload> = Vec::with_capacity(BATCH_SIZE);
        loop {
            // Wait up to FLUSH_INTERVAL for the next record. On timeout, send (if any have accumulated).
            match tokio::time::timeout(FLUSH_INTERVAL, forwarder.rx.recv()).await {
                Ok(Some(record)) => {
                    batch.push(record);
                    // Pick up everything that has arrived in one go.
                    while batch.len() < BATCH_SIZE {
                        match forwarder.rx.try_recv() {
                            Ok(next) => batch.push(next),
                            Err(_) => break,
                        }
                    }
                }
                // All senders dropped = no subscribers. Send the remainder and finish.
                Ok(None) => {
                    if !batch.is_empty() {
                        upload(&api, std::mem::take(&mut batch)).await;
                    }
                    return;
                }
                Err(_) => {}
            }
            if !batch.is_empty() {
                // `mem::take` leaves an empty Vec, so the next round can reuse it as is.
                upload(&api, std::mem::take(&mut batch)).await;
            }
        }
    });
}

/// Sends one batch to the api. Failures and timeouts are swallowed (prevents recursion; misses remain in stdout).
/// **Always cut off at [`UPLOAD_TIMEOUT`]** (the `ApiClient`'s `reqwest::Client` has no total request
/// timeout, so hitting an unresponsive api would stall the forwarding task forever).
async fn upload(api: &ApiClient, records: Vec<ApplicationLogPayload>) {
    let _ = tokio::time::timeout(UPLOAD_TIMEOUT, api.push_application_logs(records)).await;
}
