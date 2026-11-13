//! Shared contract of the application log (`log` table) and the `tracing` ingestion layer.
//!
//! Both api and web must build WARN / ERROR records **the same way**, so not only the DTOs but also the
//! derivation "`tracing` event -> 1 record" is defined once here (the role of contracts in CLAUDE.md:
//! "values and derivations that break unless api and web agree"). If they drift, the same failure looks different on screen.
//!
//! - api: writes ingested records directly to the `log` table.
//! - web: has no DB, so it sends them in batches to api's `/internal/logs` to be written.
//!
//! Only WARN / ERROR are recorded (INFO and below are left to stdout structured logs so the DB does not bloat).
//! Messages are not localized; they use the operational language (English), and carry no PII (CLAUDE.md "Logging").

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Filter, Layer};
use tracing_subscriber::registry::LookupSpan;

/// Source service name (`log.service`; keep in sync with the DB CHECK constraint).
pub const SERVICE_API: &str = "api";
pub const SERVICE_WEB: &str = "web";

/// One log record (the shape passed between services). `occurred_at` is carried as an RFC3339 (UTC) string.
///
/// `service` is **declared by the sender**, not filled by the receiver (api) in a trusted way. `/internal/logs`
/// is an internal route protected by the service token, and verifying the claim is api's responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationLogPayload {
    pub occurred_at: String,
    /// `ERROR` / `WARN`.
    pub level: String,
    /// `api` / `web`.
    pub service: String,
    /// `tracing` target (module path of the source).
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceback: Option<String>,
}

/// web -> api log ingestion request (`POST /internal/logs`). Sent in batches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationLogIngestRequest {
    pub records: Vec<ApplicationLogPayload>,
}

/// Ingestion result (number accepted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLogIngestResponse {
    pub accepted: usize,
}

/// One log row for the admin screen (api -> web).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLogEntryResponse {
    pub id: i64,
    pub occurred_at: String,
    pub level: String,
    pub service: String,
    pub target: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub tenant_id: Option<String>,
    pub traceback: Option<String>,
}

// ── tracing ingestion layer ────────────────────────────────────────────────────────

/// Destination of ingested records. **Implementations must never block** (`tracing`'s `on_event`
/// runs on the request handling thread). If it cannot send, drop silently (logging would recurse).
pub trait CapturedLogSink: Send + Sync + 'static {
    fn submit(&self, record: ApplicationLogPayload);
}

/// Layer that maps WARN / ERROR `tracing` events to [`ApplicationLogPayload`] and feeds them to [`CapturedLogSink`].
///
/// `correlation_id` / `tenant_id` are picked from the event's own fields or the enclosing spans' fields
/// (inner spans first). This lets "request -> processing -> audit event" be traced end to end by
/// `correlation_id` (CLAUDE.md "Logging").
pub struct ApplicationLogCaptureLayer<K: CapturedLogSink> {
    sink: K,
    service: &'static str,
    /// Excluded target prefixes to prevent self-recursion (logs emitted by log shipping itself are not ingested).
    excluded_targets: Vec<String>,
}

impl<K: CapturedLogSink> ApplicationLogCaptureLayer<K> {
    pub fn new(service: &'static str, sink: K) -> Self {
        Self {
            sink,
            service,
            excluded_targets: Vec::new(),
        }
    }

    /// Do not ingest events for the given target (prefix match). Used to exclude the log write path's own target
    /// and break the recursion where "a log of a write failure triggers another write".
    pub fn exclude_target(mut self, prefix: impl Into<String>) -> Self {
        self.excluded_targets.push(prefix.into());
        self
    }

    fn is_excluded(&self, target: &str) -> bool {
        self.excluded_targets
            .iter()
            .any(|prefix| target.starts_with(prefix.as_str()))
    }
}

/// Filter attached to the ingestion layer (task #801).
///
/// - **Spans always pass.** Events carry no trace key themselves and pick it from the enclosing request span
///   (`correlation_id`), so if spans are disabled, `correlation_id` becomes NULL.
/// - Only events at WARN and above pass (INFO and below are left to stdout structured logs). The ingestion layer
///   also checks the level internally, but dropping them here skips the DEBUG / TRACE calls altogether.
///
/// ⚠ **Do not make the [`Interest`] of what passes `always`.** Per-layer filter decisions remain as a per-thread
/// mark and are not cleared until `enabled` is next called. A callsite for which every layer answered `always` skips
/// `enabled`, so the leftover mark decides, and it silently disappears from both stdout and the ingestion layer. The one
/// leaving the mark is sqlx, which calls `log::log_enabled!` after every query (`LogTracer` forwards it to `enabled`),
/// and at a level `RUST_LOG` does not want, the following event is not dispatched. So **WARN / ERROR right after a query**
/// were being dropped. With `sometimes`, `enabled` is called every time and the mark is overwritten.
pub struct CaptureFilter;

impl CaptureFilter {
    fn passes(meta: &Metadata<'_>) -> bool {
        meta.is_span() || *meta.level() <= Level::WARN
    }
}

impl<S> Filter<S> for CaptureFilter {
    fn enabled(&self, meta: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        Self::passes(meta)
    }

    fn callsite_enabled(&self, meta: &'static Metadata<'static>) -> Interest {
        if Self::passes(meta) {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }
}

/// Trace keys captured at span creation (looked up by walking the scope at event time).
#[derive(Debug, Clone, Default)]
struct TrackingFields {
    correlation_id: Option<String>,
    tenant_id: Option<String>,
}

impl<K, S> Layer<S> for ApplicationLogCaptureLayer<K>
where
    K: CapturedLogSink,
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        if visitor.tracking.correlation_id.is_some() || visitor.tracking.tenant_id.is_some() {
            span.extensions_mut().insert(visitor.tracking);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let level = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            // INFO and below are not written to the DB (stdout structured logs cover them).
            _ => return,
        };
        let target = event.metadata().target();
        if self.is_excluded(target) {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // For trace keys, use the first found in the order: the event itself -> inner span -> outer span.
        let mut correlation_id = visitor.tracking.correlation_id;
        let mut tenant_id = visitor.tracking.tenant_id;
        if correlation_id.is_none() || tenant_id.is_none() {
            if let Some(scope) = ctx.event_scope(event) {
                for span in scope {
                    let extensions = span.extensions();
                    let Some(tracking) = extensions.get::<TrackingFields>() else {
                        continue;
                    };
                    if correlation_id.is_none() {
                        correlation_id.clone_from(&tracking.correlation_id);
                    }
                    if tenant_id.is_none() {
                        tenant_id.clone_from(&tracking.tenant_id);
                    }
                    if correlation_id.is_some() && tenant_id.is_some() {
                        break;
                    }
                }
            }
        }

        let message = if visitor.message.is_empty() {
            // For events without `message` (field-only records), the target stands in for the message.
            target.to_string()
        } else if visitor.extra.is_empty() {
            visitor.message
        } else {
            format!("{}{}", visitor.message, visitor.extra)
        };

        self.sink.submit(ApplicationLogPayload {
            occurred_at: now_rfc3339(),
            level: level.to_string(),
            service: self.service.to_string(),
            target: target.to_string(),
            message,
            correlation_id,
            tenant_id,
            traceback: visitor.error,
        });
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Extracts `tracing` fields. `message` is the message, `error` is the traceback, and the rest are appended to the
/// message as `key=value` (to show the same information as the structured JSON log as a one-line string on screen).
#[derive(Default)]
struct FieldVisitor {
    message: String,
    error: Option<String>,
    extra: String,
    tracking: TrackingFields,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: String) {
        match field.name() {
            "message" => self.message = value,
            "error" => self.error = Some(value),
            "correlation_id" => self.tracking.correlation_id = Some(value),
            "tenant_id" => self.tracking.tenant_id = Some(value),
            // Meta fields from the `log` crate add no information when mixed into the message.
            name if name.starts_with("log.") => {}
            name => {
                let _ = write!(self.extra, " {name}={value}");
            }
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    #[derive(Clone, Default)]
    struct CollectingSink(Arc<Mutex<Vec<ApplicationLogPayload>>>);

    impl CapturedLogSink for CollectingSink {
        fn submit(&self, record: ApplicationLogPayload) {
            self.0.lock().expect("sink mutex").push(record);
        }
    }

    /// Runs the closure under a dedicated subscriber and returns the ingested records.
    fn capture(f: impl FnOnce()) -> Vec<ApplicationLogPayload> {
        let sink = CollectingSink::default();
        let layer = ApplicationLogCaptureLayer::new(SERVICE_API, sink.clone())
            .exclude_target("idp_excluded");
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
        let records = sink.0.lock().expect("sink mutex").clone();
        records
    }

    #[test]
    fn captures_warn_and_error_only() {
        let records = capture(|| {
            tracing::info!("ignored info");
            tracing::debug!("ignored debug");
            tracing::warn!("a warning");
            tracing::error!("a failure");
        });
        let levels: Vec<_> = records.iter().map(|r| r.level.as_str()).collect();
        assert_eq!(levels, vec!["WARN", "ERROR"]);
        assert_eq!(records[0].message, "a warning");
        assert_eq!(records[1].message, "a failure");
        assert_eq!(records[0].service, SERVICE_API);
    }

    #[test]
    fn puts_error_field_into_traceback_and_extras_into_message() {
        let records = capture(|| {
            tracing::error!(error = "connection refused", attempt = 3, "db call failed");
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].traceback.as_deref(), Some("connection refused"));
        assert_eq!(records[0].message, "db call failed attempt=3");
    }

    #[test]
    fn inherits_correlation_id_from_enclosing_span() {
        let records = capture(|| {
            let span = tracing::info_span!("request", correlation_id = "corr-1");
            let _guard = span.enter();
            tracing::error!("boom");
        });
        assert_eq!(records[0].correlation_id.as_deref(), Some("corr-1"));
    }

    #[test]
    fn prefers_innermost_span_and_event_field_over_span() {
        let records = capture(|| {
            let outer = tracing::info_span!("outer", correlation_id = "outer-id");
            let _outer = outer.enter();
            let inner = tracing::info_span!("inner", correlation_id = "inner-id");
            let _inner = inner.enter();
            tracing::error!("from inner span");
            tracing::error!(correlation_id = "event-id", "from event field");
        });
        assert_eq!(records[0].correlation_id.as_deref(), Some("inner-id"));
        assert_eq!(records[1].correlation_id.as_deref(), Some("event-id"));
    }

    #[test]
    fn skips_excluded_targets() {
        let records = capture(|| {
            tracing::error!(target: "idp_excluded::sink", "must not be captured");
            tracing::error!(target: "assay_api::token", "captured");
        });
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, "assay_api::token");
    }

    #[test]
    fn falls_back_to_target_when_event_has_no_message() {
        let records = capture(|| {
            tracing::warn!(target: "assay_api::jobs", retries = 2);
        });
        assert_eq!(records[0].message, "assay_api::jobs");
    }
}
