//! アプリケーションログ（`log` テーブル）の共有契約と `tracing` 取り込み層。
//!
//! api と web の両方が WARN / ERROR を**同じ形**で組み立てる必要があるため、DTO だけでなく
//! 「`tracing` イベント → 1 レコード」の導出もここに単一定義する（CLAUDE.md の contracts の役割：
//! 「api と web で一致していないと壊れる値・導出」）。ずれると、同じ障害が画面上で別物に見える。
//!
//! - api: 取り込んだレコードを直接 `log` テーブルへ書く。
//! - web: DB を持たないため、api の `/internal/logs` へまとめて送って書いてもらう。
//!
//! 記録対象は WARN / ERROR のみ（INFO 以下は stdout の構造化ログに任せ、DB を肥大させない）。
//! 文言は多言語化せず運用言語（英語）で統一し、PII は載せない（CLAUDE.md「ログ」）。

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// 出力元サービス名（`log.service`。DB の CHECK 制約と一致させる）。
pub const SERVICE_API: &str = "api";
pub const SERVICE_WEB: &str = "web";

/// ログ 1 件（サービス間で受け渡す形）。`occurred_at` は RFC3339（UTC）の文字列で運ぶ。
///
/// `service` は受け取り側（api）が信頼できる形で埋めるのではなく**送り元が名乗る**。`/internal/logs`
/// はサービストークンで保護された内部経路であり、名乗りを検証するのは api 側の責務。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationLogPayload {
    pub occurred_at: String,
    /// `ERROR` / `WARN`。
    pub level: String,
    /// `api` / `web`。
    pub service: String,
    /// `tracing` の target（出力元モジュールパス）。
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceback: Option<String>,
}

/// web → api のログ取り込み要求（`POST /internal/logs`）。まとめて送る。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationLogIngestRequest {
    pub records: Vec<ApplicationLogPayload>,
}

/// 取り込み結果（受理件数）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLogIngestResponse {
    pub accepted: usize,
}

/// 管理画面向けのログ 1 行（api → web）。
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

// ── tracing 取り込み層 ────────────────────────────────────────────────────────

/// 取り込んだレコードの送り先。**実装は絶対にブロックしないこと**（`tracing` の `on_event` は
/// リクエスト処理スレッド上で走る）。送れないときは黙って捨てる（ログ出力は再帰を生む）。
pub trait CapturedLogSink: Send + Sync + 'static {
    fn submit(&self, record: ApplicationLogPayload);
}

/// WARN / ERROR の `tracing` イベントを [`ApplicationLogPayload`] へ写して [`CapturedLogSink`] へ流す層。
///
/// `correlation_id` / `tenant_id` は、イベント自身のフィールドか、囲っているスパンのフィールドから
/// 拾う（内側のスパンを優先）。これにより「リクエスト → 処理 → 監査イベント」を `correlation_id`
/// で一気通貫に追える（CLAUDE.md「ログ」）。
pub struct ApplicationLogCaptureLayer<K: CapturedLogSink> {
    sink: K,
    service: &'static str,
    /// 自己再帰を防ぐための除外 target 前方一致（ログ送信そのものが出すログを取り込まない）。
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

    /// 指定 target（前方一致）のイベントを取り込まない。ログ書き込み経路自身の target を除外して、
    /// 「書き込み失敗のログがまた書き込みを誘発する」再帰を断つために使う。
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

/// スパン生成時に拾っておく追跡キー（イベント時にスコープを遡って参照する）。
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
            // INFO 以下は DB へ落とさない（stdout の構造化ログが担う）。
            _ => return,
        };
        let target = event.metadata().target();
        if self.is_excluded(target) {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        // 追跡キーはイベント自身 → 内側のスパン → 外側のスパン の順に最初に見つかったものを使う。
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
            // `message` を持たないイベント（フィールドだけの記録）は target を本文の代わりにする。
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

/// `tracing` フィールドの取り出し。`message` は本文、`error` は traceback、残りは `key=value` で
/// 本文へ添える（構造化ログの JSON と同じ情報を、1 行の文字列として画面に出すため）。
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
            // `log` crate 由来のメタフィールドは本文に混ぜても情報にならない。
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

    /// 個別のサブスクライバでクロージャを実行し、取り込まれたレコードを返す。
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
