//! `tracing` による構造化ログ初期化。
//!
//! 既定は JSON 出力（本番想定）。`LOG_FORMAT=pretty` で開発向けの人間可読出力に切り替わる。
//! フィルタは環境変数 `RUST_LOG` を優先し、未設定時は `info,idp=debug`。
//!
//! 同時に、WARN / ERROR を `log` テーブルへ非同期に書き込むための取り込み層を差し込む
//! （CLAUDE.md「ログ」）。ここでは受信端を返すだけで、DB への書き込みは呼び出し側がプールを
//! 用意してからバックグラウンドタスクで行う（起動順の都合。ログ初期化は DB 接続より前に要る）。
//!
//! **`RUST_LOG` は stdout 出力だけを絞り、DB 取り込みには効かせない**（層ごとのフィルタにする）。
//! 全体フィルタにすると `RUST_LOG=warn` のときリクエストスパン（INFO）ごと落ちて、WARN / ERROR は
//! 拾えても `correlation_id` が失われる。運用のためのフィルタ設定で、画面の追跡キーが黙って
//! 欠けるのは避ける。

use crate::config::{Config, LogFormat};
use crate::infrastructure::log_capture::{self, ApplicationLogReceiver};
use idp_contracts::application_log::{ApplicationLogCaptureLayer, SERVICE_API};
use tracing::{Level, Metadata};
use tracing_subscriber::filter::{filter_fn, FilterFn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// DB 書き込み経路自身が出すログを取り込まないための除外 target。「書き込み失敗のログが
/// また書き込みを誘発する」再帰を断つ。
const EXCLUDED_TARGETS: &[&str] = &[
    "idp_core::infrastructure::log_capture",
    "idp_core::infrastructure::repositories::application_log",
    "idp_core::application::application_log",
];

/// 取り込み層に付けるフィルタ。
///
/// - **スパンは必ず通す**。イベント自身は追跡キーを持たず、囲っているリクエストスパン
///   （`correlation_id`）から拾うため、スパンが無効化されると `correlation_id` が NULL になる。
/// - イベントは WARN 以上だけを通す（INFO 以下は stdout の構造化ログに任せる）。取り込み層は
///   内部でもレベルを見るが、ここで落としておくと DEBUG / TRACE の分の呼び出し自体を省ける。
pub(crate) fn capture_filter() -> FilterFn {
    let predicate: fn(&Metadata<'_>) -> bool =
        |meta| meta.is_span() || *meta.level() <= Level::WARN;
    filter_fn(predicate)
}

/// ログを初期化し、`log` テーブルへ書き込むための受信端を返す。
///
/// 受信端を捨てた場合、取り込み層の送信は詰まって黙って捨てられるだけで、stdout の構造化ログは
/// 通常どおり出る（DB 書き込みは best-effort。CLAUDE.md「ログ」）。
pub fn init(config: &Config) -> ApplicationLogReceiver {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,idp=debug"));

    let (sink, receiver) = log_capture::channel();
    let mut capture = ApplicationLogCaptureLayer::new(SERVICE_API, sink);
    for target in EXCLUDED_TARGETS {
        capture = capture.exclude_target(*target);
    }

    let registry = tracing_subscriber::registry().with(capture.with_filter(capture_filter()));

    // `RUST_LOG` は出力層にだけ効かせる（上記モジュールコメント参照）。
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

    /// `RUST_LOG=warn` で stdout を絞っても、リクエストスパン由来の `correlation_id` が
    /// 取り込み側に残ること（全体フィルタにすると INFO スパンごと落ちて NULL になる）。
    #[tokio::test]
    async fn keeps_request_spans_when_stdout_filter_silences_info() {
        let (sink, mut receiver) = log_capture::channel();
        let capture = ApplicationLogCaptureLayer::new(SERVICE_API, sink);
        let subscriber = tracing_subscriber::registry()
            .with(capture.with_filter(capture_filter()))
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
}
