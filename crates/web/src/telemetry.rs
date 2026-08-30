//! web サービスのログ初期化（`tracing`。api と同じく JSON 構造化ログを既定とする）。
//!
//! 同時に、WARN / ERROR を管理コンソールから見えるようにするための取り込み層を差し込む
//! （CLAUDE.md「ログ」）。web は DB を持たないため、集めたレコードは api の `POST /internal/logs`
//! へまとめて送り、api が `log` テーブルへ書く。
//!
//! **送信は best-effort**。取り込み層は決してブロックせず（有界チャネルへ `try_send`）、送信の
//! 失敗はログに出さない（送信失敗のログがまた送信を誘発して止まらなくなるため）。stdout の
//! 構造化ログには通常どおり出るので、DB へ届かなくても情報そのものは失われない。
//!
//! **`RUST_LOG` は stdout 出力だけを絞り、DB 取り込みには効かせない**（層ごとのフィルタにする）。
//! 全体フィルタにすると `RUST_LOG=warn` のときリクエストスパン（INFO）ごと落ちて、WARN / ERROR は
//! 拾えても `correlation_id` が失われる（api 側 `assay_core::telemetry` と同じ扱い）。

use crate::api_client::ApiClient;
use crate::config::LogFormat;
use assay_contracts::application_log::{
    ApplicationLogCaptureLayer, ApplicationLogPayload, CapturedLogSink, SERVICE_WEB,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{Level, Metadata};
use tracing_subscriber::filter::{filter_fn, FilterFn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// チャネル容量。バーストを吸収しつつ、詰まったら捨てる方針なので過大にしない。
const CHANNEL_CAPACITY: usize = 512;
/// 1 回の送信でまとめる最大件数。
const BATCH_SIZE: usize = 64;
/// たまっていなくても、この間隔で送信を試みる（少数のエラーが画面に出るまで待たされないように）。
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// 1 回の送信に許す上限時間。api が接続だけ受けて応答を返さない場合、単一の転送タスクが
/// そこで止まり続けると以降の WARN / ERROR がチャネル溢れで捨てられ続けるため、必ず打ち切る。
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// 送信経路自身が出すログを取り込まないための除外 target（再帰防止）。
///
/// **`assay_web::api_client` 全体は除外しない。** そこには画面が使う api 呼び出しの失敗
/// （接続不能・デコード失敗・想定外ステータス）が含まれ、運用者が最も見たいログそのものだから。
/// ログ送信経路（`push_application_logs` とそれを回す [`spawn_forwarder`]）は**自分ではログを
/// 出さない**（失敗は `let _ =` で捨てる）ので、除外すべきものはこのモジュールだけで足りる。
const EXCLUDED_TARGETS: &[&str] = &["assay_web::telemetry"];

/// 取り込み層に付けるフィルタ。スパンは追跡キー（`correlation_id`）を拾うため必ず通し、
/// イベントは WARN 以上だけを通す（api 側 `assay_core::telemetry::capture_filter` と同じ）。
fn capture_filter() -> FilterFn {
    let predicate: fn(&Metadata<'_>) -> bool =
        |meta| meta.is_span() || *meta.level() <= Level::WARN;
    filter_fn(predicate)
}

struct ChannelSink(mpsc::Sender<ApplicationLogPayload>);

impl CapturedLogSink for ChannelSink {
    fn submit(&self, record: ApplicationLogPayload) {
        // 詰まっていたら捨てる（リクエスト処理スレッドを止めない）。
        let _ = self.0.try_send(record);
    }
}

/// api へレコードを転送するタスクの起動に使う受信端。[`spawn_forwarder`] へ渡す。
pub struct ApplicationLogForwarder {
    rx: mpsc::Receiver<ApplicationLogPayload>,
}

/// ログを初期化し、api へのログ転送に使う受信端を返す。
///
/// 出力形式だけを受け取る（`Config` 全体を要求しない）。web は api から共有設定を取得する**前**に
/// ログを立ち上げる必要があり、その時点では [`crate::config::Bootstrap`] しか手元に無いため。
/// 同じ理由で、転送タスクは `ApiClient` が組み上がってから [`spawn_forwarder`] で起こす。
pub fn init(log_format: LogFormat) -> ApplicationLogForwarder {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,assay_web=info"));

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let mut capture = ApplicationLogCaptureLayer::new(SERVICE_WEB, ChannelSink(tx));
    for target in EXCLUDED_TARGETS {
        capture = capture.exclude_target(*target);
    }

    let registry = tracing_subscriber::registry().with(capture.with_filter(capture_filter()));
    // `RUST_LOG` は出力層にだけ効かせる（上記モジュールコメント参照）。
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

/// 取り込んだ WARN / ERROR を api へ定期的にまとめて送るタスクを起こす。
///
/// 送信失敗は握り潰す（再帰防止。上記モジュールコメント参照）。
pub fn spawn_forwarder(api: ApiClient, mut forwarder: ApplicationLogForwarder) {
    tokio::spawn(async move {
        let mut batch: Vec<ApplicationLogPayload> = Vec::with_capacity(BATCH_SIZE);
        loop {
            // 次の 1 件を最大 FLUSH_INTERVAL 待つ。タイムアウトしたら（たまっていれば）送る。
            match tokio::time::timeout(FLUSH_INTERVAL, forwarder.rx.recv()).await {
                Ok(Some(record)) => {
                    batch.push(record);
                    // 届いている分はまとめて拾う。
                    while batch.len() < BATCH_SIZE {
                        match forwarder.rx.try_recv() {
                            Ok(next) => batch.push(next),
                            Err(_) => break,
                        }
                    }
                }
                // 送信端がすべて落ちた = 購読者がいない。最後の分を送って終わる。
                Ok(None) => {
                    if !batch.is_empty() {
                        upload(&api, std::mem::take(&mut batch)).await;
                    }
                    return;
                }
                Err(_) => {}
            }
            if !batch.is_empty() {
                // `mem::take` は空の Vec を残すので、次の周回はそのまま使い回せる。
                upload(&api, std::mem::take(&mut batch)).await;
            }
        }
    });
}

/// 1 バッチを api へ送る。失敗も時間切れも握り潰す（再帰防止。取りこぼしは stdout に残る）。
/// **必ず [`UPLOAD_TIMEOUT`] で打ち切る**（`ApiClient` の `reqwest::Client` は総リクエスト
/// タイムアウトを持たないため、応答しない api に当たると転送タスクが永久に止まる）。
async fn upload(api: &ApiClient, records: Vec<ApplicationLogPayload>) {
    let _ = tokio::time::timeout(UPLOAD_TIMEOUT, api.push_application_logs(records)).await;
}
