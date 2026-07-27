//! web サービスのログ初期化（`tracing`。api と同じく JSON 構造化ログを既定とする）。
//!
//! 同時に、WARN / ERROR を管理コンソールから見えるようにするための取り込み層を差し込む
//! （CLAUDE.md「ログ」）。web は DB を持たないため、集めたレコードは api の `POST /internal/logs`
//! へまとめて送り、api が `log` テーブルへ書く。
//!
//! **送信は best-effort**。取り込み層は決してブロックせず（有界チャネルへ `try_send`）、送信の
//! 失敗はログに出さない（送信失敗のログがまた送信を誘発して止まらなくなるため）。stdout の
//! 構造化ログには通常どおり出るので、DB へ届かなくても情報そのものは失われない。

use crate::api_client::ApiClient;
use crate::config::LogFormat;
use idp_contracts::application_log::{
    ApplicationLogCaptureLayer, ApplicationLogPayload, CapturedLogSink, SERVICE_WEB,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// チャネル容量。バーストを吸収しつつ、詰まったら捨てる方針なので過大にしない。
const CHANNEL_CAPACITY: usize = 512;
/// 1 回の送信でまとめる最大件数。
const BATCH_SIZE: usize = 64;
/// たまっていなくても、この間隔で送信を試みる（少数のエラーが画面に出るまで待たされないように）。
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// 送信経路自身が出すログを取り込まないための除外 target（再帰防止）。
const EXCLUDED_TARGETS: &[&str] = &["idp_web::telemetry", "idp_web::api_client"];

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
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,idp_web=info"));

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    let mut capture = ApplicationLogCaptureLayer::new(SERVICE_WEB, ChannelSink(tx));
    for target in EXCLUDED_TARGETS {
        capture = capture.exclude_target(*target);
    }

    let registry = tracing_subscriber::registry().with(filter).with(capture);
    match log_format {
        LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
            .init(),
        LogFormat::Pretty => registry.with(tracing_subscriber::fmt::layer()).init(),
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
                        let _ = api.push_application_logs(std::mem::take(&mut batch)).await;
                    }
                    return;
                }
                Err(_) => {}
            }
            if !batch.is_empty() {
                // `mem::take` は空の Vec を残すので、次の周回はそのまま使い回せる。
                let _ = api.push_application_logs(std::mem::take(&mut batch)).await;
            }
        }
    });
}
