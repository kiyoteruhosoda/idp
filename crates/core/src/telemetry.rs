//! `tracing` による構造化ログ初期化。
//!
//! 既定は JSON 出力（本番想定）。`LOG_FORMAT=pretty` で開発向けの人間可読出力に切り替わる。
//! フィルタは環境変数 `RUST_LOG` を優先し、未設定時は `info,idp=debug`。
//!
//! 同時に、WARN / ERROR を `log` テーブルへ非同期に書き込むための取り込み層を差し込む
//! （CLAUDE.md「ログ」）。ここでは受信端を返すだけで、DB への書き込みは呼び出し側がプールを
//! 用意してからバックグラウンドタスクで行う（起動順の都合。ログ初期化は DB 接続より前に要る）。

use crate::config::{Config, LogFormat};
use crate::infrastructure::log_capture::{self, ApplicationLogReceiver};
use idp_contracts::application_log::{ApplicationLogCaptureLayer, SERVICE_API};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// DB 書き込み経路自身が出すログを取り込まないための除外 target。「書き込み失敗のログが
/// また書き込みを誘発する」再帰を断つ。
const EXCLUDED_TARGETS: &[&str] = &[
    "idp_core::infrastructure::log_capture",
    "idp_core::infrastructure::repositories::application_log",
    "idp_core::application::application_log",
];

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

    let registry = tracing_subscriber::registry().with(filter).with(capture);

    match config.log_format() {
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true))
            .init(),
        LogFormat::Pretty => registry.with(fmt::layer().pretty()).init(),
    }

    receiver
}
