//! `tracing` による構造化ログ初期化。
//!
//! 既定は JSON 出力（本番想定）。`LOG_FORMAT=pretty` で開発向けの人間可読出力に切り替わる。
//! フィルタは環境変数 `RUST_LOG` を優先し、未設定時は `info,idp=debug`。

use crate::config::{Config, LogFormat};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init(config: &Config) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,idp=debug"));

    let registry = tracing_subscriber::registry().with(filter);

    match config.log_format() {
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true))
            .init(),
        LogFormat::Pretty => registry.with(fmt::layer().pretty()).init(),
    }
}
