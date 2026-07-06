//! web サービスのログ初期化（`tracing`。api と同じく JSON 構造化ログを既定とする）。

use crate::config::{Config, LogFormat};
use tracing_subscriber::EnvFilter;

/// ログを初期化する。`RUST_LOG` があれば優先し、無ければ既定フィルタを使う。
pub fn init(config: &Config) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,idp_web=info"));

    match config.log_format() {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}
