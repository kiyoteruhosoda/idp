//! web サービスのログ初期化（`tracing`。api と同じく JSON 構造化ログを既定とする）。

use crate::config::LogFormat;
use tracing_subscriber::EnvFilter;

/// ログを初期化する。`RUST_LOG` があれば優先し、無ければ既定フィルタを使う。
///
/// 出力形式だけを受け取る（`Config` 全体を要求しない）。web は api から共有設定を取得する**前**に
/// ログを立ち上げる必要があり、その時点では [`crate::config::Bootstrap`] しか手元に無いため。
pub fn init(log_format: LogFormat) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,idp_web=info"));

    match log_format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
        LogFormat::Pretty => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}
