//! 実行中サービスの再起動要求（web。ADR-0017）。
//!
//! 役割は api の `service_restart` と同じ（graceful shutdown を起こし、新しいプロセスの起動は配置側の
//! 再起動ポリシーへ委ねる）。web は api に依存しない別プロセスで、依存の向きも api → web ではない
//! ため、共有せずそれぞれのサービスが自分のプロセス制御を持つ。
//!
//! web 固有の事情として、**再起動の順序は api が先**である。web は起動時に api から共有ランタイム
//! 設定を取得する（ADR-0013）ので、api より先に立ち上がると古い値を掴んでしまう。順序は
//! `handlers::admin_restart_console` が担保する。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// 再起動要求の受け渡し口。`WebState` 経由でハンドラへ、`run()` 経由で graceful shutdown へ渡る。
#[derive(Clone)]
pub struct ServiceRestart {
    // `notify_one` を使う理由は api 側と同じ（待機開始前の要求を取りこぼさないため）。
    notify: Arc<Notify>,
    requested: Arc<AtomicBool>,
}

impl ServiceRestart {
    pub fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 再起動を要求する（graceful shutdown を起こす）。
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// 再起動が要求されるまで待つ。
    pub async fn requested(&self) {
        self.notify.notified().await;
    }

    /// 再起動要求によって終了しようとしているか（シグナル停止と区別してログへ出す）。
    pub fn was_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl Default for ServiceRestart {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_request_made_before_waiting_still_wakes_the_waiter() {
        let restart = ServiceRestart::new();
        restart.request();
        assert!(restart.was_requested());
        restart.requested().await;
    }
}
