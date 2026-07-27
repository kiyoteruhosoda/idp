//! 実行中サービスの再起動要求（ADR-0017）。
//!
//! ランタイム設定の DB 上書きは**起動時にしか読まれない**（ADR-0014）。反映には再起動が要るが、
//! それまでは運用者がシェルへ入って `docker compose restart` を打つしかなく、設定画面から設定を
//! 変えられるのに反映だけができない、という中途半端な状態だった。
//!
//! アプリは自分自身を起動し直せない（プロセスを起こすのはプロセス管理側の役目）。できるのは
//! **自分を綺麗に終わらせること**だけである。そこで本モジュールは graceful shutdown を起こす所まで
//! を担い、新しいプロセスの起動は配置側の再起動ポリシー（Compose の `restart: unless-stopped`・
//! systemd の `Restart=always`・k8s の `restartPolicy: Always`）に委ねる。終了コードは 0 なので、
//! **`on-failure` 系のポリシーでは再起動されない**（`docs/OPERATIONS.md` に明記する）。
//!
//! **単一インスタンス配置が前提である。** 止まるのは要求を受け取ったこのプロセスだけなので、
//! 複数レプリカ配置では他のレプリカが起動時スナップショットのまま残り、古い issuer / 設定で
//! 応答し続ける。多重化した時点で「設定を反映する」はデプロイ全体のロールアウト（k8s なら
//! `kubectl rollout restart`）になり、アプリ内の仕組みでは担えない。本リポジトリの配置形態は
//! api 1・web 1 の Compose（ADR-0007・ADR-0016）で、`InMemoryLoginRateLimiter` や権限キャッシュも
//! 同じ前提に立っている。判断の経緯は ADR-0017 §Consequences を参照。

use crate::domain::service_lifecycle::ServiceRestarter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// 再起動要求の受け渡し口。`AppState` 経由でハンドラへ、`run()` 経由で graceful shutdown へ渡る。
#[derive(Clone)]
pub struct ServiceRestart {
    // `notify_one` を使う（`notify_waiters` ではない）。要求はサーバが shutdown future を待ち始める
    // 前にも起こり得るため、待機者がいなければ permit を蓄えてくれる方でないと取りこぼす。
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

/// Application 層（`application::service_restart`）から見た DIP 境界の実装。
impl ServiceRestarter for ServiceRestart {
    fn request_restart(&self) {
        self.request();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 待機を始める**前**の要求も取りこぼさない（応答を返してから終了するため、要求が先に立つのが
    /// 通常の順序になる）。
    #[tokio::test]
    async fn a_request_made_before_waiting_still_wakes_the_waiter() {
        let restart = ServiceRestart::new();
        restart.request();
        assert!(restart.was_requested());
        // permit が蓄えられているので即座に返る（返らなければテストはタイムアウトで落ちる）。
        restart.requested().await;
    }

    #[tokio::test]
    async fn cloning_shares_the_same_signal() {
        let restart = ServiceRestart::new();
        let clone = restart.clone();
        clone.request();
        restart.requested().await;
        assert!(restart.was_requested());
    }
}
