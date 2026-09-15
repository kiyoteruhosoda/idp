//! 利用者が止まったことを RP へ知らせる（ADR-0049 I7）。
//!
//! assay がセッションを失効させても、それだけでは RP 側のログイン状態は残る。RP は自分が
//! 発行したトークンで動いているので、こちらが黙って消しても気付けない。**止めた側から言う**
//! 必要があり、その手段が Back-Channel Logout 1.0 の通知である。
//!
//! これまで通知を送っていたのは**利用者本人がログアウトしたとき**だけだった（`logout`）。
//! 管理者が利用者を無効化した・パスワードを再発行した・MFA を解除したときは、assay 側の
//! セッションとトークンだけが消え、RP 側は**何も知らないまま**だった。止める理由が
//! 「乗っ取られた」である以上、ここが伝わらないのは穴になる。
//!
//! ⚠ **`sid` は付けない。** 管理操作が失効させるのはその利用者の**全セッション**であり、
//! 1 つを名指しするものではない。`sid` を付けると RP は該当の 1 セッションしか閉じない。

use crate::application::backchannel_logout::{
    BackchannelLogoutDeliveryService, LogoutNotification,
};
use crate::domain::repositories::ClientRepository;
use crate::domain::tenant::TenantId;
use std::sync::Arc;
use uuid::Uuid;

/// 「この利用者は止まった」を RP へ伝える出口。
///
/// 管理操作（`UserLifecycleService`）はこのトレイト越しにだけ知らせる。具象は RP の一覧と
/// 配送キューの両方を握るため、トレイトで挟まないと管理操作のテストが配送の仕掛けを丸ごと
/// 組み立てる羽目になる。
#[async_trait::async_trait]
pub trait SessionStopAnnouncer: Send + Sync {
    /// 利用者の全セッションが失効したことを知らせる。**失敗しても返らない**（fail-open）。
    async fn announce_all_sessions_ended(&self, tenant_id: TenantId, subject: Uuid);
}

/// 「この利用者は止まった」を、通知を受け取れる全 RP へ伝える。
pub struct StopAnnouncementService {
    clients: Arc<dyn ClientRepository>,
    delivery: Arc<BackchannelLogoutDeliveryService>,
}

impl StopAnnouncementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        delivery: Arc<BackchannelLogoutDeliveryService>,
    ) -> Self {
        Self { clients, delivery }
    }
}

/// **fail-open**（失敗はログに留める）。呼び出し元の管理操作——無効化・パスワード再発行・
/// MFA 解除——は assay 側では既に成立しており、通知が積めなかったからといって巻き戻すと、
/// 「止めたのに止まっていない」というより悪い状態になる。積めた通知の送信自体は
/// [`BackchannelLogoutDeliveryService::deliver_due`] が再試行する。
#[async_trait::async_trait]
impl SessionStopAnnouncer for StopAnnouncementService {
    async fn announce_all_sessions_ended(&self, tenant_id: TenantId, subject: Uuid) {
        let clients = match self.clients.list(tenant_id).await {
            Ok(clients) => clients,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list clients for stop announcement");
                return;
            }
        };
        let notifications: Vec<LogoutNotification> = clients
            .iter()
            .filter_map(|c| {
                c.backchannel_logout_uri
                    .as_ref()
                    .map(|uri| LogoutNotification {
                        client_id: c.client_id.clone(),
                        backchannel_logout_uri: uri.clone(),
                    })
            })
            .collect();
        if notifications.is_empty() {
            return;
        }
        if let Err(e) = self
            .delivery
            .enqueue(tenant_id, &subject.to_string(), None, &notifications)
            .await
        {
            // 積めなかった通知は復旧できない。RP 側にログイン状態が残るため ERROR で残す。
            tracing::error!(error = %e, "failed to enqueue stop announcement");
        }
    }
}
