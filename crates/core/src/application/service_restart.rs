//! サービス再起動ユースケース（ADR-0017）。
//!
//! ランタイム設定の DB 上書きを反映する唯一の手段が再起動なので、設定画面から実行できるようにする。
//! 認可（`idp.system.admin`）は Presentation の `RequirePerms` が担い、本サービスは呼ばれた時点で
//! 認可済みとして扱う（他の管理ユースケースと同じ方針）。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::error::Result;
use crate::domain::service_lifecycle::ServiceRestarter;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use std::time::Duration;

/// 受理を返してから停止するまでの猶予。
///
/// 先に止めると、この要求自身が接続ごと切れて「押したのに何も起きなかった」ように見える。
/// 応答を書き出し切るだけの短い時間で足りる。
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

pub struct ServiceRestartService {
    restarter: Arc<dyn ServiceRestarter>,
    audit: Arc<AuditService>,
}

impl ServiceRestartService {
    pub fn new(restarter: Arc<dyn ServiceRestarter>, audit: Arc<AuditService>) -> Self {
        Self { restarter, audit }
    }

    /// 再起動を要求する。監査へ記録してから、猶予をおいて停止を要求する。
    ///
    /// 監査は停止**前**に書く。停止後には書けないうえ、稼働中の全リクエストを打ち切る操作は
    /// 誰がいつ行ったかが残っていなければ後から追えない。
    pub async fn request(
        &self,
        tenant: TenantContext,
        actor: &AdminActor,
        service: &str,
        ctx: &RequestContext,
    ) -> Result<()> {
        self.audit
            .record(
                AuditEventType::ServiceRestartRequested,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(service),
                ctx,
            )
            .await;

        let restarter = self.restarter.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SHUTDOWN_GRACE).await;
            restarter.request_restart();
        });
        Ok(())
    }
}
