//! Notify RPs that a user has been stopped (ADR-0049 I7).
//!
//! Even when assay revokes sessions, that alone leaves the sign-in state on the RP side. RPs run on
//! tokens they issued themselves, so they cannot notice if we silently delete ours. **The side that stopped it must say so**,
//! and the means is a Back-Channel Logout 1.0 notification.
//!
//! Until now notifications were sent only **when the user signed out themselves** (`logout`).
//! When an admin disabled a user, reissued the password, or removed MFA, only assay's
//! sessions and tokens disappeared, and the RPs **knew nothing**. Since the reason for stopping
//! is "the account was taken over", failing to convey this is a hole.
//!
//! ⚠ **No `sid`.** What an admin operation revokes is **all sessions** of that user,
//! not one specific session. With a `sid`, the RP would close only that one session.

use crate::application::backchannel_logout::{
    BackchannelLogoutDeliveryService, LogoutNotification,
};
use crate::domain::repositories::ClientRepository;
use crate::domain::tenant::TenantId;
use std::sync::Arc;
use uuid::Uuid;

/// The outlet that tells RPs "this user has been stopped".
///
/// Admin operations (`UserLifecycleService`) notify only through this trait. The concrete type holds both the RP list
/// and the delivery queue, so without a trait in between, admin-operation tests would have to assemble
/// the whole delivery machinery.
#[async_trait::async_trait]
pub trait SessionStopAnnouncer: Send + Sync {
    /// Notifies that all of the user's sessions have been revoked. **Failures are not returned** (fail-open).
    async fn announce_all_sessions_ended(&self, tenant_id: TenantId, subject: Uuid);
}

/// Tells every RP that can receive notifications that "this user has been stopped".
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

/// **fail-open** (failures are only logged). The calling admin operation (disable, password reissue,
/// MFA removal) has already taken effect on the assay side; rolling it back because a notification could not be queued
/// would lead to a worse state: "stopped but not actually stopped". Sending the queued notifications
/// is retried by [`BackchannelLogoutDeliveryService::deliver_due`].
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
            // A notification that could not be queued cannot be recovered. Sign-in state remains on the RP, so log it at ERROR.
            tracing::error!(error = %e, "failed to enqueue stop announcement");
        }
    }
}
