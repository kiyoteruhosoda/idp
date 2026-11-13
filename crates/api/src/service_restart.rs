//! Restart request for the running service (ADR-0017).
//!
//! DB overrides of runtime settings are **read only at startup** (ADR-0014). Applying them needs a restart,
//! but until now operators had to get a shell and run `docker compose restart`; settings could be changed
//! from the settings screen but not applied, a half-finished state.
//!
//! An app cannot restart itself (starting processes is the process manager's job). All it can do is
//! **shut itself down cleanly**. So this module goes as far as triggering graceful shutdown, and
//! leaves starting the new process to the deployment's restart policy (Compose `restart: unless-stopped`,
//! systemd `Restart=always`, k8s `restartPolicy: Always`). The exit code is 0, so
//! **`on-failure` style policies do not restart it** (stated in `docs/OPERATIONS.md`).
//!
//! **A single-instance deployment is assumed.** Only the process that received the request stops, so
//! with multiple replicas the others keep their startup snapshot and keep answering with the old issuer /
//! settings. Once replicated, "apply the settings" becomes a rollout of the whole deployment (on k8s
//! `kubectl rollout restart`), which an in-app mechanism cannot do. This repository deploys as a
//! Compose of api 1 and web 1 (ADR-0007, ADR-0016), and `InMemoryLoginRateLimiter` and the permission cache
//! rest on the same assumption. See ADR-0017 §Consequences for the reasoning.

use crate::domain::service_lifecycle::ServiceRestarter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// Handoff point for restart requests. Goes to handlers via `AppState` and to graceful shutdown via `run()`.
#[derive(Clone)]
pub struct ServiceRestart {
    // Uses `notify_one` (not `notify_waiters`). A request can come before the server starts awaiting the
    // shutdown future, so we need the one that stores a permit when nobody is waiting, or it would be lost.
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

    /// Requests a restart (triggers graceful shutdown).
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Waits until a restart is requested.
    pub async fn requested(&self) {
        self.notify.notified().await;
    }

    /// Whether we are exiting because of a restart request (logged distinctly from a signal stop).
    pub fn was_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

impl Default for ServiceRestart {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of the DIP boundary as seen from the application layer (`application::service_restart`).
impl ServiceRestarter for ServiceRestart {
    fn request_restart(&self) {
        self.request();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Does not lose requests made **before** waiting starts (we exit after returning the response, so the
    /// request coming first is the normal order).
    #[tokio::test]
    async fn a_request_made_before_waiting_still_wakes_the_waiter() {
        let restart = ServiceRestart::new();
        restart.request();
        assert!(restart.was_requested());
        // A permit is stored, so this returns immediately (if not, the test fails by timeout).
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
