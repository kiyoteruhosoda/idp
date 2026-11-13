//! Restart request for the running service (web. ADR-0017).
//!
//! Its role is the same as the api's `service_restart` (trigger a graceful shutdown and leave starting a new
//! process to the deployment's restart policy). web is a separate process not depending on the api, and the
//! dependency does not point api → web either, so nothing is shared and each service owns its process control.
//!
//! Specific to web: **the api restarts first**. web fetches the shared runtime settings from the api at
//! startup (ADR-0013), so starting before the api would pick up stale values. The order is
//! ensured by `handlers::admin_restart_console`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// Hand-off point for restart requests. Reaches handlers via `WebState` and the graceful shutdown via `run()`.
#[derive(Clone)]
pub struct ServiceRestart {
    // `notify_one` is used for the same reason as on the api side (not to miss a request made before waiting starts).
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

    /// Requests a restart (triggers a graceful shutdown).
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Waits until a restart is requested.
    pub async fn requested(&self) {
        self.notify.notified().await;
    }

    /// Whether we are shutting down due to a restart request (to log it distinctly from a signal stop).
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
