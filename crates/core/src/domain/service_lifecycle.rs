//! Lifecycle operations on the running service (ADR-0017).
//!
//! DB overrides of runtime settings are read only at startup (ADR-0014), so applying them needs a
//! restart. This places a DIP boundary so that restart can be triggered from the settings screen.
//!
//! **The app cannot restart itself.** All it can do is shut itself down cleanly; starting a new
//! process is the deployment side's restart policy (Compose, systemd, k8s). The trait is not named
//! [`ServiceStopper`] instead of `Restarter` because users see the operation as a "restart" and the
//! ubiquitous language follows that; note here, though, that the implementation only does the
//! stopping.

/// Restart of the running service (= a graceful shutdown request).
///
/// Provided by the layer that controls the process (`service_restart::ServiceRestart` in api).
pub trait ServiceRestarter: Send + Sync {
    /// Requests a restart. **Does not stop immediately** (the implementation stops after draining
    /// in-flight requests).
    fn request_restart(&self);
}
