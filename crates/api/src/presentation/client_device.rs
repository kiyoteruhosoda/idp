//! Holds the current browser's device mark attached by web, only during an internal request (task #916, ADR-0079).
//!
//! On every request web attaches the device mark (cookie `assay_device`, created on the spot if absent) to internal calls
//! as [`CLIENT_DEVICE_HEADER`]. This middleware is attached **only to the `/internal/*` subrouter**
//! (behind the service token). The same header on requests hitting the api directly is not read.
//!
//! We don't add a field to each sign-in path's DTO because any path that forgot it would fall into "no mark = not registered"
//! (the gate fails closed so nothing is let through, but legitimate users would be locked out).

use crate::domain::user_device::{DeviceRef, RequestDevice};
use assay_contracts::auth::CLIENT_DEVICE_HEADER;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_DEVICE: Option<DeviceRef>;
}

/// Holds the device mark (its fingerprint) attached by web, only during an internal request.
pub async fn capture_client_device(request: Request, next: Next) -> Response {
    let device = request
        .headers()
        .get(CLIENT_DEVICE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(DeviceRef::from_token);
    CLIENT_DEVICE.scope(device, next.run(request)).await
}

/// Accessor for the current request's device mark (`None` outside a request or for external requests).
pub struct TaskLocalRequestDevice;

impl RequestDevice for TaskLocalRequestDevice {
    fn current(&self) -> Option<DeviceRef> {
        CLIENT_DEVICE.try_with(Clone::clone).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_device_is_visible_only_inside_the_scope() {
        assert_eq!(TaskLocalRequestDevice.current(), None);
        let token = "a".repeat(64);
        let inside = CLIENT_DEVICE
            .scope(DeviceRef::from_token(&token), async {
                TaskLocalRequestDevice.current()
            })
            .await;
        assert_eq!(inside, DeviceRef::from_token(&token));
        assert_eq!(TaskLocalRequestDevice.current(), None);
    }
}
