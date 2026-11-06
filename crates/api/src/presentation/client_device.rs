//! web が添えた今のブラウザの端末の印を、内部の要求の間だけ持つ（task #916。ADR-0079）。
//!
//! web はどの要求でも端末の印（Cookie `assay_device`。無ければその場で作る）を内部の呼び出しに
//! [`CLIENT_DEVICE_HEADER`] として添える。この middleware は **`/internal/*` のサブルータにだけ**付ける
//! （サービストークンの内側）。外から直接 api に来た要求の同じ見出しは読まない。
//!
//! ログインの経路ごとに DTO へ欄を足さないのは、足し忘れた経路だけ「印が無い＝登録していない」に
//! 落ちるため（関門は断る側へ倒れるので通しはしないが、正しい利用者が入れなくなる）。

use crate::domain::user_device::{DeviceRef, RequestDevice};
use assay_contracts::auth::CLIENT_DEVICE_HEADER;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

tokio::task_local! {
    static CLIENT_DEVICE: Option<DeviceRef>;
}

/// 内部の要求の間だけ、web が添えた端末の印（の指紋）を置く。
pub async fn capture_client_device(request: Request, next: Next) -> Response {
    let device = request
        .headers()
        .get(CLIENT_DEVICE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(DeviceRef::from_token);
    CLIENT_DEVICE.scope(device, next.run(request)).await
}

/// 今の要求の端末の印を引く口（要求の外・外からの要求では `None`）。
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
