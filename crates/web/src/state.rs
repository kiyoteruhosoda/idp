//! web の共有状態（axum `State`）。API クライアントと設定を保持する。

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::cookies::SetCookies;
use crate::service_restart::ServiceRestart;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebState {
    pub config: Arc<Config>,
    pub api: ApiClient,
    /// 設定画面からの再起動要求（ADR-0017）。`run()` の graceful shutdown がこの値を待つ。
    /// テストでは `build` が作った値を誰も待たないため、要求しても何も起きない。
    pub restart: ServiceRestart,
}

impl WebState {
    pub fn build(config: Arc<Config>) -> Self {
        let api = ApiClient::new(
            config.api_base_url().to_string(),
            config.internal_service_token().to_string(),
        );
        Self {
            config,
            api,
            restart: ServiceRestart::new(),
        }
    }

    /// 応答へ載せる `Set-Cookie` の組み立てを始める（属性方針は設定から取る。ADR-0012 §3）。
    pub fn set_cookies(&self) -> SetCookies {
        SetCookies::new(self.config.cookie_policy().clone())
    }
}
