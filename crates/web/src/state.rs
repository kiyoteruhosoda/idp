//! web の共有状態（axum `State`）。API クライアントと設定を保持する。

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::cookies::SetCookies;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebState {
    pub config: Arc<Config>,
    pub api: ApiClient,
}

impl WebState {
    pub fn build(config: Arc<Config>) -> Self {
        let api = ApiClient::new(
            config.api_base_url().to_string(),
            config.internal_service_token().to_string(),
        );
        Self { config, api }
    }

    /// 応答へ載せる `Set-Cookie` の組み立てを始める（属性方針は設定から取る。ADR-0012 §3）。
    pub fn set_cookies(&self) -> SetCookies {
        SetCookies::new(self.config.cookie_policy().clone())
    }
}
