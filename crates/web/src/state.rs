//! web の共有状態（axum `State`）。API クライアントと設定を保持する。

use crate::api_client::ApiClient;
use crate::config::Config;
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
}
