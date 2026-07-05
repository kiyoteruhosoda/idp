//! axum の共有状態。各サービスを `Arc` で保持し、`FromRef` でハンドラへ部分注入する。

use crate::application::register::RegisterService;
use crate::infrastructure::db::Db;
use axum::extract::FromRef;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: Db,
    pub register: Arc<RegisterService>,
}

impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Db {
        state.pool.clone()
    }
}

impl FromRef<AppState> for Arc<RegisterService> {
    fn from_ref(state: &AppState) -> Arc<RegisterService> {
        state.register.clone()
    }
}
