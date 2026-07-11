//! テナント経路（`/{tenant_id}/...`）から tenant_id を取り出す（ADR-0009 §6・§8、MT13）。
//!
//! web は DB を持たないため実在確認は行わない（UUID 形式のみ検証。存在確認・`ACTIVE` 判定は
//! api 呼び出し側の 404/403 に委ねる。api 側の `TenantResolver` が最終防御線）。

use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

/// 経路から解決した tenant_id（`Extension` として注入される）。
#[derive(Debug, Clone)]
pub struct WebTenant(pub String);

impl WebTenant {
    /// パス組み立て用の `/{tenant_id}` プレフィクス。
    pub fn prefix(&self) -> String {
        format!("/{}", self.0)
    }
}

/// テナント経路 middleware 本体。ネストしたルートは複数のパスパラメータを持ちうるため、
/// `tenant_id` を名前で取り出す（api の `resolve_tenant` と同じ方式）。
pub async fn capture_tenant(
    Path(params): Path<HashMap<String, String>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(tenant_id) = params.get("tenant_id") else {
        tracing::error!("capture_tenant mounted on a route without a {{tenant_id}} segment");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if uuid::Uuid::parse_str(tenant_id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    request
        .extensions_mut()
        .insert(WebTenant(tenant_id.clone()));
    next.run(request).await
}
