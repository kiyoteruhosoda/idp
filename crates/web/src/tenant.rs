//! テナント経路（`/{tenant_id}/...`）から tenant_id を取り出す（ADR-0009 §6・§8、MT13）。
//!
//! web は DB を持たないため実在確認は行わない（UUID 形式のみ検証。存在確認・`ACTIVE` 判定は
//! api 呼び出し側の 404/403 に委ねる。api 側の `TenantResolver` が最終防御線）。

use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

tokio::task_local! {
    /// 処理中のリクエストの、テナント配下のパス（`/admin/accounts` など）。
    static TENANT_RELATIVE_PATH: String;
}

/// 処理中のリクエストの、テナント配下のパス（`/{tenant_id}` を除いたもの）。
///
/// 管理コンソールの共通レイアウトが、開いている画面をメニューとタブ名に示すために読む
/// （`templates::current_console_nav_item`）。画面ごとのテンプレート構造体や
/// `resolve_admin` の引数で持ち回らないのは、値が**リクエストの属性**であって画面ごとの
/// 入力ではないから —— 100 か所を超える呼び出し側のどこか 1 つが渡し忘れると、その画面
/// だけ印が出ない。[`capture_tenant`] を通らない描画（テンプレートの単体テストなど）では `None`。
pub fn current_relative_path() -> Option<String> {
    TENANT_RELATIVE_PATH.try_with(|path| path.clone()).ok()
}

/// 指定のパスを開いているものとして描画する（テンプレートのテスト用）。
#[cfg(test)]
pub(crate) fn with_relative_path<R>(path: &str, render: impl FnOnce() -> R) -> R {
    TENANT_RELATIVE_PATH.sync_scope(path.to_string(), render)
}

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
    let path = relative_path(request.uri().path(), tenant_id);
    request
        .extensions_mut()
        .insert(WebTenant(tenant_id.clone()));
    TENANT_RELATIVE_PATH.scope(path, next.run(request)).await
}

/// リクエストのパスから `/{tenant_id}` を除く。
///
/// `nest("/{tenant_id}", …)` の内側では axum が既に外しているのでそのまま返る。外側へ付け替えても
/// 同じ値になるよう、付いていれば外す。
fn relative_path(path: &str, tenant_id: &str) -> String {
    let prefix = format!("/{tenant_id}");
    match path.strip_prefix(prefix.as_str()) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => rest.to_string(),
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relative_path_never_carries_the_tenant_prefix() {
        let tenant = "00000000-0000-7000-8000-000000000001";
        assert_eq!(relative_path("/admin/accounts", tenant), "/admin/accounts");
        assert_eq!(
            relative_path(&format!("/{tenant}/admin/accounts"), tenant),
            "/admin/accounts"
        );
        assert!(relative_path(&format!("/{tenant}"), tenant).is_empty());
        // 前方一致するだけの別のパスは切らない。
        assert_eq!(
            relative_path(&format!("/{tenant}0/admin"), tenant),
            format!("/{tenant}0/admin")
        );
    }

    #[test]
    fn the_relative_path_is_absent_outside_a_request() {
        assert_eq!(current_relative_path(), None);
        assert_eq!(
            with_relative_path("/admin", current_relative_path),
            Some("/admin".to_string())
        );
    }
}
