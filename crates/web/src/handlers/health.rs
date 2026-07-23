//! ヘルスチェック（ADR-0007 §8）。
//!
//! `/healthz` は liveness（依存を見ない）。`/readyz` は api への到達性を確認する
//! （web は DB を持たないため、readiness は api の可用性で判断する）。

use crate::state::WebState;
use crate::templates::{render, VersionTemplate};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use idp_contracts::version::{BuildTimeVersionInfoProvider, VersionInfoProvider};

// version 画面は web のビルド情報に加え、api から取得した DB スキーマの適用状態も表示する。

/// liveness: プロセスが生きていれば 200。依存先は見ない。
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// readiness: api に到達できれば 200、できなければ 503。
pub async fn readiness(State(state): State<WebState>) -> StatusCode {
    if state.api.is_api_reachable().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// version: web のビルド情報（Cargo / Git）と、api から取得した DB スキーマ（マイグレーション）の
/// 適用状態を表示する。DB を直接見られない運用者が、適用済み version を画面から確認できるようにする。
/// api 未到達時はスキーマ欄を「取得できません」表示にフォールバックする（fail-soft）。
pub async fn version(State(state): State<WebState>) -> Html<String> {
    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    let schema = state.api.fetch_schema_version().await;
    Html(render(&VersionTemplate {
        info: provider.version_info(),
        schema,
    }))
}
