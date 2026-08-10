//! Prometheus メトリクスの収集と配信（G6）。
//!
//! 可観測性が JSON ログと `log` / `audit_log` テーブルだけだったため、ログイン成功率・
//! トークン発行レート・エンドポイント別レイテンシ・DB プールの枯渇といった SLO を見るのに要る値が
//! 取れなかった。ここでは `metrics` facade の収集器を設置し、Prometheus のテキスト形式で配信する。
//!
//! # 公開面
//!
//! `/internal/metrics` に置く。`/internal/*` は**リバースプロキシで外部から遮断する前提**の面で
//! （ADR-0007 §5）、多層防御としてサービス認証トークン（`X-Internal-Auth-Token`）も要る。
//! メトリクスは「どの利用者がいつ何回失敗したか」を集約した情報であり、公開面に出す値ではない。
//! Prometheus 側はスクレイプ設定でヘッダを付けて取得する（`docs/OPERATIONS.md` 参照）。
//!
//! # 何を測るか
//!
//! - **監査イベント**（ログイン成否・トークン発行・鍵ローテーション等）: 記録は
//!   `AuditService` の 1 か所（`idp_core::metrics::AUDIT_EVENTS`）。計測器を各ユースケースへ
//!   散らさない。
//! - **HTTP の所要時間**: 本モジュールのミドルウェア。
//! - **DB プールの接続数**: 定期タスク（`spawn_db_pool_metrics`）。
//!
//! ラベルの基数を有限に保つ方針は `idp_core::metrics` に書いてある。

use crate::infrastructure::db::Db;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// このサービスを表す `service` ラベル値。web も同じ名前のメトリクスを出す場合に区別できるよう
/// 付けておく（現時点で `/metrics` を持つのは api だけ）。
const SERVICE: &str = "api";

/// 所要時間ヒストグラムの区切り（秒）。
///
/// IdP の応答は「数ミリ秒（キャッシュ済みの discovery）」から「数百ミリ秒（Argon2 を伴う
/// トークン発行）」までの幅がある。既定の区切りだとこの帯域が 1〜2 バケットに潰れて
/// p95 が読めないため、5ms〜10s を対数的に刻む。
const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// DB プール接続数を観測する間隔。枯渇は数十秒続いて初めて問題になるため 10 秒で足りる。
const DB_POOL_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// 収集器を**プロセスに 1 度だけ**設置し、レンダリング用のハンドルを返す。
///
/// `metrics` の収集器はプロセスグローバルで、2 度設置できない。統合テストは 1 プロセス内で
/// `AppState` を何度も組み立てるため、2 度目以降は最初のハンドルを返す（失敗にしない）。
pub fn handle() -> Option<PrometheusHandle> {
    static HANDLE: std::sync::OnceLock<Option<PrometheusHandle>> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let builder = PrometheusBuilder::new()
                .add_global_label("service", SERVICE)
                .set_buckets_for_metric(
                    metrics_exporter_prometheus::Matcher::Full(
                        idp_core::metrics::HTTP_REQUEST_DURATION.to_string(),
                    ),
                    DURATION_BUCKETS,
                )
                .expect("duration buckets are a non-empty compile-time constant");
            match builder.install_recorder() {
                Ok(handle) => Some(handle),
                Err(e) => {
                    // メトリクスが出ないことは可用性の問題ではない。起動は続ける。
                    tracing::warn!(error = %e, "failed to install the metrics recorder; /internal/metrics will be empty");
                    None
                }
            }
        })
        .clone()
}

/// `GET /internal/metrics`: Prometheus のテキスト形式で現在値を返す。
///
/// 収集器の設置に失敗している場合は 503 を返す（空の 200 を返すと、監視側からは
/// 「イベントが 1 件も起きていない」と区別できない）。
pub async fn metrics_endpoint(
    State(state): State<crate::presentation::state::AppState>,
) -> Response {
    match state.metrics.as_ref() {
        Some(handle) => (
            StatusCode::OK,
            [
                // Prometheus のテキスト形式（version 0.0.4）。
                (
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            handle.render(),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics recorder is not installed\n",
        )
            .into_response(),
    }
}

/// HTTP リクエストの所要時間を記録するミドルウェア。
///
/// `route` ラベルには**マッチしたルートの雛形**を使う。実 URL を使うと、テナント ID・利用者 ID が
/// そのままラベル値になって時系列が際限なく増える。雛形が取れないリクエスト（404）は
/// `unmatched` にまとめる——存在しないパスを叩かれるだけで時系列が増えては困る。
pub async fn track_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();

    metrics::histogram!(
        idp_core::metrics::HTTP_REQUEST_DURATION,
        "method" => method.as_str().to_string(),
        "route" => route,
        "status" => response.status().as_u16().to_string(),
    )
    .record(elapsed.as_secs_f64());

    response
}

/// sqlx コネクションプールの接続数を定期的に観測するタスクを起こす。
///
/// gauge を「使うたびに書く」形にしないのは、プールの枯渇が**何も起きていない間**にこそ
/// 見たい値だから（枯渇して要求が待たされているとき、記録する側も待たされている）。
pub fn spawn_db_pool_metrics(pool: Db) {
    tokio::spawn(async move {
        loop {
            metrics::gauge!(
                idp_core::metrics::DB_POOL_CONNECTIONS,
                "state" => idp_core::metrics::DB_POOL_STATE_TOTAL,
            )
            .set(pool.size() as f64);
            metrics::gauge!(
                idp_core::metrics::DB_POOL_CONNECTIONS,
                "state" => idp_core::metrics::DB_POOL_STATE_IDLE,
            )
            .set(pool.num_idle() as f64);
            tokio::time::sleep(DB_POOL_SAMPLE_INTERVAL).await;
        }
    });
}
