//! ヘルスチェック（ADR-0007 §8・ADR-0031）。
//!
//! `/healthz` は liveness（依存を見ない）。`/readyz` は api への到達性を確認する
//! （web は DB を持たないため、readiness は api の可用性で判断する）。どちらも**無認証**。
//!
//! 詳細（版数・稼働時間・サーバー時刻）は `/internal/health` に置き、内部トークンの内側でしか
//! 読めないようにする（ADR-0031 決定 1）。

use crate::state::WebState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use idp_contracts::health::{service, HealthCheck, LivenessResponse, ServiceHealth};
use idp_contracts::version::{BuildTimeVersionInfoProvider, VersionInfoProvider};

// version 画面は web のビルド情報に加え、api から取得した DB スキーマの適用状態も表示する。

/// liveness: プロセスが生きていれば 200。依存先は見ない。
///
/// 本文に `service` を載せるのは、domain-split（ADR-0019）で web（`idp.*`）と api（`identity.*`）が
/// 別ホストになった以上、「叩いたつもりのサービスと違う方が答えている」取り違えが起こり得るため。
/// 以前は本文が空だったので、200 が返っても**どちらが答えたのか分からなかった**。
pub async fn liveness() -> (StatusCode, Json<LivenessResponse>) {
    (StatusCode::OK, Json(LivenessResponse::ok(service::WEB)))
}

/// 内部向けの詳細ヘルス（`/internal/health`）。ルータが `require_service_token` の内側に置く。
///
/// web が依存するのは api だけなので、検査もそれ 1 つ。`server_time` を返すのは、時計ずれの
/// 切り分けに要るため（`private_key_jwt` の assertion は `exp` 5 分・許容 60 秒で判定するため、
/// ずれは「理由の分からない `invalid_client`」として現れる。ADR-0030）。
pub async fn internal_health(State(state): State<WebState>) -> Json<ServiceHealth> {
    let checks = vec![if state.api.is_api_reachable().await {
        HealthCheck::pass("api")
    } else {
        HealthCheck::fail("api", "api unreachable")
    }];

    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(ServiceHealth::new(
        service::WEB,
        provider.version_info(),
        state.started_at,
        chrono::Utc::now(),
        checks,
    ))
}

/// readiness: api に到達できれば 200、できなければ 503。
pub async fn readiness(State(state): State<WebState>) -> StatusCode {
    if state.api.is_api_reachable().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
