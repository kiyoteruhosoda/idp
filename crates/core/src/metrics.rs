//! メトリクスの**名前とラベルの定義**（G6）。
//!
//! 収集器（Prometheus レコーダ）の設置と `/internal/metrics` の配信は api が持つ
//! （`crate::presentation::metrics`）。ここに置くのは「どんな名前で何を数えるか」だけで、
//! `tracing` と同じく **facade へ記録するだけ**の層である。収集器が設置されていなければ
//! 記録は捨てられる（メトリクスが無効な構成でも呼び出し側は分岐しなくてよい）。
//!
//! # ラベルの基数（cardinality）
//!
//! Prometheus はラベル値の組み合わせごとに時系列を作る。値の種類が増え続けるラベル
//! （`tenant_id`・`user_id`・`client_id`・`correlation_id`・URL のパス変数）を付けると、
//! 監視側のメモリが利用者数に比例して膨らむ。**ここで使うラベルは有限の enum に限る**。
//! 「どのテナントで失敗したか」は監査ログ（`audit_log`）で追う——メトリクスは
//! 「全体として何件起きているか」を見るための集約である。

/// 監査イベントの発生数（`event_type` × `result`）。
///
/// ログイン成功率・トークン発行レート・鍵ローテーションの成否は、すべてこの 1 本から出る。
/// 個別に計測器を散らさないのは、監査イベントが既に「何が起きたか」のドメイン語彙であり、
/// 二重に定義すると片方だけ増えて静かにずれるため。ラベルはどちらも有限の enum。
pub const AUDIT_EVENTS: &str = "idp_audit_events_total";

/// HTTP リクエストの所要時間（秒）。ラベルは `service`・`method`・`route`・`status`。
///
/// `route` は**マッチしたルートの雛形**（`/{tenant_id}/admin/users/{user_id}`）で、実 URL では
/// ない。実 URL を入れるとテナント・利用者ごとに時系列が増える。
pub const HTTP_REQUEST_DURATION: &str = "idp_http_request_duration_seconds";

/// sqlx コネクションプールの接続数。ラベル `state` は `total`（確立済み）と `idle`（貸出可能）。
///
/// 枯渇は「`total` が上限に張り付き、`idle` が 0 のまま」として現れる。所要時間の悪化だけでは
/// DB 側が遅いのかプール待ちなのか区別できないため、両方を見る。
pub const DB_POOL_CONNECTIONS: &str = "idp_db_pool_connections";

/// `DB_POOL_CONNECTIONS` の `state` ラベル値。
pub const DB_POOL_STATE_TOTAL: &str = "total";
pub const DB_POOL_STATE_IDLE: &str = "idle";
