//! 汎用 TTL キャッシュ抽象（DIP 境界。ADR-0009 §7）。
//!
//! テナント解決（id → tenant）と scope→権限解決（`(user_id, permission_code, tenant_id)` の存在確認）は
//! いずれもリクエスト毎に評価されるホットパスであり、TTL 付きインメモリキャッシュ + 更新時 invalidation
//! で参照コストを抑える。キャッシュは用途ごとに別インスタンス（別キー空間）を注入して共有する
//! 汎用機構として設計する。
//!
//! `InMemoryLoginRateLimiter` と同様、trait 越しに注入して単体インスタンス前提とし、スケールアウト時は
//! Redis 等の共有ストア実装へ差し替える（本 trait が DIP 境界）。実装は infrastructure 層
//! （[`crate::infrastructure::cache`]）。
#![allow(dead_code)]

/// キー `K` から値 `V` を引く TTL キャッシュ。時刻依存（有効期限判定）は実装内部に閉じ、
/// 呼び出し側は現在時刻を意識しない。トレイトオブジェクト（`Arc<dyn Cache<K, V>>`）として
/// 注入できるよう、メソッドはジェネリクスを持たない（object-safe）。
pub trait Cache<K, V>: Send + Sync {
    /// 有効期限内のエントリがあれば複製を返す。無い（未登録・期限切れ）場合は `None`。
    fn get(&self, key: &K) -> Option<V>;
    /// エントリを登録する（既存キーは上書きし、TTL を張り直す）。
    fn insert(&self, key: K, value: V);
    /// 指定キーのエントリを無効化する（付与・剥奪・更新時に呼ぶ）。
    fn invalidate(&self, key: &K);
}
