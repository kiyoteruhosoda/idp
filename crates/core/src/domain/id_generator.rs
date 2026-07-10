//! エンティティ ID 生成の抽象（テストで固定値に差し替えるための境界。ADR-0009 §12）。
//!
//! 実環境の ID 生成は必ず本トレイト越しに行う（`CLAUDE.md`「テスト」。時刻・乱数と同様に注入する）。
//! 生成する UUID は UUIDv7（時刻順序型）。`jti`・`correlation_id`・`csrf_id` 等の揮発トークンは
//! この抽象の対象外で、呼び出し側が直接 `Uuid::new_v4()` を使う（時刻順序性が不要かつ
//! 生成時刻を露出させたくないため）。

use uuid::Uuid;

pub trait IdGenerator: Send + Sync {
    /// エンティティ主キー用の UUID（UUIDv7）を生成する。
    fn new_id(&self) -> Uuid;
}
