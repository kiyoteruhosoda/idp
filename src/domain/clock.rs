//! 時刻取得の抽象（テストで固定実装に差し替えるための境界）。
//!
//! 実環境の時刻取得は必ず本トレイト越しに行う（`CLAUDE.md`「テスト」）。実装は infrastructure 層。

use chrono::{DateTime, Utc};

pub trait Clock: Send + Sync {
    /// 現在時刻（常に UTC）。
    fn now(&self) -> DateTime<Utc>;
}
