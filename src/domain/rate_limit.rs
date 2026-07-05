//! ログイン試行のレート制限（IP 単位、設計仕様 §4.3）。実装は infrastructure 層。

use chrono::{DateTime, Utc};

pub trait LoginRateLimiter: Send + Sync {
    /// `key`（IP アドレス等）の試行を 1 回記録し、制限内なら `true` を返す。
    /// 制限超過なら `false`（呼び出し側はログインを拒否する）。
    fn check_and_record(&self, key: &str, now: DateTime<Utc>) -> bool;
}
