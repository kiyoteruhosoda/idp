//! Back-channel logout の送信要求（`backchannel_logout_deliveries`。G5）。
//!
//! OpenID Connect Back-Channel Logout 1.0 の通知を「撃ちっぱなし」から「永続キュー + 再試行」へ
//! 移すための行表現。RP がその瞬間だけ落ちていた・ネットワークが切れていた、という理由で
//! ログアウトが黙って失われないようにする。
//!
//! 署名済みの `logout_token` は保存しない（保存すると「RP へ提示すればログアウトが成立する値」が
//! DB に長く残り、再試行のたびに `iat`/`exp` も古いままになる）。クレームの素材だけを持ち、送信の
//! 直前に現行の署名鍵で署名する。`jti` だけは行の作成時に確定させ、再試行でも変えない（RP 側は
//! `jti` で重複配送を弾ける）。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// 1 クライアントへの back-channel logout 通知要求。
#[derive(Debug, Clone)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    /// ログアウトが発生したテナント（`logout_token` の `iss` を導出する）。
    pub tenant_id: TenantId,
    /// 通知先クライアント（`logout_token` の `aud`）。
    pub client_id: String,
    pub target_uri: String,
    /// `logout_token` の `sub`（利用者の外部公開識別子）。
    pub subject: String,
    /// `logout_token` の `sid`。セッション単位のログアウトに使う（不明なら `None`）。
    pub sid: Option<String>,
    /// `logout_token` の `jti`。再試行で変えない。
    pub jti: Uuid,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BackchannelLogoutDelivery {
    /// 新規の送信要求を組み立てる（次回試行は即時）。
    pub fn new(
        id: Uuid,
        jti: Uuid,
        tenant_id: TenantId,
        client_id: String,
        target_uri: String,
        subject: String,
        sid: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            tenant_id,
            client_id,
            target_uri,
            subject,
            sid,
            jti,
            attempts: 0,
            next_attempt_at: now,
            last_error: None,
            delivered_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_delivered(&self) -> bool {
        self.delivered_at.is_some()
    }
}

/// 再試行の待ち時間（指数バックオフ）。
///
/// `attempts` は**その試行を終えた時点の回数**（1 回目の失敗後は 1）。上限を設けるのは、
/// 長期間落ちている RP のために間隔が無限に伸びて事実上の放置になるのを避けるため。
pub fn retry_backoff(attempts: i32) -> Duration {
    const BASE_SECS: i64 = 30;
    const MAX_SECS: i64 = 3_600;
    let exponent = attempts.clamp(1, 16) - 1;
    let secs = BASE_SECS.saturating_mul(1i64 << exponent.min(20));
    Duration::seconds(secs.min(MAX_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(retry_backoff(1), Duration::seconds(30));
        assert_eq!(retry_backoff(2), Duration::seconds(60));
        assert_eq!(retry_backoff(3), Duration::seconds(120));
        // 上限（1 時間）を超えない。
        assert_eq!(retry_backoff(20), Duration::seconds(3_600));
        // 0・負の入力でも最小待ちに落ちる（呼び出し側の取り違えでゼロ待ちループにしない）。
        assert_eq!(retry_backoff(0), Duration::seconds(30));
        assert_eq!(retry_backoff(-5), Duration::seconds(30));
    }
}
