//! 本人が見る「状況」の読み取りモデル（task #896。ADR-0078）。
//!
//! 「アカウントのセキュリティ」の先頭に、ログイン状態・持ち物・アプリのトークン・組織の決まり・注意を
//! 1 か所にまとめて出す。どれも既にある表（`sso_sessions`・`sso_session_contexts`・`user_devices`・
//! `app_approver_keys`・`refresh_tokens`・`sign_in_history`・`sign_in_app_usage`・`audit_log`）を
//! 読むだけで、新しく書くものは無い。

use crate::domain::user_device::CountryCode;
use chrono::{DateTime, NaiveDate, Utc};

/// 注意を数える期間（日）。
pub const WARNING_WINDOW_DAYS: i64 = 30;

/// 1 日の断られたログインがこの回数以上なら「失敗の多い日」として出す。
pub const FAILURE_DAY_THRESHOLD: u32 = 5;

/// アプリのトークンの一覧に、最近トークンを出したアプリとして載せる期間（日）。
pub const RECENT_APP_DAYS: i64 = 30;

/// ログイン状態 1 つの文脈（`sso_session_contexts` と、そこから辿れる端末・認証アプリの鍵）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionContextStatus {
    pub session_hash: String,
    /// このログイン状態を作ったブラウザの端末の印が分かっているか。
    pub device_identified: bool,
    /// その端末が登録済みなら、その登録。
    pub registered_device: Option<RegisteredDeviceStatus>,
    /// ログイン状態を作ったときの国。
    pub country: Option<CountryCode>,
    /// 端末の鍵の結び付け（DBSC）。
    pub key: Option<SessionKeyStatus>,
    /// 承認した認証アプリの鍵（承認で入ったとき）。
    pub approver: Option<ApproverStatus>,
    /// このログイン状態でパスキーの本人確認を最後に通した時刻。
    pub passkey_verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDeviceStatus {
    pub name: String,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyStatus {
    /// `ES256` / `RS256`。
    pub algorithm: String,
    /// 公開鍵の指紋（RFC 7638・base64url）。
    pub thumbprint: String,
    pub bound_at: DateTime<Utc>,
    /// 最後に鍵で署名して更新した時刻。
    pub refreshed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverStatus {
    pub device_name: String,
    /// `tee` / `strongbox` / `software`。
    pub security_level: String,
}

/// アプリ 1 つの、いま有効なトークンの種別。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTokenStatus {
    pub client_id: String,
    pub app_name: String,
    /// 同意した範囲（同意の記録が無ければ空）。
    pub scopes: Vec<String>,
    /// 期限内で取り消されていないリフレッシュトークンの数。
    pub active_refresh_tokens: u32,
    /// そのうち DPoP で端末の鍵に結び付いている数。
    pub dpop_bound_refresh_tokens: u32,
    /// 最後にこのアプリへトークンを出した時刻（記録があれば）。
    pub last_issued_at: Option<DateTime<Utc>>,
    /// リフレッシュトークンで更新した回数（記録の残っているログインの合計）。
    pub refresh_use_count: u32,
    /// 最後に更新した時刻と、そのとき送ってきた相手。
    pub refresh_last_used_at: Option<DateTime<Utc>>,
    pub refresh_last_ip: Option<String>,
    pub refresh_last_user_agent: Option<String>,
    /// 使い終えたリフレッシュトークンがもう一度来た最後の時刻。
    pub refresh_reuse_detected_at: Option<DateTime<Utc>>,
}

/// 直近の注意（[`WARNING_WINDOW_DAYS`] 日）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityWarnings {
    /// リフレッシュトークンの使い回しを検知した回数と最後の時刻。
    pub refresh_reuse: Occurrences,
    /// ログイン状態に別の鍵の署名が来た（Cookie の持ち出しの疑い）回数と最後の時刻。
    pub session_key_mismatch: Occurrences,
    /// アプリのトークンに別の鍵の DPoP が来た回数と最後の時刻。
    pub dpop_key_mismatch: Occurrences,
    /// 登録していない端末でログインした回数と最後の時刻。
    pub unregistered_sign_ins: Occurrences,
    /// 断られたログインが [`FAILURE_DAY_THRESHOLD`] 回以上あった日（UTC の日付）と回数。新しい順。
    pub failure_days: Vec<(NaiveDate, u32)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Occurrences {
    pub count: u32,
    pub last_at: Option<DateTime<Utc>>,
}

impl SecurityWarnings {
    /// 出すものが 1 つも無いか。
    pub fn is_empty(&self) -> bool {
        self.refresh_reuse.count == 0
            && self.session_key_mismatch.count == 0
            && self.dpop_key_mismatch.count == 0
            && self.unregistered_sign_ins.count == 0
            && self.failure_days.is_empty()
    }
}
