//! セキュリティの知らせ（task #872。ADR-0071）。
//!
//! 「登録していない端末でログインした」「端末を登録した・取り消した・登録が切れた」を、運用者の
//! 知らせの宛先へ送る。**送れなくても元の処理は止めない**（ログインを知らせの失敗で断らない）。
//! 同じ出来事は必ず監査ログにも残るので、知らせは「気付くのを早くする」ための写しにあたる。
//!
//! 知らせに載せるのは表示の材料（時刻・国・ブラウザの名乗り・入り方・端末の名前）だけで、
//! 端末の印・セッション id・メールアドレスは載せない。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::tenant::TenantId;
use crate::domain::user_device::CountryCode;
use crate::domain::values::AuthenticationMethod;

/// 知らせる出来事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityAlertKind {
    /// 登録していない端末でログインした。
    UnregisteredDeviceSignIn {
        /// その端末で初めて見たログインか（同じ印でのログインが前にもあれば `false`）。
        first_seen: bool,
        methods: Vec<AuthenticationMethod>,
    },
    /// 端末を登録した。
    DeviceRegistered { device_name: String },
    /// 利用者が端末の登録を取り消した。
    DeviceRevoked { device_name: String },
    /// 使われないまま期限が過ぎ、端末の登録が切れた。
    DeviceExpired { device_name: String },
    /// SSH の公開鍵を登録した（task #885）。
    SshKeyRegistered {
        key_name: String,
        fingerprint: String,
    },
    /// SSH の公開鍵を取り消した（task #885）。
    SshKeyRevoked {
        key_name: String,
        fingerprint: String,
    },
}

impl SecurityAlertKind {
    /// 知らせの重さ。登録していない端末でのログインと登録・取り消しは「注意」、期限切れは「お知らせ」。
    pub fn severity(&self) -> SecurityAlertSeverity {
        match self {
            Self::UnregisteredDeviceSignIn { .. }
            | Self::DeviceRegistered { .. }
            | Self::DeviceRevoked { .. }
            | Self::SshKeyRegistered { .. }
            | Self::SshKeyRevoked { .. } => SecurityAlertSeverity::Warning,
            Self::DeviceExpired { .. } => SecurityAlertSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAlertSeverity {
    Info,
    Warning,
}

/// 知らせ 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAlert {
    pub kind: SecurityAlertKind,
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// 利用者の表示名（ログイン id）。知らせを読む人が「誰の話か」を分かるようにする。
    pub username: String,
    pub occurred_at: DateTime<Utc>,
    pub country: Option<CountryCode>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// 同じ端末の知らせを 1 件へ束ねるための鍵（端末の印の指紋の先頭。印そのものではない）。
    pub group_key: String,
}

/// 知らせの送り口。実装は呼び出し元を待たせない（送信と送り直しは裏で行う）。
#[async_trait]
pub trait SecurityAlertSink: Send + Sync {
    async fn send(&self, alert: SecurityAlert);
}

/// 送り先が設定されていないときの送り口（何もしない）。
pub struct DisabledSecurityAlertSink;

#[async_trait]
impl SecurityAlertSink for DisabledSecurityAlertSink {
    async fn send(&self, _alert: SecurityAlert) {}
}
