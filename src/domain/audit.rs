//! 監査イベント（設計仕様 §7）。構造化ログと `audit_log` テーブルの双方へ出力する。
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 監査イベント種別（設計仕様 §7）。`sso_session.terminated` は将来の Logout 用に予約。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    LoginSucceeded,
    LoginFailed,
    LoginLocked,
    AuthorizationCodeIssued,
    AuthorizationCodeUsed,
    AuthorizationCodeReuseDetected,
    TokenIssued,
    ClientAuthenticationFailed,
    SsoSessionCreated,
    SsoSessionResumed,
    SsoSessionExpired,
    SsoSessionTerminated,
    /// 管理者による利用者権限の付与／剥奪（ADR-0006、設計仕様 §7）。
    UserPermissionGranted,
    UserPermissionRevoked,
    /// 管理者によるクライアント（RP）の登録・更新・シークレット再発行（設計仕様 §9.3・§7）。
    ClientRegistered,
    ClientUpdated,
    ClientSecretRotated,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::LoginLocked => "login.locked",
            Self::AuthorizationCodeIssued => "authorization_code.issued",
            Self::AuthorizationCodeUsed => "authorization_code.used",
            Self::AuthorizationCodeReuseDetected => "authorization_code.reuse_detected",
            Self::TokenIssued => "token.issued",
            Self::ClientAuthenticationFailed => "client.authentication_failed",
            Self::SsoSessionCreated => "sso_session.created",
            Self::SsoSessionResumed => "sso_session.resumed",
            Self::SsoSessionExpired => "sso_session.expired",
            Self::SsoSessionTerminated => "sso_session.terminated",
            Self::UserPermissionGranted => "user_permission.granted",
            Self::UserPermissionRevoked => "user_permission.revoked",
            Self::ClientRegistered => "client.registered",
            Self::ClientUpdated => "client.updated",
            Self::ClientSecretRotated => "client.secret_rotated",
        }
    }
}

/// 監査イベントの成否。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult {
    Success,
    Failure,
}

impl AuditResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// 監査イベント 1 件。PII は含めない（ユーザー識別はハッシュ済み `user_id` のみ）。
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub occurred_at: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: AuditResult,
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// `audit_log` から読み出した 1 行（状況確認画面 A3 の読み取りモデル）。
///
/// `event_type` / `result` は保存時の文字列そのままを保持する（過去に廃止された種別も欠落なく表示するため、
/// enum へは restrict しない）。
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub event_type: String,
    pub occurred_at: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// 監査ログ検索条件（A3。エラー絞り込みを主眼に、`event_type` / `result` / 期間 / `client_id` /
/// `correlation_id` で絞る）。指定した項目のみ AND で適用する。
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub event_type: Option<String>,
    pub result: Option<String>,
    pub client_id: Option<String>,
    pub correlation_id: Option<String>,
    /// 期間の下限・上限（`occurred_at`、含む）。
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// ページング（新しい順）。
    pub limit: i64,
    pub offset: i64,
}
