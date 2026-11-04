//! 本人が見る「ログイン履歴」（task #879。ADR-0073）。
//!
//! 1 回のログインの試み（成功・失敗・締め出し・決まりで断った）を 1 行として残し、成功したログインには
//! 「どのアプリで使われ、リフレッシュトークンがどう使われたか」を添える。
//!
//! # 2 つの接続元を混ぜない
//!
//! ログインの行の接続元・ブラウザは**ログインした本人のブラウザ**。リフレッシュの接続元・名乗りは
//! **トークンを送ってきた相手**で、アプリのサーバーが裏で更新するならそのサーバーになる。
//! 同じ列に入れると「家の外のサーバーの IP」を「家の外からログインされた」と読み違えるので、
//! 型も分けて持つ（[`SignInRecord`] と [`RefreshUsage`]）。

use crate::domain::audit::{AuditEvent, AuditEventType};
use crate::domain::tenant::TenantId;
use crate::domain::user_device::CountryCode;
use crate::domain::values::{string_enum, AuthenticationMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 1 ページに出す件数の上限（画面は新しい順にこの件数ずつ見る）。
pub const SIGN_IN_HISTORY_PAGE_MAX: u32 = 50;

string_enum!(
    /// ログインの試みの結末（`sign_in_history.outcome` の許可値）。
    SignInOutcome {
        /// ログインした。
        Succeeded => "succeeded",
        /// 資格情報が合わない等で断った。
        Failed => "failed",
        /// 失敗が続いた・締め出し中で断った。
        Locked => "locked",
        /// 認証ポリシー（決まり）で断った。
        Denied => "denied",
    }
);

string_enum!(
    /// 断った理由の種類（画面の言葉に写す分類。監査ログの `reason` を丸めたもの）。
    SignInFailureKind {
        WrongPassword => "wrong_password",
        WrongPasskey => "wrong_passkey",
        /// 確認コード（TOTP・リカバリーコード・メール/SMS のコード）が合わない。
        WrongCode => "wrong_code",
        /// 失敗が続いたので締め出した。
        TooManyFailures => "too_many_failures",
        /// 締め出し中に来た。
        AccountLocked => "account_locked",
        /// 利用者が止められている・メールが未確認。
        AccountNotActive => "account_not_active",
        /// 同じ接続元からの試みが多すぎる。
        RateLimited => "rate_limited",
        /// 認証ポリシー・管理者の権限が無い等の決まりで断った。
        PolicyDenied => "policy_denied",
        /// 外部の IdP でのログインが通らなかった。
        ExternalFailed => "external_failed",
        Other => "other",
    }
);

/// 断ったログインの試み（監査ログへ書く所で写す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInFailure {
    pub user_id: Uuid,
    pub tenant_id: Option<TenantId>,
    pub occurred_at: DateTime<Utc>,
    pub outcome: SignInOutcome,
    pub kind: SignInFailureKind,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub client_id: Option<String>,
}

/// 監査イベントが「本人の履歴に出すべき、断ったログイン」なら写しを返す。
///
/// 利用者が定まらない失敗（知らないユーザー名）は誰の履歴にも出さない。
pub fn sign_in_failure_from_audit(event: &AuditEvent) -> Option<SignInFailure> {
    let user_id = event.user_id?;
    let reason = event.reason.as_deref().unwrap_or("");
    let (outcome, kind) = match event.event_type {
        AuditEventType::LoginFailed => failure_kind(reason),
        AuditEventType::LoginLocked => (
            SignInOutcome::Locked,
            if reason == "too_many_failures" {
                SignInFailureKind::TooManyFailures
            } else {
                SignInFailureKind::AccountLocked
            },
        ),
        AuditEventType::LoginPolicyDenied => {
            (SignInOutcome::Denied, SignInFailureKind::PolicyDenied)
        }
        AuditEventType::ExternalLoginFailed => {
            (SignInOutcome::Failed, SignInFailureKind::ExternalFailed)
        }
        _ => return None,
    };
    Some(SignInFailure {
        user_id,
        tenant_id: event.tenant_id,
        occurred_at: event.occurred_at,
        outcome,
        kind,
        ip_address: event.ip_address.clone(),
        user_agent: event.user_agent.clone(),
        client_id: event.client_id.clone(),
    })
}

/// `login.failed` の `reason` を分類に写す。
fn failure_kind(reason: &str) -> (SignInOutcome, SignInFailureKind) {
    let kind = match reason {
        "invalid_password" | "invalid_current_password" => SignInFailureKind::WrongPassword,
        "invalid_passkey" => SignInFailureKind::WrongPasskey,
        "account_not_active" | "email_not_verified" => SignInFailureKind::AccountNotActive,
        "ip_rate_limited" => SignInFailureKind::RateLimited,
        "missing_admin_permission" => {
            return (SignInOutcome::Denied, SignInFailureKind::PolicyDenied)
        }
        r if r.starts_with("invalid_")
            && (r.contains("totp") || r.contains("code") || r.contains("otp")) =>
        {
            SignInFailureKind::WrongCode
        }
        _ => SignInFailureKind::Other,
    };
    (SignInOutcome::Failed, kind)
}

/// 成功したログイン（web がログイン状態の Cookie を置いた応答で写す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInSuccess {
    pub user_id: Uuid,
    pub tenant_id: TenantId,
    pub occurred_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<CountryCode>,
    pub methods: Vec<AuthenticationMethod>,
    /// SSO セッションの `sid`（リフレッシュトークンが持つ値と同じ）。
    pub sid: String,
    /// 登録した端末だったか（端末の印が届かなければ `None`）。
    pub device_registered: Option<bool>,
}

/// 履歴の 1 行（読み出し）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInRecord {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub outcome: SignInOutcome,
    pub failure_kind: Option<SignInFailureKind>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<CountryCode>,
    pub methods: Vec<AuthenticationMethod>,
    /// 断ったログインを始めたアプリ（分かれば）。
    pub client_id: Option<String>,
    pub app_name: Option<String>,
    pub sid: Option<String>,
    pub device_registered: Option<bool>,
}

/// 成功したログインが、あるアプリでどう使われたか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInAppUse {
    pub sid: String,
    pub client_id: String,
    pub app_name: Option<String>,
    pub first_issued_at: DateTime<Utc>,
    pub last_issued_at: DateTime<Utc>,
    /// リフレッシュトークンを出していなければ `None`。
    pub refresh: Option<RefreshUsage>,
}

/// リフレッシュトークンの使われ方。接続元・名乗りは**更新を送ってきた相手**のもの。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshUsage {
    pub use_count: u32,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_ip_address: Option<String>,
    pub last_user_agent: Option<String>,
    pub reuse_detected_at: Option<DateTime<Utc>>,
    pub state: RefreshState,
}

/// リフレッシュトークンの今の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshState {
    /// まだ使える。
    Active,
    /// 期限より前に取り消された（ログアウト・端末の取り消し・使い回しの検知など）。
    Revoked { at: Option<DateTime<Utc>> },
    /// 期限が過ぎた（掃除で行が消えたものも含む）。
    Expired,
}

/// `refresh_tokens` の (sid, client) ごとの集計。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefreshTokenTally {
    /// 残っている行の数（掃除で消えていれば 0）。
    pub rows: u32,
    /// 取り消されておらず期限内の行の数。
    pub active: u32,
    /// 期限内の行の数（取り消し済みを含む）。
    pub unexpired: u32,
    pub last_revoked_at: Option<DateTime<Utc>>,
}

impl RefreshTokenTally {
    /// 集計から今の状態を決める。
    ///
    /// 更新（rotation）のたびに古い行は取り消されるので、「取り消された行がある」だけでは取り消しと
    /// 言えない。使える行が 1 本も無く、期限内の行が残っているときだけ取り消しとみなす。
    pub fn state(&self) -> RefreshState {
        if self.active > 0 {
            RefreshState::Active
        } else if self.unexpired > 0 {
            RefreshState::Revoked {
                at: self.last_revoked_at,
            }
        } else {
            RefreshState::Expired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditResult;

    fn event(event_type: AuditEventType, reason: &str, user: Option<Uuid>) -> AuditEvent {
        AuditEvent {
            event_type,
            occurred_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            tenant_id: None,
            user_id: user,
            client_id: Some("app".into()),
            ip_address: Some("203.0.113.5".into()),
            user_agent: Some("UA".into()),
            result: AuditResult::Failure,
            reason: Some(reason.into()),
            correlation_id: "c".into(),
        }
    }

    #[test]
    fn wrong_password_and_lockout_are_told_apart() {
        let u = Some(Uuid::nil());
        let f =
            sign_in_failure_from_audit(&event(AuditEventType::LoginFailed, "invalid_password", u))
                .unwrap();
        assert_eq!(
            (f.outcome, f.kind),
            (SignInOutcome::Failed, SignInFailureKind::WrongPassword)
        );
        let l =
            sign_in_failure_from_audit(&event(AuditEventType::LoginLocked, "too_many_failures", u))
                .unwrap();
        assert_eq!(
            (l.outcome, l.kind),
            (SignInOutcome::Locked, SignInFailureKind::TooManyFailures)
        );
        let a =
            sign_in_failure_from_audit(&event(AuditEventType::LoginLocked, "account_locked", u))
                .unwrap();
        assert_eq!(a.kind, SignInFailureKind::AccountLocked);
    }

    #[test]
    fn codes_passkeys_and_policies_are_classified() {
        let u = Some(Uuid::nil());
        let kind = |t, r| sign_in_failure_from_audit(&event(t, r, u)).unwrap().kind;
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_totp"),
            SignInFailureKind::WrongCode
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_recovery_code"),
            SignInFailureKind::WrongCode
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "invalid_passkey"),
            SignInFailureKind::WrongPasskey
        );
        assert_eq!(
            kind(AuditEventType::LoginPolicyDenied, "policy=x"),
            SignInFailureKind::PolicyDenied
        );
        assert_eq!(
            kind(AuditEventType::ExternalLoginFailed, "provider=g reason=x"),
            SignInFailureKind::ExternalFailed
        );
        assert_eq!(
            kind(AuditEventType::LoginFailed, "something_new"),
            SignInFailureKind::Other
        );
    }

    #[test]
    fn failures_without_a_user_and_other_events_are_not_copied() {
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::LoginFailed,
            "unknown_user",
            None
        ))
        .is_none());
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::LoginSucceeded,
            "",
            Some(Uuid::nil())
        ))
        .is_none());
        assert!(sign_in_failure_from_audit(&event(
            AuditEventType::StepUpFailed,
            "",
            Some(Uuid::nil())
        ))
        .is_none());
    }

    #[test]
    fn rotation_alone_is_not_revocation() {
        let t = |rows, active, unexpired| RefreshTokenTally {
            rows,
            active,
            unexpired,
            last_revoked_at: None,
        };
        // 3 回更新した: 古い 3 本は取り消し済み、最新の 1 本が使える。
        assert_eq!(t(4, 1, 4).state(), RefreshState::Active);
        assert_eq!(
            t(4, 0, 4).state(),
            RefreshState::Revoked { at: None },
            "期限内なのに使える行が無い＝取り消された"
        );
        assert_eq!(t(4, 0, 0).state(), RefreshState::Expired);
        assert_eq!(t(0, 0, 0).state(), RefreshState::Expired, "掃除で消えた");
    }
}
