//! 監査イベント（設計仕様 §7）。構造化ログと `audit_log` テーブルの双方へ出力する。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 監査イベント種別（設計仕様 §7）。`sso_session.terminated` は将来の Logout 用に予約。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    LoginSucceeded,
    LoginFailed,
    LoginLocked,
    /// 認証ポリシーによるログイン拒否（ユーザー認証・認証ポリシー仕様書 §21）。`reason` に
    /// 一致したポリシーコードを記録する（資格情報は記録しない）。
    LoginPolicyDenied,
    /// 管理者による認証ポリシーの作成・更新・削除（同仕様 §21）。`reason` にポリシーコードを記録する。
    AuthenticationPolicyCreated,
    AuthenticationPolicyUpdated,
    AuthenticationPolicyDeleted,
    AuthorizationCodeIssued,
    AuthorizationCodeUsed,
    AuthorizationCodeReuseDetected,
    TokenIssued,
    ClientAuthenticationFailed,
    SsoSessionCreated,
    SsoSessionResumed,
    SsoSessionExpired,
    SsoSessionTerminated,
    /// SAML SSO: 署名付き SAML Response（アサーション）の発行（成功）／AuthnRequest の拒否（失敗。
    /// 未登録 SP・ACS 不一致等。理由を記録する）。
    SamlResponseIssued,
    /// 管理者による利用者権限の付与／剥奪（ADR-0006、設計仕様 §7）。
    UserPermissionGranted,
    UserPermissionRevoked,
    /// 管理者によるクライアント（RP）の登録・更新・シークレット再発行（設計仕様 §9.3・§7）。
    ClientRegistered,
    ClientUpdated,
    ClientSecretRotated,
    /// 管理者によるクライアントの論理削除（ADR-0035）。実体は残すので、削除後も
    /// `client_id` から「どのアプリだったか」を追える。
    ClientDeleted,
    /// Refresh Token の発行・使用（rotation 成功）・再利用検知（設計仕様 §9.1）。
    RefreshTokenIssued,
    RefreshTokenUsed,
    RefreshTokenReuseDetected,
    /// 同意の付与・取り消し（F3: Consent）。`ConsentRevoked` は利用者自身による連携解除（G10）。
    ConsentGranted,
    ConsentDenied,
    ConsentRevoked,
    /// ゲスト招待の作成・承諾・メンバーシップ解除（ADR-0009 §3）。招待トークンは記録しない。
    TenantInvitationCreated,
    TenantInvitationAccepted,
    TenantMembershipRevoked,
    /// ゲストメンバーシップの一時停止・再開（MT24）。解除（削除）と違い、メンバーシップ行と
    /// 当該テナント scope の権限行は残る。
    TenantMembershipSuspended,
    TenantMembershipResumed,
    /// 管理者による利用者の作成（ADR-0009 §5）。自動生成パスワードは記録しない。
    UserCreated,
    /// 管理者による利用者の状態変更（有効化・無効化）・削除・パスワード再発行（ADR-0009 §5）。
    /// 自動生成パスワードは記録しない。
    UserStatusChanged,
    UserDeleted,
    UserPasswordReset,
    /// 管理者による利用者プロフィール（メール・表示名・ログイン識別子）の更新（MT25）。
    /// 変更した項目名のみ記録し、値そのもの（PII）は記録しない。
    UserProfileUpdated,
    /// 管理者によるログイン識別子（AP8。仕様 §4）の追加・有効/無効の切替・削除。
    /// `reason` に**種別**のみ記録する（電話番号・メールアドレスは PII なので値は記録しない）。
    UserLoginIdentifierAdded,
    UserLoginIdentifierUpdated,
    UserLoginIdentifierRemoved,
    /// 認証器（AP9。仕様 §5）の状態変更・リカバリーコードの発行と使用・email OTP の送信。
    /// `reason` に種別・件数・残数を記録する（コード・シークレットそのものは記録しない）。
    AuthenticatorStatusChanged,
    RecoveryCodesIssued,
    RecoveryCodeUsed,
    EmailOtpSent,
    /// SMS OTP・電話番号の登録確認コードの送信（AP13）。`reason` に用途だけを記録する
    /// （電話番号もコードも記録しない）。
    SmsOtpSent,
    /// 管理者による MFA（TOTP・Passkey）の解除（MT21）。本人が端末を失った場合の復旧手段。
    /// 解除した要素の種別と件数のみ記録し、シークレット・クレデンシャルは記録しない。
    UserMfaReset,
    /// 管理者によるアカウントロックの即時解除（AP6。仕様 §17.1・§24.6）。`reason` に
    /// 解除前にロックが掛かっていたか・クリアした失敗回数を記録する。
    UserAccountUnlocked,
    /// 外部 IdP ログイン（AP10。仕様 §13）の成否。`reason` にプロバイダコードと失敗理由を
    /// 記録する（外部 IdP のトークン・クレームは記録しない）。
    ExternalLoginSucceeded,
    ExternalLoginFailed,
    /// 外部 IdP 設定（AP10）の作成・更新・削除。`reason` にプロバイダコードを記録する。
    ExternalIdpCreated,
    ExternalIdpUpdated,
    ExternalIdpDeleted,
    /// Step-up 認証（AP5。仕様 §15）の成否。`reason` に対象操作を記録する（資格情報は記録しない）。
    StepUpSucceeded,
    StepUpFailed,
    /// パスワード変更（初回強制変更を含む。ADR-0009 §5）。パスワードそのものは記録しない。
    PasswordChanged,
    /// テナントの作成・更新・削除（ADR-0009 §5）。自動生成パスワードは記録しない。
    TenantCreated,
    TenantUpdated,
    TenantDeleted,
    /// テナントへのドメイン割り当て（ADR-0029）。ログインをどのテナントへ向けるかを決める操作。
    TenantDomainAdded,
    TenantDomainRemoved,
    /// root（idp.system.admin）によるシステム設定の更新（SMTP 等。MT14）。値そのものは記録しない。
    SystemSettingsUpdated,
    /// root（idp.system.admin）による api の再起動要求（ADR-0017）。ランタイム設定の反映手段であり、
    /// 稼働中の全リクエストを打ち切る操作なので必ず監査へ残す。
    ServiceRestartRequested,
    /// パスワードリセットの要求・完了（MT18）。トークン・メールアドレスは記録しない。
    PasswordResetRequested,
    PasswordResetCompleted,
    /// 自己登録アカウントのメール検証の要求・完了（SEC6b）。トークン・メールアドレスは記録しない。
    EmailVerificationRequested,
    EmailVerified,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::LoginLocked => "login.locked",
            Self::LoginPolicyDenied => "login.policy_denied",
            Self::AuthenticationPolicyCreated => "authentication_policy.created",
            Self::AuthenticationPolicyUpdated => "authentication_policy.updated",
            Self::AuthenticationPolicyDeleted => "authentication_policy.deleted",
            Self::AuthorizationCodeIssued => "authorization_code.issued",
            Self::AuthorizationCodeUsed => "authorization_code.used",
            Self::AuthorizationCodeReuseDetected => "authorization_code.reuse_detected",
            Self::TokenIssued => "token.issued",
            Self::ClientAuthenticationFailed => "client.authentication_failed",
            Self::SsoSessionCreated => "sso_session.created",
            Self::SsoSessionResumed => "sso_session.resumed",
            Self::SsoSessionExpired => "sso_session.expired",
            Self::SsoSessionTerminated => "sso_session.terminated",
            Self::SamlResponseIssued => "saml_response.issued",
            Self::UserPermissionGranted => "user_permission.granted",
            Self::UserPermissionRevoked => "user_permission.revoked",
            Self::ClientRegistered => "client.registered",
            Self::ClientUpdated => "client.updated",
            Self::ClientSecretRotated => "client.secret_rotated",
            Self::ClientDeleted => "client.deleted",
            Self::RefreshTokenIssued => "refresh_token.issued",
            Self::RefreshTokenUsed => "refresh_token.used",
            Self::RefreshTokenReuseDetected => "refresh_token.reuse_detected",
            Self::ConsentGranted => "consent.granted",
            Self::ConsentDenied => "consent.denied",
            Self::ConsentRevoked => "consent.revoked",
            Self::TenantInvitationCreated => "tenant_invitation.created",
            Self::TenantInvitationAccepted => "tenant_invitation.accepted",
            Self::TenantMembershipRevoked => "tenant_membership.revoked",
            Self::TenantMembershipSuspended => "tenant_membership.suspended",
            Self::TenantMembershipResumed => "tenant_membership.resumed",
            Self::UserCreated => "user.created",
            Self::UserStatusChanged => "user.status_changed",
            Self::UserDeleted => "user.deleted",
            Self::UserPasswordReset => "user.password_reset",
            Self::UserProfileUpdated => "user.profile_updated",
            Self::UserLoginIdentifierAdded => "user.login_identifier_added",
            Self::UserLoginIdentifierUpdated => "user.login_identifier_updated",
            Self::UserLoginIdentifierRemoved => "user.login_identifier_removed",
            Self::AuthenticatorStatusChanged => "authenticator.status_changed",
            Self::RecoveryCodesIssued => "recovery_codes.issued",
            Self::RecoveryCodeUsed => "recovery_code.used",
            Self::EmailOtpSent => "email_otp.sent",
            Self::SmsOtpSent => "sms_otp.sent",
            Self::UserMfaReset => "user.mfa_reset",
            Self::UserAccountUnlocked => "user.account_unlocked",
            Self::ExternalLoginSucceeded => "external_login.succeeded",
            Self::ExternalLoginFailed => "external_login.failed",
            Self::ExternalIdpCreated => "external_idp.created",
            Self::ExternalIdpUpdated => "external_idp.updated",
            Self::ExternalIdpDeleted => "external_idp.deleted",
            Self::StepUpSucceeded => "step_up.succeeded",
            Self::StepUpFailed => "step_up.failed",
            Self::PasswordChanged => "password.changed",
            Self::TenantCreated => "tenant.created",
            Self::TenantUpdated => "tenant.updated",
            Self::TenantDeleted => "tenant.deleted",
            Self::TenantDomainAdded => "tenant.domain_added",
            Self::TenantDomainRemoved => "tenant.domain_removed",
            Self::SystemSettingsUpdated => "system_settings.updated",
            Self::ServiceRestartRequested => "service.restart_requested",
            Self::PasswordResetRequested => "password_reset.requested",
            Self::PasswordResetCompleted => "password_reset.completed",
            Self::EmailVerificationRequested => "email_verification.requested",
            Self::EmailVerified => "email_verification.verified",
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
    /// イベントが属するテナント（テナント単位の追跡。ADR-0009 §8）。テナント文脈の無い
    /// イベント（起動時処理等）のみ `None`。
    pub tenant_id: Option<TenantId>,
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
    pub tenant_id: Option<Uuid>,
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
    /// 監査ログを参照するテナント（テナント越しの閲覧を防ぐため、参照系は常に設定する）。
    pub tenant_id: Option<Uuid>,
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
