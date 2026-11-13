//! Audit events (design spec §7). Output to both structured logs and the `audit_log` table.
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Audit event types (design spec §7). `sso_session.terminated` is reserved for future Logout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    LoginSucceeded,
    LoginFailed,
    LoginLocked,
    /// Sign-in refusal by an authentication policy (user authentication & authentication policy spec §21). The matching
    /// policy code is recorded in `reason` (credentials are not recorded).
    LoginPolicyDenied,
    /// Creation, update and deletion of authentication policies by an admin (same spec §21). The policy code is recorded in `reason`.
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
    /// SAML SSO: issuance of a signed SAML Response (assertion) (success) / refusal of an AuthnRequest (failure:
    /// unregistered SP, ACS mismatch, etc. The reason is recorded).
    SamlResponseIssued,
    /// Granting / revoking user permissions by an admin (ADR-0006, design spec §7).
    UserPermissionGranted,
    UserPermissionRevoked,
    /// Granting / revoking admin permissions to system clients by an admin (ADR-0037).
    /// The `client_id` column is the **target** client; the actor appears in the `user_id` column (person) or
    /// `actor_client=` in `reason` (machine).
    ClientPermissionGranted,
    ClientPermissionRevoked,
    /// Registration, update and deletion of protected resources (the audience placed in `aud`) by an admin (ADR-0042).
    /// `resource=<uri>` is recorded in `reason`.
    ResourceRegistered,
    ResourceUpdated,
    ResourceDeleted,
    /// Registration, update and deletion of apps (`applications`) by an admin (ADR-0054). `application=<id>` is recorded in
    /// `reason`. The display name can change, so it is kept by id.
    ApplicationRegistered,
    ApplicationUpdated,
    ApplicationDeleted,
    /// Adding / removing app <-> authentication method (binding) by an admin (ADR-0054).
    ApplicationBindingAdded,
    ApplicationBindingRemoved,
    /// Moving an identity by an admin (moved from another app. ADR-0067). Kept as 1 row rather than 2 rows of remove + add:
    /// with 2 rows, "left removed" and "moved" cannot be told apart in the audit log. `reason` is
    /// `application=<moved to> … kind=<kind> target=<counterpart> from_application=<moved from>`.
    ApplicationBindingMoved,
    /// Assigning / unassigning principals (people, service accounts) by an admin (ADR-0054 / ADR-0059).
    /// The `user_id` column (person) or `client_id` column (service account) is the **target** principal;
    /// the actor appears in `actor=` of `reason`.
    ApplicationAssigned,
    ApplicationUnassigned,
    /// A user without an assignment came to an app (ADR-0054 decision). If `result` is
    /// [`AuditResult::Failure`] they were actually refused; if [`AuditResult::Success`] they were
    /// **let through during the record-only period** (= a migration gap). Both are emitted as one type
    /// so that before and after the switch can be counted with the same query.
    ApplicationAccessDenied,
    /// Registration, update and secret reissue of clients (RPs) by an admin (design spec §9.3, §7).
    ClientRegistered,
    ClientUpdated,
    ClientSecretRotated,
    /// Logical deletion of a client by an admin (ADR-0035). The entity is kept, so even after deletion
    /// "which app it was" can be traced from `client_id`.
    ClientDeleted,
    /// Refresh Token issuance, use (rotation success) and reuse detection (design spec §9.1).
    /// `RefreshTokenRevoked` is when the user themselves drops issued tokens all at once from the security screen
    /// (ADR-0047). The `client_id` column is empty (the target is not a single one).
    RefreshTokenIssued,
    RefreshTokenUsed,
    RefreshTokenReuseDetected,
    RefreshTokenRevoked,
    /// A DPoP-bound refresh token came with a proof from a different key (ADR-0075 decision 7).
    /// A sign that a stolen token was about to be used on another device. Nothing is revoked.
    RefreshTokenKeyMismatch,
    /// Granting and revoking consent (F3: Consent). `ConsentRevoked` is unlinking by the user themselves (G10).
    ConsentGranted,
    ConsentDenied,
    ConsentRevoked,
    /// Creating, accepting guest invitations and removing memberships (ADR-0009 §3). Invitation tokens are not recorded.
    TenantInvitationCreated,
    TenantInvitationAccepted,
    TenantMembershipRevoked,
    /// Suspending and resuming guest memberships (MT24). Unlike removal (deletion), the membership row and
    /// permission rows scoped to that tenant remain.
    TenantMembershipSuspended,
    TenantMembershipResumed,
    /// Writing / clearing admin notes on accounts (people, service accounts) (ADR-0063 / ADR-0065).
    /// Note contents are not recorded (free-form history may contain PII). `reason` holds the kind and the counterpart.
    AccountNoteUpdated,
    /// Creation of a user by an admin (ADR-0009 §5). Auto-generated passwords are not recorded.
    UserCreated,
    /// Status change (enable / disable), deletion and password reissue of a user by an admin (ADR-0009 §5).
    /// Auto-generated passwords are not recorded.
    UserStatusChanged,
    UserDeleted,
    UserPasswordReset,
    /// Update of a user profile (email, display name, sign-in identifier) by an admin (MT25).
    /// Only the names of changed fields are recorded, not the values themselves (PII).
    UserProfileUpdated,
    /// Adding, enabling/disabling and deleting sign-in identifiers (AP8. Spec §4) by an admin.
    /// Only the **kind** is recorded in `reason` (phone numbers and email addresses are PII, so values are not recorded).
    UserLoginIdentifierAdded,
    UserLoginIdentifierUpdated,
    UserLoginIdentifierRemoved,
    /// Changing the primary email address by an admin (ADR-0052). It is an operation that moves `users.email` = the notification destination,
    /// so it is a separate type from adding/switching identifiers. `reason` records only **where it was promoted
    /// from** (the address is PII, so the value is not recorded).
    UserPrimaryEmailChanged,
    /// Status changes of authenticators (AP9. Spec §5), issuance and use of recovery codes, and sending email OTP.
    /// `reason` records kind, count and remaining (codes and secrets themselves are not recorded).
    AuthenticatorStatusChanged,
    RecoveryCodesIssued,
    RecoveryCodeUsed,
    EmailOtpSent,
    /// Sending SMS OTP and phone number registration confirmation codes (AP13). `reason` records only the purpose
    /// (neither phone number nor code is recorded).
    SmsOtpSent,
    /// Removal of MFA (TOTP, Passkey) by an admin (MT21). A recovery means when the user lost their device.
    /// Only the kinds and counts of removed factors are recorded, not secrets or credentials.
    UserMfaReset,
    /// Immediate unlock of an account lock by an admin (AP6. Spec §17.1, §24.6). `reason` records
    /// whether it was locked before the unlock and the failure count that was cleared.
    UserAccountUnlocked,
    /// Success/failure of external IdP sign-in (AP10. Spec §13). `reason` records the provider code and the failure
    /// reason (external IdP tokens and claims are not recorded).
    ExternalLoginSucceeded,
    ExternalLoginFailed,
    /// Creation, update and deletion of external IdP settings (AP10). The provider code is recorded in `reason`.
    ExternalIdpCreated,
    ExternalIdpUpdated,
    ExternalIdpDeleted,
    /// Success/failure of step-up authentication (AP5. Spec §15). The target operation is recorded in `reason` (credentials are not recorded).
    StepUpSucceeded,
    StepUpFailed,
    /// Password change (including the forced change on first sign-in. ADR-0009 §5). The password itself is not recorded.
    PasswordChanged,
    /// Creation, update and deletion of tenants (ADR-0009 §5). Auto-generated passwords are not recorded.
    TenantCreated,
    TenantUpdated,
    TenantDeleted,
    /// Domain assignment to a tenant (ADR-0029). An operation that decides which tenant sign-ins go to.
    TenantDomainAdded,
    TenantDomainRemoved,
    /// Update of system settings by root (idp.system.admin) (SMTP etc. MT14). Values themselves are not recorded.
    SystemSettingsUpdated,
    /// Overriding / clearing tenant setting values by a tenant admin (ADR-0058). Values themselves are not recorded;
    /// `reason` keeps only the key and whether it was set or cleared (same as `SystemSettingsUpdated`).
    TenantSettingsUpdated,
    /// An api restart request by root (idp.system.admin) (ADR-0017). It is the means of applying runtime settings and
    /// aborts all in-flight requests, so it is always audited.
    ServiceRestartRequested,
    /// Requesting / completing a password reset (MT18). Tokens and email addresses are not recorded.
    PasswordResetRequested,
    PasswordResetCompleted,
    /// Requesting / completing email verification for self-registered accounts (SEC6b). Tokens and email addresses are not recorded.
    EmailVerificationRequested,
    EmailVerified,
    /// Credentials were set via an account setup link issued by an admin (ADR-0062).
    /// `reason` keeps how they were set (`method=passkey` / `method=password`). Tokens are not recorded.
    AccountSetupCompleted,
    /// Signed in on an unregistered device (task #872. ADR-0071). `reason` keeps "whether it is a first-time device".
    /// Device marks and session ids are not recorded.
    UnregisteredDeviceSignIn,
    /// In an organization restricted to registered devices (task #916. ADR-0079), authenticated correctly on an unregistered device. Sign-in
    /// was not completed and was redirected to device registration. `reason` keeps the method and "whether there was a device mark".
    UnregisteredDeviceRefused,
    /// A user registered or revoked a device (task #872). `reason` keeps the device id (not the name).
    DeviceRegistered,
    DeviceRevoked,
    /// A device registration expired after going unused past its expiry (task #872).
    DeviceExpired,
    /// A user registered or revoked an SSH public key (task #885). `reason` keeps the key id and fingerprint
    /// (not the name).
    SshKeyRegistered,
    SshKeyRevoked,
    /// Bound an SSO session to a device key (DBSC. task #887, ADR-0074). `reason` keeps the method and the key fingerprint.
    SessionKeyBound,
    /// A binding registration/refresh signature was not accepted (reason in `reason`). When the session was ended by a signature
    /// from a different key, `reason` is `key_mismatch`.
    SessionKeyRejected,
    /// Registered or revoked an authenticator app key (task #892, ADR-0077). `reason` holds the key id and where it lives.
    ApproverKeyRegistered,
    ApproverKeyRevoked,
    /// Key Attestation was not accepted at key registration intake (reason in `reason`).
    ApproverKeyRejected,
    /// A "Continue in app" request was approved or refused in the authenticator app.
    AppApprovalApproved,
    AppApprovalDenied,
    /// An approved code was used from a browser different from the one that started the request (suspected approval of another device's request).
    AppApprovalRefused,
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
            Self::ClientPermissionGranted => "client_permission.granted",
            Self::ClientPermissionRevoked => "client_permission.revoked",
            Self::ResourceRegistered => "resource.registered",
            Self::ResourceUpdated => "resource.updated",
            Self::ResourceDeleted => "resource.deleted",
            Self::ApplicationRegistered => "application.registered",
            Self::ApplicationUpdated => "application.updated",
            Self::ApplicationDeleted => "application.deleted",
            Self::ApplicationBindingAdded => "application_binding.added",
            Self::ApplicationBindingRemoved => "application_binding.removed",
            Self::ApplicationBindingMoved => "application_binding.moved",
            Self::ApplicationAssigned => "application.assigned",
            Self::ApplicationUnassigned => "application.unassigned",
            Self::ApplicationAccessDenied => "application.access_denied",
            Self::ClientRegistered => "client.registered",
            Self::ClientUpdated => "client.updated",
            Self::ClientSecretRotated => "client.secret_rotated",
            Self::ClientDeleted => "client.deleted",
            Self::RefreshTokenIssued => "refresh_token.issued",
            Self::RefreshTokenUsed => "refresh_token.used",
            Self::RefreshTokenReuseDetected => "refresh_token.reuse_detected",
            Self::RefreshTokenRevoked => "refresh_token.revoked",
            Self::RefreshTokenKeyMismatch => "refresh_token.dpop_key_mismatch",
            Self::ConsentGranted => "consent.granted",
            Self::ConsentDenied => "consent.denied",
            Self::ConsentRevoked => "consent.revoked",
            Self::TenantInvitationCreated => "tenant_invitation.created",
            Self::TenantInvitationAccepted => "tenant_invitation.accepted",
            Self::TenantMembershipRevoked => "tenant_membership.revoked",
            Self::TenantMembershipSuspended => "tenant_membership.suspended",
            Self::TenantMembershipResumed => "tenant_membership.resumed",
            Self::AccountNoteUpdated => "account.note_updated",
            Self::UserCreated => "user.created",
            Self::UserStatusChanged => "user.status_changed",
            Self::UserDeleted => "user.deleted",
            Self::UserPasswordReset => "user.password_reset",
            Self::UserProfileUpdated => "user.profile_updated",
            Self::UserLoginIdentifierAdded => "user.login_identifier_added",
            Self::UserLoginIdentifierUpdated => "user.login_identifier_updated",
            Self::UserLoginIdentifierRemoved => "user.login_identifier_removed",
            Self::UserPrimaryEmailChanged => "user.primary_email_changed",
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
            Self::TenantSettingsUpdated => "tenant_settings.updated",
            Self::ServiceRestartRequested => "service.restart_requested",
            Self::PasswordResetRequested => "password_reset.requested",
            Self::PasswordResetCompleted => "password_reset.completed",
            Self::EmailVerificationRequested => "email_verification.requested",
            Self::EmailVerified => "email_verification.verified",
            Self::AccountSetupCompleted => "account_setup.completed",
            Self::UnregisteredDeviceSignIn => "login.unregistered_device",
            Self::UnregisteredDeviceRefused => "login.unregistered_device_refused",
            Self::DeviceRegistered => "device.registered",
            Self::DeviceRevoked => "device.revoked",
            Self::DeviceExpired => "device.expired",
            Self::SshKeyRegistered => "ssh_key.registered",
            Self::SshKeyRevoked => "ssh_key.revoked",
            Self::SessionKeyBound => "sso_session.key_bound",
            Self::SessionKeyRejected => "sso_session.key_rejected",
            Self::ApproverKeyRegistered => "approver_key.registered",
            Self::ApproverKeyRevoked => "approver_key.revoked",
            Self::ApproverKeyRejected => "approver_key.rejected",
            Self::AppApprovalApproved => "app_approval.approved",
            Self::AppApprovalDenied => "app_approval.denied",
            Self::AppApprovalRefused => "app_approval.refused",
        }
    }
}

/// Success/failure of an audit event.
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

/// One audit event. No PII (users are identified only by the hashed `user_id`).
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub occurred_at: DateTime<Utc>,
    /// The tenant the event belongs to (per-tenant tracking. ADR-0009 §8). `None` only for events with no
    /// tenant context (startup processing, etc.).
    pub tenant_id: Option<TenantId>,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub result: AuditResult,
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// One row read from `audit_log` (the read model of the status screen A3).
///
/// `event_type` / `result` keep the stored string as is (not restricted to the enum, so that types retired in the past are still shown
/// without gaps).
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

/// Audit log search conditions (A3. Mainly for narrowing down errors, filtering by `event_type` / `result` / period / `client_id` /
/// `correlation_id`). Only the specified items are applied, combined with AND.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    /// The tenant whose audit log is viewed (always set on reads to prevent viewing across tenants).
    pub tenant_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub result: Option<String>,
    pub client_id: Option<String>,
    pub correlation_id: Option<String>,
    /// Lower and upper bounds of the period (`occurred_at`, inclusive).
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Paging (newest first).
    pub limit: i64,
    pub offset: i64,
}
