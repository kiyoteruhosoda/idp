//! axum の共有状態。各サービスを `Arc` で保持し、`FromRef` でハンドラへ部分注入する。
//!
//! [`AppState::build`] がユースケースの組み立て（依存注入）を一手に担う。
//! バイナリ（`lib.rs::run`）と統合テストの双方から同じ組み立てを使う。
//!
//! テナントは `/{tenant_id}/...` ルートでは `TenantResolver` middleware が、`/internal/*` では
//! web が DTO で送る `tenant_id`（`require_internal_tenant`。未指定・不正は 400）が解決する。
//! かつての「起動時に解決した root を既定テナントとして全リクエストへ適用する」過渡運用
//! （`default_tenant`）は SEC4 で撤去した。

use crate::application::account_language::AccountLanguageService;
use crate::application::account_password::AccountPasswordService;
use crate::application::account_profile::AccountProfileService;
use crate::application::account_security::AccountSecurityService;
use crate::application::account_tenants::AccountTenantsService;
use crate::application::admin_access::AdminAccessService;
use crate::application::admin_login::AdminLoginService;
use crate::application::application_log::ApplicationLogService;
use crate::application::audit::AuditService;
use crate::application::audit_query::AuditQueryService;
use crate::application::authentication_policy_management::AuthenticationPolicyManagementService;
use crate::application::authenticator_management::AuthenticatorManagementService;
use crate::application::authorize::AuthorizeService;
use crate::application::backchannel_logout::{
    BackchannelLogoutDeliveryService, KeyServiceLogoutTokenSigner,
};
use crate::application::change_password::ChangePasswordService;
use crate::application::client_management::ClientManagementService;
use crate::application::client_status::ClientStatusService;
use crate::application::code_issuance::CodeIssuanceService;
use crate::application::consent::ConsentService;
use crate::application::cors_policy::ApiCorsPolicy;
use crate::application::email_verification::EmailVerificationService;
use crate::application::expired_record_purge::ExpiredRecordPurgeService;
use crate::application::external_idp_management::ExternalIdpManagementService;
use crate::application::external_login::ExternalLoginService;
use crate::application::introspection::IntrospectionService;
use crate::application::invitation::InvitationService;
use crate::application::key_service::KeyService;
use crate::application::login::LoginService;
use crate::application::logout::LogoutService;
use crate::application::member_directory::MemberDirectoryService;
use crate::application::mfa_login::MfaLoginService;
use crate::application::passkey_authentication::PasskeyAuthenticationService;
use crate::application::passkey_registration::PasskeyRegistrationService;
use crate::application::password_reset::PasswordResetService;
use crate::application::permission_management::PermissionManagementService;
use crate::application::portal_login::PortalLoginService;
use crate::application::register::RegisterService;
use crate::application::revocation::RevocationService;
use crate::application::saml_service_provider_management::SamlServiceProviderManagementService;
use crate::application::saml_sso::SamlSsoService;
use crate::application::service_restart::ServiceRestartService;
use crate::application::sso_restore::SsoRestorer;
use crate::application::step_up::StepUpService;
use crate::application::system_settings::SystemSettingsService;
use crate::application::tenant_management::TenantManagementService;
use crate::application::tenant_resolution::TenantResolutionService;
use crate::application::token::TokenService;
use crate::application::totp_registration::TotpRegistrationService;
use crate::application::user_lifecycle::UserLifecycleService;
use crate::application::user_management::UserManagementService;
use crate::application::userinfo::UserInfoService;
use crate::config::Config;
use crate::domain::cache::Cache;
use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::UserPermissionRepository;
use crate::domain::tenant::{Tenant, TenantId};
use crate::infrastructure::backchannel_logout::ReqwestBackchannelLogoutSender;
use crate::infrastructure::cache::InMemoryTtlCache;
use crate::infrastructure::db::Db;
use crate::infrastructure::external_oidc::ReqwestExternalOidcClient;
use crate::infrastructure::id_generator::UuidV7Generator;
use crate::infrastructure::mailer::LettreSmtpMailer;
use crate::infrastructure::password::Argon2PasswordHasher;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::infrastructure::repositories::application_log::{
    SqlxApplicationLogQuery, SqlxApplicationLogSink,
};
use crate::infrastructure::repositories::audit_log::{SqlxAuditLogQuery, SqlxAuditLogSink};
use crate::infrastructure::repositories::auth_session::SqlxAuthSessionRepository;
use crate::infrastructure::repositories::authentication_policy::SqlxAuthenticationPolicyRepository;
use crate::infrastructure::repositories::authorization_code::SqlxAuthorizationCodeRepository;
use crate::infrastructure::repositories::backchannel_logout::SqlxBackchannelLogoutDeliveryRepository;
use crate::infrastructure::repositories::cached_user_permission::{
    CachedUserPermissionRepository, PermissionKey,
};
use crate::infrastructure::repositories::client::SqlxClientRepository;
use crate::infrastructure::repositories::consent::SqlxClientConsentRepository;
use crate::infrastructure::repositories::email_verification_token::SqlxEmailVerificationTokenRepository;
use crate::infrastructure::repositories::external_idp::{
    SqlxExternalIdentityProviderRepository, SqlxExternalIdentityRepository,
    SqlxExternalLoginRequestRepository,
};
use crate::infrastructure::repositories::passkey_challenge::SqlxPasskeyChallengeRepository;
use crate::infrastructure::repositories::password_reset_token::SqlxPasswordResetTokenRepository;
use crate::infrastructure::repositories::refresh_token::SqlxRefreshTokenRepository;
use crate::infrastructure::repositories::revoked_access_token::SqlxRevokedAccessTokenRepository;
use crate::infrastructure::repositories::saml_service_provider::SqlxSamlServiceProviderRepository;
use crate::infrastructure::repositories::saml_sso_request::SqlxSamlSsoRequestRepository;
use crate::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use crate::infrastructure::repositories::sso_session::SqlxSsoSessionRepository;
use crate::infrastructure::repositories::system_setting::SqlxSystemSettingsRepository;
use crate::infrastructure::repositories::tenant::SqlxTenantRepository;
use crate::infrastructure::repositories::tenant_member_query::SqlxTenantMemberQuery;
use crate::infrastructure::repositories::tenant_membership::SqlxTenantMembershipRepository;
use crate::infrastructure::repositories::tenant_provisioning::SqlxTenantProvisioningRepository;
use crate::infrastructure::repositories::totp_secret::SqlxTotpSecretRepository;
use crate::infrastructure::repositories::user::SqlxUserRepository;
use crate::infrastructure::repositories::user_authenticator::SqlxUserAuthenticatorRepository;
use crate::infrastructure::repositories::user_permission::SqlxUserPermissionRepository;
use crate::infrastructure::repositories::webauthn_credential::SqlxWebAuthnCredentialRepository;
use crate::infrastructure::webauthn::WebAuthnService;
use crate::service_restart::ServiceRestart;
use axum::extract::FromRef;
use std::sync::Arc;

/// IP 単位のログインレート制限: 5 分間で最大 30 試行（設計仕様 §4.3「IP単位でもレート制限」）。
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 30;
const LOGIN_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

/// IP 単位の自己登録レート制限: 5 分間で最大 10 試行（SEC6。列挙・大量作成の抑止）。
const REGISTER_RATE_LIMIT_MAX_ATTEMPTS: usize = 10;
const REGISTER_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

/// IP 単位のパスワードリセット要求レート制限: 15 分間で最大 5 試行（MT18。メール爆撃・列挙の抑止）。
const PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS: usize = 5;
const PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES: i64 = 15;

#[derive(Clone)]
pub struct AppState {
    pub pool: Db,
    pub config: Arc<Config>,
    /// テナント解決（id → tenant）。`TenantResolver` middleware が使う（MT9 でルーターへ mount）。
    pub tenant_resolution: Arc<TenantResolutionService>,
    pub register: Arc<RegisterService>,
    /// 自己登録アカウントのメール検証（確認リンク送出・消費。SEC6b）。
    pub email_verification: Arc<EmailVerificationService>,
    pub authorize: Arc<AuthorizeService>,
    pub login: Arc<LoginService>,
    /// 強制パスワード変更（ADR-0009 §5）。`LoginService` の `must_change_password` 検出を受けて
    /// `auth_session_id` ベースでパスワードを設定する。
    pub change_password: Arc<ChangePasswordService>,
    pub consent: Arc<ConsentService>,
    pub token: Arc<TokenService>,
    pub userinfo: Arc<UserInfoService>,
    pub keys: Arc<KeyService>,
    pub admin_access: Arc<AdminAccessService>,
    pub admin_login: Arc<AdminLoginService>,
    /// エンドユーザー・ポータルの直接ログイン（クライアント非依存。TOTP を尊重して SSO を直接発行する）。
    pub portal_login: Arc<PortalLoginService>,
    pub clients_admin: Arc<ClientManagementService>,
    pub clients_status: Arc<ClientStatusService>,
    pub permissions_admin: Arc<PermissionManagementService>,
    /// 認証ポリシーの管理（CRUD。ユーザー認証・認証ポリシー仕様書 §7）。評価はログイン系サービスが行う。
    pub authentication_policies_admin: Arc<AuthenticationPolicyManagementService>,
    /// 管理者による利用者作成（自動生成パスワード・must_change_password。ADR-0009 §5）。
    pub users_admin: Arc<UserManagementService>,
    /// 管理者による利用者ライフサイクル操作（無効化・削除・パスワード再発行。ADR-0009 §5）。
    pub users_lifecycle: Arc<UserLifecycleService>,
    /// テナント作成・管理（idp.system.admin 必須。ADR-0009 §5・§6）。設定画面のテナント設定区画
    /// （自テナント参照・表示名更新。MT14）も本サービスを通す。
    pub tenants_admin: Arc<TenantManagementService>,
    /// システム設定（SMTP 等。root/idp.system.admin のみ。MT14）。
    pub system_settings: Arc<SystemSettingsService>,
    /// セルフサービスのパスワード変更（ログイン済みユーザーの設定画面。MT15）。
    pub account_password: Arc<AccountPasswordService>,
    /// セルフサービスの表示言語変更（ログイン済みユーザーの設定画面。MT20）。
    pub account_language: Arc<AccountLanguageService>,
    /// セルフサービスの表示名（プロフィール）取得・更新（ログイン済みユーザーの設定画面）。
    pub account_profile: Arc<AccountProfileService>,
    /// ログイン中ユーザーの所属テナント列挙（テナント切り替え UI）。
    pub account_tenants: Arc<AccountTenantsService>,
    /// セルフサービス・パスワードリセット（忘失時。メールリンク経由。MT18）。
    pub password_reset: Arc<PasswordResetService>,
    /// ゲスト招待・メンバーシップ（ADR-0009 §3）。
    pub invitations: Arc<InvitationService>,
    pub member_directory: Arc<MemberDirectoryService>,
    pub audit_query: Arc<AuditQueryService>,
    /// エラー・警告ログ（`log` テーブル）の取り込み・参照・掃除（CLAUDE.md「ログ」）。
    /// api 自身の `tracing` 取り込みタスク・web からの `/internal/logs`・管理画面の参照が共有する。
    pub application_logs: Arc<ApplicationLogService>,
    pub logout: Arc<LogoutService>,
    /// セルフサービスのセキュリティ画面（セッション一覧・失効／連携アプリ解除。G10）。
    pub account_security: Arc<AccountSecurityService>,
    /// Step-up 認証（重要操作の直前の本人確認。AP5）。
    pub step_up: Arc<StepUpService>,
    /// 認証器の統合管理（一覧・状態変更・リカバリーコード・email OTP。AP9）。
    pub authenticators: Arc<AuthenticatorManagementService>,
    /// 認証器の登録簿（AP9）。
    pub authenticator_repository: Arc<dyn crate::domain::repositories::UserAuthenticatorRepository>,
    /// 外部 IdP ログイン（AP10）。
    pub external_login: Arc<ExternalLoginService>,
    /// 外部 IdP 設定の管理（AP10）。
    pub external_idps: Arc<ExternalIdpManagementService>,
    /// 外部 IdP 設定の参照（ログイン画面のボタン用）。GC・一覧が直接使う。
    pub external_providers:
        Arc<dyn crate::domain::repositories::ExternalIdentityProviderRepository>,
    /// 外部 IdP ログインの進行状態（AP10）。
    pub external_login_requests:
        Arc<dyn crate::domain::repositories::ExternalLoginRequestRepository>,
    /// 期限切れレコードの一括 GC（G2）。対象表の一覧は
    /// [`crate::infrastructure::repositories::expired_records`] にある。
    pub expired_records: Arc<ExpiredRecordPurgeService>,
    /// CORS の許可オリジン判定（G1）。ミドルウェアが使う。
    pub cors_policy: Arc<ApiCorsPolicy>,
    /// Back-channel logout の送信キュー（G5）。ハンドラは積むだけ、送信はワーカーが行う。
    pub backchannel_logout: Arc<BackchannelLogoutDeliveryService>,
    pub revocation: Arc<RevocationService>,
    pub introspection: Arc<IntrospectionService>,
    pub totp_registration: Arc<TotpRegistrationService>,
    pub mfa_login: Arc<MfaLoginService>,
    pub passkey_registration: Arc<PasskeyRegistrationService>,
    pub passkey_authentication: Arc<PasskeyAuthenticationService>,
    /// SAML SP（クライアント）登録（テナント管理者向け）。
    pub saml_service_providers: Arc<SamlServiceProviderManagementService>,
    /// SAML SP-initiated SSO（`/saml/sso` の受信と `/internal/saml/resume` の応答発行）。
    pub saml_sso: Arc<SamlSsoService>,
    /// 設定画面からの再起動要求（ADR-0017）。`run()` の graceful shutdown がこの値を待つ。
    /// テストでは `build` が作った値を誰も待たないため、要求しても何も起きない。
    pub restart: ServiceRestart,
    /// 再起動ユースケース（監査記録 → 停止要求。ADR-0017）。`restart` と同じ signal を指す。
    pub service_restart: Arc<ServiceRestartService>,
}

/// Back-channel logout ワーカーが 1 回の起動で扱う通知の最大件数。
///
/// 大きくすると復旧時の追いつきは速いが、落ちている RP が多いと 1 回の走行が長引く（各件で
/// タイムアウトを待つため）。ポーリング間隔（`BACKCHANNEL_LOGOUT_POLL_INTERVAL_SECS`）に対して
/// 走行が伸びすぎない程度に抑える。
const BACKCHANNEL_LOGOUT_BATCH_SIZE: u32 = 50;

impl AppState {
    /// すべてのユースケースを組み立てる（トレイト越しのコンストラクタ注入）。
    pub fn build(pool: Db, config: Arc<Config>, clock: Arc<dyn Clock>) -> Self {
        let users = Arc::new(SqlxUserRepository::new(pool.clone()));
        let tenant_memberships = Arc::new(SqlxTenantMembershipRepository::new(pool.clone()));
        let clients = Arc::new(SqlxClientRepository::new(pool.clone()));
        let auth_sessions = Arc::new(SqlxAuthSessionRepository::new(pool.clone()));
        let sso_sessions = Arc::new(SqlxSsoSessionRepository::new(pool.clone()));
        let codes = Arc::new(SqlxAuthorizationCodeRepository::new(pool.clone()));
        let refresh_tokens = Arc::new(SqlxRefreshTokenRepository::new(pool.clone()));
        let revoked_access_tokens = Arc::new(SqlxRevokedAccessTokenRepository::new(pool.clone()));
        let signing_keys = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
        let saml_service_provider_repo =
            Arc::new(SqlxSamlServiceProviderRepository::new(pool.clone()));
        let tenants = Arc::new(SqlxTenantRepository::new(pool.clone()));
        // scope→権限解決（ADR-0009 §7）: `has_permission` の判定結果を TTL キャッシュし、付与・剥奪時に
        // invalidate する。判定（admin_access）と変更（permissions_admin）が同一インスタンスを共有する
        // ため、付与直後の反映漏れ（stale allow/deny）を避けられる。
        let permission_cache: Arc<dyn Cache<PermissionKey, bool>> =
            Arc::new(InMemoryTtlCache::new(
                chrono_from_std(config.permission_cache_ttl()),
                clock.clone(),
            ));
        let user_permissions: Arc<dyn UserPermissionRepository> =
            Arc::new(CachedUserPermissionRepository::new(
                Arc::new(SqlxUserPermissionRepository::new(pool.clone())),
                permission_cache,
            ));
        let client_consents = Arc::new(SqlxClientConsentRepository::new(pool.clone()));
        let totp_secrets = Arc::new(SqlxTotpSecretRepository::new(pool.clone()));
        let authentication_policies =
            Arc::new(SqlxAuthenticationPolicyRepository::new(pool.clone()));
        let webauthn_credentials = Arc::new(SqlxWebAuthnCredentialRepository::new(pool.clone()));
        let passkey_challenges = Arc::new(SqlxPasskeyChallengeRepository::new(pool.clone()));
        let audit_sink = Arc::new(SqlxAuditLogSink::new(pool.clone()));
        let audit_logs = Arc::new(SqlxAuditLogQuery::new(pool.clone()));
        let hasher = Arc::new(Argon2PasswordHasher::new());
        let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7Generator);
        let rate_limiter = Arc::new(InMemoryLoginRateLimiter::new(
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            chrono::Duration::minutes(LOGIN_RATE_LIMIT_WINDOW_MINUTES),
        ));

        let audit = Arc::new(AuditService::new(audit_sink, clock.clone()));
        let saml_service_providers = Arc::new(SamlServiceProviderManagementService::new(
            saml_service_provider_repo,
            ids.clone(),
            clock.clone(),
        ));
        // システム設定（SMTP 等。root のみ。MT14）。秘匿値は key_encryption_key で暗号化して保存する。
        // 開発用既定 secret の使用状況も渡す（ランタイム設定の保存前に「その値で次回起動できるか」を
        // 判定するため。ADR-0017）。
        let system_settings = Arc::new(SystemSettingsService::new(
            Arc::new(SqlxSystemSettingsRepository::new(pool.clone())),
            *config.key_encryption_key(),
            config.deployment_state(),
            audit.clone(),
            clock.clone(),
        ));
        // AP9: 認証器の統合管理。種別ごとの表に散っていた登録状況を 1 つの登録簿へ集約し、
        // リカバリーコード・email OTP を追加する。
        let authenticator_repository: Arc<
            dyn crate::domain::repositories::UserAuthenticatorRepository,
        > = Arc::new(SqlxUserAuthenticatorRepository::new(pool.clone()));
        let authenticators = Arc::new(AuthenticatorManagementService::new(
            authenticator_repository.clone(),
            users.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::new()),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));

        // セルフサービスのパスワード変更（ログイン済みユーザー。MT15）。
        let account_password = Arc::new(AccountPasswordService::new(
            sso_sessions.clone(),
            users.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // セルフサービスの表示言語変更（ログイン済みユーザー。MT20）。
        let account_language = Arc::new(AccountLanguageService::new(
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));
        // セルフサービスの表示名（プロフィール）取得・更新（ログイン済みユーザー）。
        let account_profile = Arc::new(AccountProfileService::new(
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));
        // ログイン中ユーザーの所属テナント列挙（テナント切り替え UI）。
        let account_tenants = Arc::new(AccountTenantsService::new(
            sso_sessions.clone(),
            tenant_memberships.clone(),
            tenants.clone(),
            clock.clone(),
        ));
        // パスワードリセット（忘失時。MT18）。SMTP はシステム設定（MT14）、配送は MT17 の Mailer を
        // 再利用する。要求は IP 単位でレート制限し、成功時は全セッション・トークンを失効させる。
        let password_reset = Arc::new(PasswordResetService::new(
            users.clone(),
            Arc::new(SqlxPasswordResetTokenRepository::new(pool.clone())),
            sso_sessions.clone(),
            refresh_tokens.clone(),
            codes.clone(),
            hasher.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::new()),
            Arc::new(InMemoryLoginRateLimiter::new(
                PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS,
                chrono::Duration::minutes(PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES),
            )),
            audit.clone(),
            clock.clone(),
            config.password_reset_ttl(),
            config.public_web_base_url().to_string(),
        ));
        let keys = Arc::new(KeyService::new(
            signing_keys.clone(),
            clock.clone(),
            *config.key_encryption_key(),
        ));
        let code_issuance = Arc::new(CodeIssuanceService::new(
            codes.clone(),
            audit.clone(),
            clock.clone(),
            config.authorization_code_ttl(),
        ));

        // 自己登録（SEC6）: テナント設定トグル（既定 OFF）＋ IP 単位レート制限。ログインとは別の
        // 制限器を使う（登録の失敗でログイン試行枠を消費させない）。
        let register_rate_limiter = Arc::new(InMemoryLoginRateLimiter::new(
            REGISTER_RATE_LIMIT_MAX_ATTEMPTS,
            chrono::Duration::minutes(REGISTER_RATE_LIMIT_WINDOW_MINUTES),
        ));
        let register = Arc::new(RegisterService::new(
            users.clone(),
            tenant_memberships.clone(),
            tenants.clone(),
            hasher.clone(),
            register_rate_limiter,
            clock.clone(),
            ids.clone(),
        ));
        // メール検証（SEC6b）: 自己登録で確認リンクを送り、消費で email_verified を立てる。SMTP は
        // システム設定（MT14）、配送は MT17 の Mailer を再利用する。
        let email_verification = Arc::new(EmailVerificationService::new(
            users.clone(),
            Arc::new(SqlxEmailVerificationTokenRepository::new(pool.clone())),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::new()),
            audit.clone(),
            clock.clone(),
            config.email_verification_ttl(),
            config.public_web_base_url().to_string(),
        ));
        // SSO 復元の共通判定（OIDC authorize と SAML SSO が共有する）。
        let sso_restorer = Arc::new(SsoRestorer::new(
            sso_sessions.clone(),
            users.clone(),
            tenant_memberships.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
        ));
        let authorize = Arc::new(AuthorizeService::new(
            clients.clone(),
            auth_sessions.clone(),
            sso_restorer.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            clock.clone(),
            config.auth_session_ttl(),
        ));
        // SAML SP-initiated SSO。進行状態の TTL は OIDC の auth_session と同じ値を使う。
        let saml_sso = Arc::new(SamlSsoService::new(
            Arc::new(SqlxSamlServiceProviderRepository::new(pool.clone())),
            Arc::new(SqlxSamlSsoRequestRepository::new(pool.clone())),
            users.clone(),
            sso_restorer.clone(),
            keys.clone(),
            audit.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.auth_session_ttl(),
        ));
        let login = Arc::new(LoginService::new(
            users.clone(),
            auth_sessions.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            totp_secrets.clone(),
            authentication_policies.clone(),
            code_issuance.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.login_lockout(),
            config.auth_policy_default_effect(),
            *config.csrf_secret(),
        ));
        let change_password = Arc::new(ChangePasswordService::new(
            auth_sessions.clone(),
            users.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            totp_secrets.clone(),
            authentication_policies.clone(),
            code_issuance.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.auth_policy_default_effect(),
            *config.csrf_secret(),
        ));
        let consent = Arc::new(ConsentService::new(
            auth_sessions.clone(),
            client_consents.clone(),
            clients.clone(),
            code_issuance.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // 管理コンソールのログイン（ADR-0006 §6）。IP レート制限は通常ログインと同一の制限器を共有する。
        let admin_login = Arc::new(AdminLoginService::new(
            users.clone(),
            sso_sessions.clone(),
            user_permissions.clone(),
            totp_secrets.clone(),
            authentication_policies.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.login_lockout(),
            config.auth_policy_default_effect(),
        ));
        // エンドユーザー・ポータルの直接ログイン。admin_login と同機構（クライアント非依存の SSO 直接発行）
        // だが admin 権限を要求せず、TOTP（MFA）を尊重する。`mfa_ticket` の署名鍵は CSRF 秘密鍵を流用する。
        let portal_login = Arc::new(PortalLoginService::new(
            authenticator_repository.clone(),
            users.clone(),
            sso_sessions.clone(),
            totp_secrets.clone(),
            authentication_policies.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            *config.csrf_secret(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.login_lockout(),
            config.auth_policy_default_effect(),
        ));
        let clients_admin = Arc::new(ClientManagementService::new(
            clients.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // クライアント状況一覧（A3）: 登録クライアント × 監査ログ由来の最終利用時刻。
        let clients_status = Arc::new(ClientStatusService::new(
            clients.clone(),
            audit_logs.clone(),
        ));
        let audit_query = Arc::new(AuditQueryService::new(audit_logs));
        let application_logs = Arc::new(ApplicationLogService::new(
            Arc::new(SqlxApplicationLogSink::new(pool.clone())),
            Arc::new(SqlxApplicationLogQuery::new(pool.clone())),
            clock.clone(),
        ));
        let token = Arc::new(TokenService::new(
            clients.clone(),
            users.clone(),
            codes.clone(),
            refresh_tokens.clone(),
            keys.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.access_token_ttl(),
            config.id_token_ttl(),
            config.refresh_token_ttl(),
        ));
        let userinfo = Arc::new(UserInfoService::new(
            signing_keys.clone(),
            users.clone(),
            revoked_access_tokens.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.clock_skew(),
        ));
        let permissions_admin = Arc::new(PermissionManagementService::new(
            users.clone(),
            tenant_memberships.clone(),
            user_permissions.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // 認証ポリシーの管理（CRUD）。評価用のリポジトリ（login / passkey_authentication）と同一実装を共有する。
        let authentication_policies_admin = Arc::new(AuthenticationPolicyManagementService::new(
            authentication_policies.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // 管理者による利用者作成（ADR-0009 §5）。テナント作成フロー（tenants_admin）が生成する初期
        // 管理者ユーザーもこのサービスを通す（作成ロジックの単一の出所）。
        let users_admin = Arc::new(UserManagementService::new(
            users.clone(),
            tenant_memberships.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // 管理者による利用者ライフサイクル操作（ADR-0009 §5・MT21）。パスワード再発行・無効化・
        // MFA 解除時は当該利用者のセッション・トークンを失効させる。
        let users_lifecycle = Arc::new(UserLifecycleService::new(
            authenticator_repository.clone(),
            users.clone(),
            sso_sessions.clone(),
            refresh_tokens.clone(),
            codes.clone(),
            totp_secrets.clone(),
            webauthn_credentials.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // テナント作成・管理（ADR-0009 §4・§6）。作成者を新テナントのブートストラップ管理者
        // （ACTIVE GUEST + idp.tenant.admin）として登録し、テナント・メンバーシップ・権限付与は
        // 単一トランザクションで永続化する（unit of work。REF2）。付与は判定キャッシュを経由しないが、
        // 新規生成テナント ID のため該当キーがキャッシュに載っていることはない。
        let tenants_admin = Arc::new(TenantManagementService::new(
            tenants.clone(),
            Arc::new(SqlxTenantProvisioningRepository::new(pool.clone())),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // ゲスト招待・メンバーシップ（ADR-0009 §3）。権限は同一キャッシュ付きリポジトリを共有するため、
        // メンバーシップ解除に伴う権限剥奪も判定キャッシュへ即時反映される。招待メール（MT17）は
        // システム設定の SMTP（MT14）で best-effort 送信し、未設定・失敗時はトークンの手動伝達に戻る。
        let invitations = Arc::new(InvitationService::new(
            users.clone(),
            tenant_memberships.clone(),
            user_permissions.clone(),
            // ゲスト停止時、当該テナント分の refresh token を失効させる（MT24）。
            refresh_tokens.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::new()),
            audit.clone(),
            clock.clone(),
            config.invitation_ttl(),
            config.public_web_base_url().to_string(),
        ));
        // メンバー一覧の参照（MT22）。絞り込み・ページングを DB 側で行う読み取り専用の経路で、
        // メンバーシップの変更（InvitationService）とは関心を分ける。
        let member_directory = Arc::new(MemberDirectoryService::new(Arc::new(
            SqlxTenantMemberQuery::new(pool.clone()),
        )));
        let admin_access = Arc::new(AdminAccessService::new(
            sso_sessions.clone(),
            users.clone(),
            user_permissions,
            tenant_memberships.clone(),
            clock.clone(),
        ));

        // テナント解決（ADR-0009 §7）: id → tenant のホットパスを TTL キャッシュ + 更新時 invalidation で
        // 抑える。MT9 で `TenantResolver` middleware がこのサービスをルーターへ mount する。
        let tenant_cache: Arc<dyn Cache<TenantId, Tenant>> = Arc::new(InMemoryTtlCache::new(
            chrono_from_std(config.tenant_cache_ttl()),
            clock.clone(),
        ));
        let tenant_resolution = Arc::new(TenantResolutionService::new(tenants, tenant_cache));

        // F4: Logout（RP-initiated / front-channel / back-channel）。
        let logout = Arc::new(LogoutService::new(
            sso_sessions.clone(),
            users.clone(),
            clients.clone(),
            codes,
            audit.clone(),
            clock.clone(),
            config.issuer().to_string(),
        ));

        // AP10: 外部 IdP ログイン。外部 IdP は「本 IdP がクライアントとして振る舞う」唯一の経路で、
        // ID Token の検証（署名・iss・aud・exp・nonce）は `ExternalOidcClient` の実装に閉じている。
        let external_providers: Arc<
            dyn crate::domain::repositories::ExternalIdentityProviderRepository,
        > = Arc::new(SqlxExternalIdentityProviderRepository::new(pool.clone()));
        let external_login_requests: Arc<
            dyn crate::domain::repositories::ExternalLoginRequestRepository,
        > = Arc::new(SqlxExternalLoginRequestRepository::new(pool.clone()));
        let external_login = Arc::new(ExternalLoginService::new(
            external_providers.clone(),
            Arc::new(SqlxExternalIdentityRepository::new(pool.clone())),
            external_login_requests.clone(),
            users.clone(),
            sso_sessions.clone(),
            auth_sessions.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            authentication_policies.clone(),
            Arc::new(ReqwestExternalOidcClient::new()),
            audit.clone(),
            clock.clone(),
            ids.clone(),
            *config.key_encryption_key(),
            config.public_web_base_url().to_string(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.auth_policy_default_effect(),
        ));
        let external_idps = Arc::new(ExternalIdpManagementService::new(
            external_providers.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
            *config.key_encryption_key(),
        ));

        // AP5: Step-up 認証。IP レート制限はログインと同一の制限器を共有する（別枠にすると、
        // ログインで締め出された攻撃者が step-up 経由で試行を続けられる）。
        let step_up = Arc::new(StepUpService::new(
            sso_sessions.clone(),
            users.clone(),
            totp_secrets.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            config.step_up_max_age_secs(),
        ));

        // G10: セルフサービスのセキュリティ画面。
        let account_security = Arc::new(AccountSecurityService::new(
            sso_sessions.clone(),
            users.clone(),
            client_consents.clone(),
            clients.clone(),
            refresh_tokens.clone(),
            audit.clone(),
            clock.clone(),
        ));

        // G5: Back-channel logout の送信キュー。ログアウトのハンドラは通知要求を積むだけで終え、
        // 実際の HTTP 送信は `idp_api::run` が起動するワーカーが再試行付きで行う。
        let backchannel_logout = Arc::new(BackchannelLogoutDeliveryService::new(
            Arc::new(SqlxBackchannelLogoutDeliveryRepository::new(pool.clone())),
            Arc::new(KeyServiceLogoutTokenSigner::new(keys.clone())),
            Arc::new(ReqwestBackchannelLogoutSender::new()),
            ids.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.backchannel_logout_max_attempts() as i32,
            BACKCHANNEL_LOGOUT_BATCH_SIZE,
        ));

        // F5: Token 管理（revocation / introspection）。
        let revocation = Arc::new(RevocationService::new(
            clients.clone(),
            refresh_tokens.clone(),
            revoked_access_tokens.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
        ));
        let introspection = Arc::new(IntrospectionService::new(
            clients.clone(),
            signing_keys.clone(),
            refresh_tokens,
            revoked_access_tokens,
            users.clone(),
            hasher,
            clock.clone(),
            config.issuer().to_string(),
            config.clock_skew(),
        ));

        let totp_registration = Arc::new(TotpRegistrationService::new(
            authenticators.clone(),
            totp_secrets.clone(),
            sso_sessions.clone(),
            *config.key_encryption_key(),
            config.issuer().to_string(),
            clock.clone(),
        ));
        let mfa_login = Arc::new(MfaLoginService::new(
            authenticator_repository.clone(),
            auth_sessions.clone(),
            totp_secrets,
            users.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            // パスワード認証と同じ limiter インスタンス・同じロックポリシーを共有する（SEC3）。
            // 別枠にすると「パスワードで上限まで、TOTP でさらに上限まで」と試行できてしまう。
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.login_lockout(),
            *config.csrf_secret(),
            authentication_policies.clone(),
            config.auth_policy_default_effect(),
        ));

        // WebAuthn の RP ID・origin は **web の公開ベース URL のホスト**から導出する（ADR-0019 決定 2。
        // Passkey のセレモニーは web のページ上で実行されるため。`PUBLIC_WEB_BASE_URL` 未設定時は
        // issuer に追従し、single-origin では従来と同値になる）。per-tenant のパスは渡さない —
        // WebAuthn はプロトコル上ホスト単位であり、パスを含められないため（ADR-0009 §6）。
        // テナント分離は「クレデンシャル ⇔ ユーザー ⇔ 所属元テナント」のアプリ層の紐付けで実現する。
        let webauthn = Arc::new(WebAuthnService::new(config.public_web_base_url()));
        let passkey_registration = Arc::new(PasskeyRegistrationService::new(
            authenticators.clone(),
            webauthn_credentials.clone(),
            passkey_challenges.clone(),
            sso_sessions.clone(),
            webauthn.clone(),
            clock.clone(),
            ids,
        ));
        let passkey_authentication = Arc::new(PasskeyAuthenticationService::new(
            webauthn_credentials,
            authenticator_repository.clone(),
            passkey_challenges,
            auth_sessions.clone(),
            users.clone(),
            tenant_memberships.clone(),
            sso_sessions.clone(),
            client_consents,
            authentication_policies.clone(),
            code_issuance,
            webauthn,
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
            config.auth_policy_default_effect(),
        ));
        // 設定画面からの再起動（ADR-0017）。signal 自体は `run()` の graceful shutdown へ、
        // ユースケース（監査 → 停止要求）はハンドラへ渡すため、同じ値を 2 経路で保持する。
        let restart = ServiceRestart::new();
        let service_restart = Arc::new(ServiceRestartService::new(
            Arc::new(restart.clone()),
            audit.clone(),
        ));

        // CORS の許可オリジン（G1）。`/token`・`/userinfo` はホットパスのため、テナント→オリジン
        // 集合をテナント解決と同じ TTL でキャッシュする。管理画面で `redirect_uris` を変えた直後は
        // 最大 TTL 分だけ古い集合が使われるが、TTL は既定で短く、影響は「新しいオリジンからの
        // 読み取りが少しの間できない」だけ（古いオリジンが余分に通ることも同じ長さで起きる）。
        let cors_policy = Arc::new(ApiCorsPolicy::new(
            clients.clone(),
            config.cors_allowed_origins(),
            Arc::new(InMemoryTtlCache::new(
                chrono_from_std(config.tenant_cache_ttl()),
                clock.clone(),
            )),
        ));

        // 期限切れレコードの一括 GC（G2）。対象表の一覧は infrastructure 側に単一定義してあり、
        // ここは組み立てて `run()` のタスクへ渡すだけ。
        let expired_records = Arc::new(ExpiredRecordPurgeService::new(
            crate::infrastructure::repositories::expired_records::all_expiring_record_stores(
                pool.clone(),
            ),
            clock.clone(),
        ));

        Self {
            pool,
            config,
            tenant_resolution,
            register,
            email_verification,
            authorize,
            login,
            change_password,
            consent,
            token,
            userinfo,
            keys,
            admin_access,
            admin_login,
            portal_login,
            clients_admin,
            clients_status,
            permissions_admin,
            authentication_policies_admin,
            users_admin,
            users_lifecycle,
            tenants_admin,
            system_settings,
            account_password,
            account_language,
            account_profile,
            account_tenants,
            password_reset,
            invitations,
            member_directory,
            audit_query,
            application_logs,
            logout,
            account_security,
            step_up,
            authenticators,
            authenticator_repository,
            external_login,
            external_idps,
            external_providers,
            external_login_requests,
            backchannel_logout,
            revocation,
            introspection,
            totp_registration,
            mfa_login,
            passkey_registration,
            passkey_authentication,
            saml_service_providers,
            saml_sso,
            restart,
            service_restart,
            expired_records,
            cors_policy,
        }
    }
}

/// 設定値（`std::time::Duration`）を解決キャッシュの TTL（`chrono::Duration`）へ変換する。
/// TTL は秒精度で扱うため丸めは問題にならない（オーバーフロー時は上限に飽和させる）。
fn chrono_from_std(d: std::time::Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Db {
        state.pool.clone()
    }
}

impl FromRef<AppState> for Arc<RegisterService> {
    fn from_ref(state: &AppState) -> Arc<RegisterService> {
        state.register.clone()
    }
}
