//! axum の共有状態。各サービスを `Arc` で保持し、`FromRef` でハンドラへ部分注入する。
//!
//! [`AppState::build`] がユースケースの組み立て（依存注入）を一手に担う。
//! バイナリ（`lib.rs::run`）と統合テストの双方から同じ組み立てを使う。
//!
//! # 過渡期のテナント解決（MT5 → MT9）
//!
//! ユースケースは `TenantContext` を必須で受け取る（ADR-0009 §8）が、`/{tenant_id}/...`
//! ルーティングと `TenantResolver` middleware は後続タスク（MT6・MT9）で導入する。それまでは
//! 起動時に解決した **root テナントを既定のテナント** として全リクエストに適用する
//! （`default_tenant`）。MT9 で「リクエストパスから解決した `Extension<ResolvedTenant>`」へ
//! 置き換える。

use crate::application::admin_access::AdminAccessService;
use crate::application::admin_login::AdminLoginService;
use crate::application::audit::AuditService;
use crate::application::audit_query::AuditQueryService;
use crate::application::authorize::AuthorizeService;
use crate::application::change_password::ChangePasswordService;
use crate::application::client_management::ClientManagementService;
use crate::application::client_status::ClientStatusService;
use crate::application::code_issuance::CodeIssuanceService;
use crate::application::consent::ConsentService;
use crate::application::introspection::IntrospectionService;
use crate::application::invitation::InvitationService;
use crate::application::key_service::KeyService;
use crate::application::login::LoginService;
use crate::application::logout::LogoutService;
use crate::application::mfa_login::MfaLoginService;
use crate::application::passkey_authentication::PasskeyAuthenticationService;
use crate::application::passkey_registration::PasskeyRegistrationService;
use crate::application::permission_management::PermissionManagementService;
use crate::application::register::RegisterService;
use crate::application::revocation::RevocationService;
use crate::application::tenant_management::TenantManagementService;
use crate::application::tenant_resolution::TenantResolutionService;
use crate::application::token::TokenService;
use crate::application::totp_registration::TotpRegistrationService;
use crate::application::user_management::UserManagementService;
use crate::application::userinfo::UserInfoService;
use crate::config::Config;
use crate::domain::cache::Cache;
use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::UserPermissionRepository;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::cache::InMemoryTtlCache;
use crate::infrastructure::db::Db;
use crate::infrastructure::id_generator::UuidV7Generator;
use crate::infrastructure::password::Argon2PasswordHasher;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::infrastructure::repositories::audit_log::{SqlxAuditLogQuery, SqlxAuditLogSink};
use crate::infrastructure::repositories::cached_user_permission::{
    CachedUserPermissionRepository, PermissionKey,
};
use crate::infrastructure::repositories::auth_session::SqlxAuthSessionRepository;
use crate::infrastructure::repositories::authorization_code::SqlxAuthorizationCodeRepository;
use crate::infrastructure::repositories::client::SqlxClientRepository;
use crate::infrastructure::repositories::consent::SqlxClientConsentRepository;
use crate::infrastructure::repositories::passkey_challenge::SqlxPasskeyChallengeRepository;
use crate::infrastructure::repositories::refresh_token::SqlxRefreshTokenRepository;
use crate::infrastructure::repositories::revoked_access_token::SqlxRevokedAccessTokenRepository;
use crate::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use crate::infrastructure::repositories::sso_session::SqlxSsoSessionRepository;
use crate::infrastructure::repositories::tenant::SqlxTenantRepository;
use crate::infrastructure::repositories::tenant_membership::SqlxTenantMembershipRepository;
use crate::infrastructure::repositories::totp_secret::SqlxTotpSecretRepository;
use crate::infrastructure::repositories::user::SqlxUserRepository;
use crate::infrastructure::repositories::user_permission::SqlxUserPermissionRepository;
use crate::infrastructure::repositories::webauthn_credential::SqlxWebAuthnCredentialRepository;
use crate::infrastructure::webauthn::WebAuthnService;
use axum::extract::FromRef;
use std::sync::Arc;

/// IP 単位のログインレート制限: 5 分間で最大 30 試行（設計仕様 §4.3「IP単位でもレート制限」）。
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 30;
const LOGIN_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

#[derive(Clone)]
pub struct AppState {
    pub pool: Db,
    pub config: Arc<Config>,
    /// 過渡期（MT9 まで）の既定テナント（root）。全リクエストをこのテナントの文脈で処理する。
    pub default_tenant: TenantContext,
    /// テナント解決（id → tenant）。`TenantResolver` middleware が使う（MT9 でルーターへ mount）。
    pub tenant_resolution: Arc<TenantResolutionService>,
    pub register: Arc<RegisterService>,
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
    pub clients_admin: Arc<ClientManagementService>,
    pub clients_status: Arc<ClientStatusService>,
    pub permissions_admin: Arc<PermissionManagementService>,
    /// 管理者による利用者作成（自動生成パスワード・must_change_password。ADR-0009 §5）。
    pub users_admin: Arc<UserManagementService>,
    /// テナント作成・管理（idp.system.admin 必須。ADR-0009 §5・§6）。
    pub tenants_admin: Arc<TenantManagementService>,
    /// ゲスト招待・メンバーシップ（ADR-0009 §3）。
    pub invitations: Arc<InvitationService>,
    pub audit_query: Arc<AuditQueryService>,
    pub logout: Arc<LogoutService>,
    pub revocation: Arc<RevocationService>,
    pub introspection: Arc<IntrospectionService>,
    pub totp_registration: Arc<TotpRegistrationService>,
    pub mfa_login: Arc<MfaLoginService>,
    pub passkey_registration: Arc<PasskeyRegistrationService>,
    pub passkey_authentication: Arc<PasskeyAuthenticationService>,
}

impl AppState {
    /// すべてのユースケースを組み立てる（トレイト越しのコンストラクタ注入）。
    /// `default_tenant` は起動時に解決した root テナント ID（上記モジュールコメント参照）。
    pub fn build(
        pool: Db,
        config: Arc<Config>,
        clock: Arc<dyn Clock>,
        default_tenant: TenantId,
    ) -> Self {
        let users = Arc::new(SqlxUserRepository::new(pool.clone()));
        let tenant_memberships = Arc::new(SqlxTenantMembershipRepository::new(pool.clone()));
        let clients = Arc::new(SqlxClientRepository::new(pool.clone()));
        let auth_sessions = Arc::new(SqlxAuthSessionRepository::new(pool.clone()));
        let sso_sessions = Arc::new(SqlxSsoSessionRepository::new(pool.clone()));
        let codes = Arc::new(SqlxAuthorizationCodeRepository::new(pool.clone()));
        let refresh_tokens = Arc::new(SqlxRefreshTokenRepository::new(pool.clone()));
        let revoked_access_tokens = Arc::new(SqlxRevokedAccessTokenRepository::new(pool.clone()));
        let signing_keys = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
        let tenants = Arc::new(SqlxTenantRepository::new(pool.clone()));
        // scope→権限解決（ADR-0009 §7）: `has_permission` の判定結果を TTL キャッシュし、付与・剥奪時に
        // invalidate する。判定（admin_access）と変更（permissions_admin）が同一インスタンスを共有する
        // ため、付与直後の反映漏れ（stale allow/deny）を避けられる。
        let permission_cache: Arc<dyn Cache<PermissionKey, bool>> = Arc::new(
            InMemoryTtlCache::new(chrono_from_std(config.permission_cache_ttl()), clock.clone()),
        );
        let user_permissions: Arc<dyn UserPermissionRepository> =
            Arc::new(CachedUserPermissionRepository::new(
                Arc::new(SqlxUserPermissionRepository::new(pool.clone())),
                permission_cache,
            ));
        let client_consents = Arc::new(SqlxClientConsentRepository::new(pool.clone()));
        let totp_secrets = Arc::new(SqlxTotpSecretRepository::new(pool.clone()));
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

        let register = Arc::new(RegisterService::new(
            users.clone(),
            tenant_memberships.clone(),
            hasher.clone(),
            clock.clone(),
            ids.clone(),
        ));
        let authorize = Arc::new(AuthorizeService::new(
            clients.clone(),
            users.clone(),
            auth_sessions.clone(),
            sso_sessions.clone(),
            tenant_memberships.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            audit.clone(),
            clock.clone(),
            config.auth_session_ttl(),
            config.sso_idle_ttl(),
        ));
        let login = Arc::new(LoginService::new(
            users.clone(),
            auth_sessions.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            totp_secrets.clone(),
            code_issuance.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
        ));
        let change_password = Arc::new(ChangePasswordService::new(
            auth_sessions.clone(),
            users.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
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
            hasher.clone(),
            rate_limiter,
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
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
            user_permissions.clone(),
            audit.clone(),
            clock.clone(),
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
        // テナント作成・管理（ADR-0009 §5・§6）。初期管理者の生成は users_admin へ委譲し、新テナント
        // scope の idp.tenant.admin 付与は同一キャッシュ付きリポジトリを共有するため判定へ即時反映される。
        let tenants_admin = Arc::new(TenantManagementService::new(
            tenants.clone(),
            users_admin.clone(),
            user_permissions.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // ゲスト招待・メンバーシップ（ADR-0009 §3）。権限は同一キャッシュ付きリポジトリを共有するため、
        // メンバーシップ解除に伴う権限剥奪も判定キャッシュへ即時反映される。
        let invitations = Arc::new(InvitationService::new(
            users.clone(),
            tenant_memberships.clone(),
            user_permissions.clone(),
            audit.clone(),
            clock.clone(),
            config.invitation_ttl(),
        ));
        let admin_access = Arc::new(AdminAccessService::new(
            sso_sessions.clone(),
            users.clone(),
            user_permissions,
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
            clients,
            signing_keys.clone(),
            refresh_tokens,
            revoked_access_tokens,
            hasher,
            clock.clone(),
            config.issuer().to_string(),
            config.clock_skew(),
        ));

        let totp_registration = Arc::new(TotpRegistrationService::new(
            totp_secrets.clone(),
            sso_sessions.clone(),
            *config.key_encryption_key(),
            config.issuer().to_string(),
            clock.clone(),
        ));
        let mfa_login = Arc::new(MfaLoginService::new(
            auth_sessions.clone(),
            totp_secrets,
            users.clone(),
            sso_sessions.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
        ));

        // WebAuthn の RP ID・origin は**基底 issuer のホスト**から導出する（ADR-0009 §6）。
        // per-tenant issuer（`<基底>/<tenant_id>`）は渡さない — WebAuthn はプロトコル上ホスト単位であり、
        // パスを含められないため。テナント分離は「クレデンシャル ⇔ ユーザー ⇔ 所属元テナント」の
        // アプリ層の紐付けで実現する。`config.issuer()` は基底（ホスト）issuer。
        let webauthn = Arc::new(WebAuthnService::new(config.issuer()));
        let passkey_registration = Arc::new(PasskeyRegistrationService::new(
            webauthn_credentials.clone(),
            passkey_challenges.clone(),
            sso_sessions.clone(),
            webauthn.clone(),
            clock.clone(),
            ids,
        ));
        let passkey_authentication = Arc::new(PasskeyAuthenticationService::new(
            webauthn_credentials,
            passkey_challenges,
            auth_sessions.clone(),
            users.clone(),
            sso_sessions.clone(),
            client_consents,
            code_issuance,
            webauthn,
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
        ));

        Self {
            pool,
            config,
            default_tenant: TenantContext::new(default_tenant),
            tenant_resolution,
            register,
            authorize,
            login,
            change_password,
            consent,
            token,
            userinfo,
            keys,
            admin_access,
            admin_login,
            clients_admin,
            clients_status,
            permissions_admin,
            users_admin,
            tenants_admin,
            invitations,
            audit_query,
            logout,
            revocation,
            introspection,
            totp_registration,
            mfa_login,
            passkey_registration,
            passkey_authentication,
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
