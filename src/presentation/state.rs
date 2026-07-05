//! axum の共有状態。各サービスを `Arc` で保持し、`FromRef` でハンドラへ部分注入する。
//!
//! [`AppState::build`] がユースケースの組み立て（依存注入）を一手に担う。
//! バイナリ（`lib.rs::run`）と統合テストの双方から同じ組み立てを使う。

use crate::application::audit::AuditService;
use crate::application::authorize::AuthorizeService;
use crate::application::code_issuance::CodeIssuanceService;
use crate::application::key_service::KeyService;
use crate::application::login::LoginService;
use crate::application::register::RegisterService;
use crate::application::token::TokenService;
use crate::application::userinfo::UserInfoService;
use crate::config::Config;
use crate::domain::clock::Clock;
use crate::infrastructure::db::Db;
use crate::infrastructure::password::Argon2PasswordHasher;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::infrastructure::repositories::audit_log::SqlxAuditLogSink;
use crate::infrastructure::repositories::auth_session::SqlxAuthSessionRepository;
use crate::infrastructure::repositories::authorization_code::SqlxAuthorizationCodeRepository;
use crate::infrastructure::repositories::client::SqlxClientRepository;
use crate::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use crate::infrastructure::repositories::sso_session::SqlxSsoSessionRepository;
use crate::infrastructure::repositories::user::SqlxUserRepository;
use axum::extract::FromRef;
use std::sync::Arc;

/// IP 単位のログインレート制限: 5 分間で最大 30 試行（設計仕様 §4.3「IP単位でもレート制限」）。
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 30;
const LOGIN_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

#[derive(Clone)]
pub struct AppState {
    pub pool: Db,
    pub config: Arc<Config>,
    pub register: Arc<RegisterService>,
    pub authorize: Arc<AuthorizeService>,
    pub login: Arc<LoginService>,
    pub token: Arc<TokenService>,
    pub userinfo: Arc<UserInfoService>,
    pub keys: Arc<KeyService>,
}

impl AppState {
    /// すべてのユースケースを組み立てる（トレイト越しのコンストラクタ注入）。
    pub fn build(pool: Db, config: Arc<Config>, clock: Arc<dyn Clock>) -> Self {
        let users = Arc::new(SqlxUserRepository::new(pool.clone()));
        let clients = Arc::new(SqlxClientRepository::new(pool.clone()));
        let auth_sessions = Arc::new(SqlxAuthSessionRepository::new(pool.clone()));
        let sso_sessions = Arc::new(SqlxSsoSessionRepository::new(pool.clone()));
        let codes = Arc::new(SqlxAuthorizationCodeRepository::new(pool.clone()));
        let signing_keys = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
        let audit_sink = Arc::new(SqlxAuditLogSink::new(pool.clone()));
        let hasher = Arc::new(Argon2PasswordHasher::new());
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
            hasher.clone(),
            clock.clone(),
        ));
        let authorize = Arc::new(AuthorizeService::new(
            clients.clone(),
            users.clone(),
            auth_sessions.clone(),
            sso_sessions.clone(),
            code_issuance.clone(),
            audit.clone(),
            clock.clone(),
            config.auth_session_ttl(),
            config.sso_idle_ttl(),
        ));
        let login = Arc::new(LoginService::new(
            users.clone(),
            auth_sessions,
            sso_sessions,
            code_issuance,
            hasher.clone(),
            rate_limiter,
            audit.clone(),
            clock.clone(),
            config.sso_idle_ttl(),
            config.sso_absolute_ttl(),
        ));
        let token = Arc::new(TokenService::new(
            clients,
            users.clone(),
            codes,
            keys.clone(),
            hasher,
            audit,
            clock.clone(),
            config.issuer().to_string(),
            config.access_token_ttl(),
            config.id_token_ttl(),
        ));
        let userinfo = Arc::new(UserInfoService::new(
            signing_keys,
            users,
            clock,
            config.issuer().to_string(),
            config.clock_skew(),
        ));

        Self {
            pool,
            config,
            register,
            authorize,
            login,
            token,
            userinfo,
            keys,
        }
    }
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
