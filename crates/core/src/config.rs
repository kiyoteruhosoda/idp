//! アプリケーション設定。
//!
//! 設定値の取得は **必ず本モジュール経由**で行う。生の環境変数・DSN を各所で直接参照しない。
//! 優先順位: 環境変数 > DB（system_settings テーブル）> 既定値。
//!
//! 一部の getter（各種 TTL・クロックスキュー）は後続フェーズ（T2〜）で使用するため、
//! 現時点では未使用でも保持する。
#![allow(dead_code)]

use crate::domain::system_setting::{
    runtime_setting_definition, DefaultRisk, SettingOwner, RUNTIME_SETTING_DEFINITIONS,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

/// 秘密鍵暗号化キーの開発用デフォルト（ちょうど 32 バイト）。本番では必ず `KEY_ENCRYPTION_KEY`
/// を設定する。運用では DB 外の鍵管理（KMS 等）へ移行する。
const DEV_KEY_ENCRYPTION_KEY: &[u8; 32] = b"idp-dev-insecure-key-0123456789!";

/// サービス間内部認証トークンの開発用デフォルト（ADR-0007 §5）。本番では必ず
/// `INTERNAL_SERVICE_TOKEN` を設定する。web→api の `/internal/*` 呼び出しを保護する共有シークレット。
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";

/// CSRF トークン HMAC 鍵の開発用デフォルト（ちょうど 32 バイト）。本番では必ず
/// `CSRF_SECRET` を web と api で同じ値に設定する（SEC7）。
pub const DEV_CSRF_SECRET: &[u8; 32] = b"idp-dev-insecure-csrf-secret-xxx";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    Builtin,
    Env,
    Db,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSetting {
    pub key: String,
    pub owner: SettingOwner,
    pub source: SettingSource,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    /// 画面表示用の安全判定（値や fingerprint は含めない）。
    pub status: SettingSafetyStatus,
    /// 危険/安全判定の根拠。secret の平文・fingerprint は含めない。
    pub reason: String,
    /// 起動時に解決された有効値（表示用）。secret のときは常に `None`（平文を外へ出さない）。
    pub value: Option<String>,
    /// 組み込み既定値（表示用）。secret のときは `None`。
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSafetyStatus {
    Safe,
    NeedsAction,
}

#[derive(Debug, Clone)]
pub struct Config {
    issuer: String,
    bind_addr: String,
    database_url: String,
    db_max_connections: u32,
    log_format: LogFormat,
    auth_session_ttl: Duration,
    authorization_code_ttl: Duration,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    access_token_ttl: Duration,
    id_token_ttl: Duration,
    refresh_token_ttl: Duration,
    clock_skew: Duration,
    /// ゲスト招待トークンの有効期限（ADR-0009 §3）。
    invitation_ttl: Duration,
    /// パスワードリセットトークンの有効期限（MT18）。
    password_reset_ttl: Duration,
    /// メール検証トークンの有効期限（SEC6b）。
    email_verification_ttl: Duration,
    /// テナント解決キャッシュの TTL（ADR-0009 §7。id → tenant のホットパス）。
    tenant_cache_ttl: Duration,
    /// scope→権限解決キャッシュの TTL（ADR-0009 §7。付与・剥奪時は即時 invalidate される）。
    permission_cache_ttl: Duration,
    cookie_secure: bool,
    key_encryption_key: [u8; 32],
    key_encryption_key_is_dev: bool,
    /// 署名鍵ローテーション: `not_after` のこの日数前に新鍵を生成して旧鍵を退役させる（K2）。
    key_rotation_lead_days: u32,
    /// リバースプロキシが付与する `X-Forwarded-For` / `X-Forwarded-Proto` を信頼するか（S1）。
    trust_forwarded_headers: bool,
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない（S1）。
    hsts_max_age: u64,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    /// CSRF トークン HMAC 鍵（`CSRF_SECRET`）。web と api で同じ値を設定する（SEC7）。
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    /// 利用者がブラウザで開く web 画面の公開ベース URL（招待メールの承諾リンク等。MT17）。
    public_web_base_url: String,
    resolved_settings: Vec<ResolvedSetting>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_and_db_settings(&HashMap::new())
    }

    pub fn from_env_and_db_settings(db_settings: &HashMap<String, String>) -> anyhow::Result<Self> {
        let resolver = ConfigResolver::new(db_settings);
        let (key_encryption_key, key_encryption_key_is_dev) = load_key_encryption_key()?;
        let issuer = normalize_issuer(resolver.string("ISSUER", "http://localhost:8080"));
        // Cookie の Secure 属性。既定は issuer のスキームに従う（https なら有効）。
        let cookie_secure = resolver.parse("COOKIE_SECURE", issuer.starts_with("https://"))?;
        // web→api の /internal/* 呼び出しを保護する共有シークレット（ADR-0007 §5）。
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (v, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // CSRF トークン HMAC 鍵（SEC7）。web と api で同じ値を設定する。
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // 本番（https issuer）では開発用デフォルトのシークレットで起動しない（fail-fast）。
        ensure_production_secrets(
            &issuer,
            key_encryption_key_is_dev,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        // 招待メール等の承諾リンクの土台。単一オリジン構成（ADR-0007）では issuer と同一オリジンに
        // web 画面が同居するため既定は issuer。web を別オリジンへ置く構成でのみ明示設定する。
        let public_web_base_url = match resolver.optional_string("PUBLIC_WEB_BASE_URL") {
            Some(v) => normalize_issuer(v),
            None => issuer.clone(),
        };

        Ok(Self {
            issuer,
            bind_addr: resolver.string("BIND_ADDR", "0.0.0.0:8080"),
            database_url: resolver.string("DATABASE_URL", "mysql://idp:idp@127.0.0.1:3306/idp"),
            db_max_connections: resolver.parse("DB_MAX_CONNECTIONS", 10)?,
            log_format: match resolver
                .string("LOG_FORMAT", "json")
                .to_ascii_lowercase()
                .as_str()
            {
                "pretty" => LogFormat::Pretty,
                _ => LogFormat::Json,
            },
            auth_session_ttl: secs(resolver.parse("AUTH_SESSION_TTL_SECS", 600)?),
            authorization_code_ttl: secs(resolver.parse("AUTHORIZATION_CODE_TTL_SECS", 60)?),
            sso_idle_ttl: secs(resolver.parse("SSO_IDLE_TTL_SECS", 28_800)?),
            sso_absolute_ttl: secs(resolver.parse("SSO_ABSOLUTE_TTL_SECS", 86_400)?),
            access_token_ttl: secs(resolver.parse("ACCESS_TOKEN_TTL_SECS", 900)?),
            id_token_ttl: secs(resolver.parse("ID_TOKEN_TTL_SECS", 3_600)?),
            // Refresh Token は既定 30 日（offline_access scope で発行。rotation あり）。
            refresh_token_ttl: secs(resolver.parse("REFRESH_TOKEN_TTL_SECS", 2_592_000)?),
            clock_skew: secs(resolver.parse("CLOCK_SKEW_SECS", 60)?),
            invitation_ttl: secs(resolver.parse("INVITATION_TTL_SECS", 604_800)?),
            password_reset_ttl: secs(resolver.parse("PASSWORD_RESET_TTL_SECS", 3_600)?),
            email_verification_ttl: secs(resolver.parse("EMAIL_VERIFICATION_TTL_SECS", 86_400)?),
            tenant_cache_ttl: secs(resolver.parse("TENANT_CACHE_TTL_SECS", 60)?),
            permission_cache_ttl: secs(resolver.parse("PERMISSION_CACHE_TTL_SECS", 60)?),
            cookie_secure,
            key_encryption_key,
            key_encryption_key_is_dev,
            key_rotation_lead_days: resolver.parse("KEY_ROTATION_LEAD_DAYS", 30)?,
            trust_forwarded_headers: resolver.parse("TRUST_FORWARDED_HEADERS", false)?,
            hsts_max_age: resolver.parse("HSTS_MAX_AGE", 0u64)?,
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            public_web_base_url,
            resolved_settings: resolver.resolved_settings(),
        })
    }

    /// OIDC issuer（末尾スラッシュ無し。ID Token の `iss` と完全一致させる）。
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }
    pub fn database_url(&self) -> &str {
        &self.database_url
    }
    pub fn db_max_connections(&self) -> u32 {
        self.db_max_connections
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
    pub fn auth_session_ttl(&self) -> Duration {
        self.auth_session_ttl
    }
    pub fn authorization_code_ttl(&self) -> Duration {
        self.authorization_code_ttl
    }
    pub fn sso_idle_ttl(&self) -> Duration {
        self.sso_idle_ttl
    }
    pub fn sso_absolute_ttl(&self) -> Duration {
        self.sso_absolute_ttl
    }
    pub fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }
    pub fn id_token_ttl(&self) -> Duration {
        self.id_token_ttl
    }
    pub fn refresh_token_ttl(&self) -> Duration {
        self.refresh_token_ttl
    }
    pub fn clock_skew(&self) -> Duration {
        self.clock_skew
    }
    /// ゲスト招待トークンの有効期限（ADR-0009 §3）。
    pub fn invitation_ttl(&self) -> Duration {
        self.invitation_ttl
    }
    /// パスワードリセットトークンの有効期限（MT18）。
    pub fn password_reset_ttl(&self) -> Duration {
        self.password_reset_ttl
    }

    pub fn email_verification_ttl(&self) -> Duration {
        self.email_verification_ttl
    }
    /// テナント解決キャッシュ（id → tenant）の TTL（ADR-0009 §7）。
    pub fn tenant_cache_ttl(&self) -> Duration {
        self.tenant_cache_ttl
    }
    /// scope→権限解決キャッシュ（`has_permission`）の TTL（ADR-0009 §7）。
    pub fn permission_cache_ttl(&self) -> Duration {
        self.permission_cache_ttl
    }
    /// Cookie に `Secure` 属性を付けるか（設計仕様 §2.4。開発時の http issuer では無効化できる）。
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
    /// 秘密鍵（SigningKeys.private_key_encrypted）の暗号化に使う 32 バイト鍵。
    pub fn key_encryption_key(&self) -> &[u8; 32] {
        &self.key_encryption_key
    }
    /// 開発用デフォルトの暗号化鍵を使っているか（本番では警告対象）。
    pub fn key_encryption_key_is_dev(&self) -> bool {
        self.key_encryption_key_is_dev
    }
    /// 署名鍵ローテーション: `not_after` のこの日数前に次期鍵を生成して旧鍵を退役させる（K2）。
    pub fn key_rotation_lead_days(&self) -> u32 {
        self.key_rotation_lead_days
    }
    /// リバースプロキシが付与する `X-Forwarded-For` / `X-Forwarded-Proto` を信頼するか（S1）。
    pub fn trust_forwarded_headers(&self) -> bool {
        self.trust_forwarded_headers
    }
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない（S1）。
    pub fn hsts_max_age(&self) -> u64 {
        self.hsts_max_age
    }
    /// web→api の `/internal/*` 呼び出しを保護するサービス認証トークン（ADR-0007 §5）。
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    /// 開発用デフォルトの内部サービストークンを使っているか（本番では警告対象）。
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    /// CSRF トークン HMAC 鍵（SEC7）。ログイン・同意フォームの CSRF トークン導出に使う。
    /// web と api で同じ値（`CSRF_SECRET` 環境変数）を設定する。
    pub fn csrf_secret(&self) -> &[u8; 32] {
        &self.csrf_secret
    }
    /// 開発用デフォルトの CSRF シークレットを使っているか（本番では起動を拒否する）。
    pub fn csrf_secret_is_dev(&self) -> bool {
        self.csrf_secret_is_dev
    }
    /// 利用者がブラウザで開く web 画面の公開ベース URL（末尾スラッシュ無し。招待メールの
    /// 承諾リンク等に使う。既定は issuer と同一オリジン。MT17）。
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }

    pub fn resolved_settings(&self) -> &[ResolvedSetting] {
        &self.resolved_settings
    }
}

struct ConfigResolver<'a> {
    db_settings: &'a HashMap<String, String>,
}

impl<'a> ConfigResolver<'a> {
    fn new(db_settings: &'a HashMap<String, String>) -> Self {
        Self { db_settings }
    }

    fn optional_string(&self, key: &str) -> Option<String> {
        env_lookup(key).or_else(|| {
            let db_allowed = runtime_setting_definition(key)
                .map(|def| def.owner == SettingOwner::DbManaged)
                .unwrap_or(false);
            db_allowed
                .then(|| self.db_settings.get(key).filter(|v| !v.is_empty()).cloned())
                .flatten()
        })
    }

    fn string(&self, key: &str, default: &str) -> String {
        self.optional_string(key)
            .unwrap_or_else(|| default.to_string())
    }

    fn parse<T>(&self, key: &str, default: T) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.optional_string(key) {
            Some(v) => v
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
            None => Ok(default),
        }
    }

    fn source(&self, key: &str) -> SettingSource {
        if env_lookup(key).is_some() {
            return SettingSource::Env;
        }
        let db_allowed = runtime_setting_definition(key)
            .map(|def| def.owner == SettingOwner::DbManaged)
            .unwrap_or(false);
        if db_allowed
            && self
                .db_settings
                .get(key)
                .filter(|v| !v.is_empty())
                .is_some()
        {
            SettingSource::Db
        } else {
            SettingSource::Builtin
        }
    }

    fn safety_status(&self, key: &str, default_risk: DefaultRisk) -> SettingSafetyStatus {
        match key {
            "KEY_ENCRYPTION_KEY" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "INTERNAL_SERVICE_TOKEN" if env_lookup(key).is_none() => {
                SettingSafetyStatus::NeedsAction
            }
            "CSRF_SECRET" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "COOKIE_SECURE" => match self.optional_string(key) {
                Some(v) if v.eq_ignore_ascii_case("false") => SettingSafetyStatus::NeedsAction,
                None => SettingSafetyStatus::NeedsAction,
                _ => SettingSafetyStatus::Safe,
            },
            "HSTS_MAX_AGE" => match self.optional_string(key) {
                Some(v) if v != "0" => SettingSafetyStatus::Safe,
                _ => SettingSafetyStatus::NeedsAction,
            },
            _ if default_risk == DefaultRisk::Dangerous
                && self.source(key) == SettingSource::Builtin =>
            {
                SettingSafetyStatus::NeedsAction
            }
            _ => SettingSafetyStatus::Safe,
        }
    }

    fn safety_reason(&self, key: &str, default_risk: DefaultRisk) -> String {
        match key {
            "KEY_ENCRYPTION_KEY" | "INTERNAL_SERVICE_TOKEN" | "CSRF_SECRET"
                if env_lookup(key).is_none() =>
            {
                "開発用の既知 secret が使われています。環境変数でランダム値を設定してください。".to_string()
            }
            "COOKIE_SECURE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "Cookie Secure が無効または組み込み既定です。HTTPS 配置では true にしてください。".to_string()
            }
            "HSTS_MAX_AGE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "HSTS が無効です。HTTPS 配置では正の max-age を設定してください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Dangerous => {
                "危険な組み込み既定値が使われています。環境変数または DB 管理値で上書きしてください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Review => {
                "組み込み既定値です。配置環境に適しているか確認してください。".to_string()
            }
            _ => "現在の出所では要対応項目は検出されていません。".to_string(),
        }
    }

    fn resolved_settings(&self) -> Vec<ResolvedSetting> {
        RUNTIME_SETTING_DEFINITIONS
            .iter()
            .map(|def| ResolvedSetting {
                key: def.key.to_string(),
                owner: def.owner,
                source: match def.owner {
                    SettingOwner::Builtin => SettingSource::Builtin,
                    SettingOwner::EnvLocked | SettingOwner::DbManaged => self.source(def.key),
                },
                secret: def.secret,
                restart_required: def.restart_required,
                default_risk: def.default_risk,
                status: self.safety_status(def.key, def.default_risk),
                reason: self.safety_reason(def.key, def.default_risk),
                value: (!def.secret)
                    .then(|| {
                        self.optional_string(def.key)
                            .or_else(|| def.default_value.map(str::to_string))
                    })
                    .flatten(),
                default_value: (!def.secret)
                    .then(|| def.default_value.map(str::to_string))
                    .flatten(),
            })
            .collect()
    }
}

fn normalize_issuer(raw: String) -> String {
    raw.trim_end_matches('/').to_string()
}

/// 本番相当（issuer が `https://`）で開発用デフォルトのシークレットが使われていたら起動を失敗させる。
///
/// 開発用デフォルト（`DEV_KEY_ENCRYPTION_KEY`・`DEV_INTERNAL_SERVICE_TOKEN`・`DEV_CSRF_SECRET`）は
/// ソースに埋め込まれた既知値であり、本番で使うと署名鍵の暗号化・`/internal/*` の保護・CSRF 防御が
/// 実質無効になる。warning での見逃しを防ぐため、http（ローカル開発）以外では設定漏れを構成エラーとする。
fn ensure_production_secrets(
    issuer: &str,
    key_encryption_key_is_dev: bool,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    if !issuer.starts_with("https://") {
        return Ok(());
    }
    if key_encryption_key_is_dev {
        anyhow::bail!(
            "ISSUER is https ({issuer}) but KEY_ENCRYPTION_KEY is not set; \
             refusing to start with the built-in development key. \
             Set KEY_ENCRYPTION_KEY (base64, 32 bytes) in production."
        );
    }
    if internal_service_token_is_dev {
        anyhow::bail!(
            "ISSUER is https ({issuer}) but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with web) in production."
        );
    }
    if csrf_secret_is_dev {
        anyhow::bail!(
            "ISSUER is https ({issuer}) but CSRF_SECRET is not set; \
             refusing to start with the built-in development key. \
             Set CSRF_SECRET (base64, 32 bytes, shared with web) in production."
        );
    }
    Ok(())
}

/// `KEY_ENCRYPTION_KEY`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
fn load_key_encryption_key() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("KEY_ENCRYPTION_KEY") {
        Some(v) => {
            let bytes = STANDARD
                .decode(v.trim())
                .map_err(|e| anyhow::anyhow!("KEY_ENCRYPTION_KEY must be base64: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                anyhow::anyhow!(
                    "KEY_ENCRYPTION_KEY must decode to 32 bytes, got {}",
                    b.len()
                )
            })?;
            Ok((arr, false))
        }
        None => Ok((*DEV_KEY_ENCRYPTION_KEY, true)),
    }
}

/// `CSRF_SECRET`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => {
            let bytes = STANDARD
                .decode(v.trim())
                .map_err(|e| anyhow::anyhow!("CSRF_SECRET must be base64: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                anyhow::anyhow!("CSRF_SECRET must decode to 32 bytes, got {}", b.len())
            })?;
            Ok((arr, false))
        }
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

fn secs(v: u64) -> Duration {
    Duration::from_secs(v)
}

/// 環境変数を引く。**空文字列は「未設定」として扱う**。
///
/// Docker Compose の `${VAR:-}` は未指定でもキーを空文字列で注入するため、空を未設定と
/// みなさないと数値・bool パースが失敗して起動できなくなる（例: `COOKIE_SECURE=""`）。
fn env_lookup(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// 環境変数を文字列で引く（未設定・空は既定値）。設定解決は [`ConfigResolver`] へ移行済みで、
/// 現在はフォールバック挙動を検証するテストからのみ使う。
#[cfg(test)]
fn env_or(key: &str, default: &str) -> String {
    env_lookup(key).unwrap_or_else(|| default.to_string())
}

/// 環境変数をパースして引く（未設定・空は既定値）。[`env_or`] と同じくテスト専用の補助。
#[cfg(test)]
fn env_parse<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env_lookup(key) {
        Some(v) => v
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// プロセス共有の環境変数を触るテストを直列化するためのロック。
    ///
    /// `cargo test` は 1 プロセス内の複数スレッドでテストを並列実行し、`std::env` は
    /// プロセス全体で共有される。環境変数を設定/削除しつつ `Config` を組み立てるテストが
    /// 並行すると、あるテストが設定した値を別テストが読んでしまい非決定的に失敗する
    /// （例: `KEY_ROTATION_LEAD_DAYS` の 14 と 7 の取り違え）。該当テストはこのロックを
    /// 取得して直列化する。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `ENV_LOCK` を取得する。ロック保持中に別テストが panic して poison しても、
    /// 排他自体は保たれているため内側の値を取り出して継続する。
    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn issuer_is_normalized_without_trailing_slash() {
        assert_eq!(
            normalize_issuer("https://idp.example.com/".to_string()),
            "https://idp.example.com"
        );
        assert_eq!(
            normalize_issuer("https://idp.example.com".to_string()),
            "https://idp.example.com"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        // https issuer + 開発用デフォルト → 構成エラー（fail-fast）。
        assert!(ensure_production_secrets("https://idp.example.com", true, false, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, true, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, false, true).is_err());
        // 全部明示設定されていれば https でも起動できる。
        assert!(ensure_production_secrets("https://idp.example.com", false, false, false).is_ok());
        // http（ローカル開発）は開発用デフォルトを許容する（起動時 warning のみ）。
        assert!(ensure_production_secrets("http://localhost:8080", true, true, true).is_ok());
    }

    #[test]
    fn db_managed_settings_override_builtin_defaults() {
        let _env = env_guard();
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 7);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Db);
        assert_eq!(rotation.owner, SettingOwner::DbManaged);
    }

    #[test]
    fn env_overrides_db_managed_settings() {
        let _env = env_guard();
        std::env::set_var("KEY_ROTATION_LEAD_DAYS", "14");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 14);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Env);
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
    }

    #[test]
    fn shared_web_runtime_settings_ignore_db_until_materialized() {
        let _env = env_guard();
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        let db = HashMap::from([("AUTH_SESSION_TTL_SECS".to_string(), "1200".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.auth_session_ttl(), Duration::from_secs(600));
        let ttl = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "AUTH_SESSION_TTL_SECS")
            .unwrap();
        assert_eq!(ttl.owner, SettingOwner::EnvLocked);
        assert_eq!(ttl.source, SettingSource::Builtin);
    }

    #[test]
    fn env_locked_settings_ignore_db_values() {
        let _env = env_guard();
        std::env::remove_var("DB_MAX_CONNECTIONS");
        let db = HashMap::from([("DB_MAX_CONNECTIONS".to_string(), "99".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.db_max_connections(), 10);
        let db_max = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "DB_MAX_CONNECTIONS")
            .unwrap();
        assert_eq!(db_max.owner, SettingOwner::EnvLocked);
        assert_eq!(db_max.source, SettingSource::Builtin);
    }

    #[test]
    fn resolved_settings_flag_dangerous_bootstrap_defaults_without_exposing_values() {
        let _env = env_guard();
        std::env::remove_var("KEY_ENCRYPTION_KEY");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        for key in [
            "KEY_ENCRYPTION_KEY",
            "INTERNAL_SERVICE_TOKEN",
            "CSRF_SECRET",
            "COOKIE_SECURE",
            "HSTS_MAX_AGE",
        ] {
            let setting = settings.iter().find(|setting| setting.key == key).unwrap();
            assert_eq!(setting.status, SettingSafetyStatus::NeedsAction);
            assert!(!setting.reason.contains("idp-dev-insecure"));
        }
    }

    #[test]
    fn explicit_secure_cookie_and_hsts_are_marked_safe() {
        let _env = env_guard();
        std::env::set_var("COOKIE_SECURE", "true");
        std::env::set_var("HSTS_MAX_AGE", "31536000");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        let cookie = settings
            .iter()
            .find(|setting| setting.key == "COOKIE_SECURE")
            .unwrap();
        let hsts = settings
            .iter()
            .find(|setting| setting.key == "HSTS_MAX_AGE")
            .unwrap();
        assert_eq!(cookie.status, SettingSafetyStatus::Safe);
        assert_eq!(hsts.status, SettingSafetyStatus::Safe);

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
    }

    #[test]
    fn env_parse_falls_back_to_default_when_unset() {
        // 未設定キーは既定値を返す。
        let v: u64 = env_parse("IDP_TEST_DEFINITELY_UNSET_KEY", 42).unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        // Compose の `${VAR:-}` 由来の空文字列は「未設定」として既定値へフォールバックする。
        let key = "IDP_TEST_EMPTY_ENV_VAR";
        std::env::set_var(key, "");
        assert_eq!(env_or(key, "fallback"), "fallback");
        let v: bool = env_parse(key, true).unwrap();
        assert!(v);
        std::env::remove_var(key);
    }
}
