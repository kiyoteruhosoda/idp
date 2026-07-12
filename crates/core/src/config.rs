//! アプリケーション設定。
//!
//! 設定値の取得は **必ず本モジュール経由**で行う。生の環境変数・DSN を各所で直接参照しない。
//! 優先順位: 環境変数 > DB（system_settings テーブル）> 既定値。
//! MVP では DB 上書きは未実装のため、実質「環境変数 > 既定値」で解決する。
//!
//! 一部の getter（各種 TTL・クロックスキュー）は後続フェーズ（T2〜）で使用するため、
//! 現時点では未使用でも保持する。
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use std::env;
use std::time::Duration;

/// 秘密鍵暗号化キーの開発用デフォルト（ちょうど 32 バイト）。本番では必ず `KEY_ENCRYPTION_KEY`
/// を設定する。運用では DB 外の鍵管理（KMS 等）へ移行する。
const DEV_KEY_ENCRYPTION_KEY: &[u8; 32] = b"idp-dev-insecure-key-0123456789!";

/// サービス間内部認証トークンの開発用デフォルト（ADR-0007 §5）。本番では必ず
/// `INTERNAL_SERVICE_TOKEN` を設定する。web→api の `/internal/*` 呼び出しを保護する共有シークレット。
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
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
    /// 利用者がブラウザで開く web 画面の公開ベース URL（招待メールの承諾リンク等。MT17）。
    public_web_base_url: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let (key_encryption_key, key_encryption_key_is_dev) = load_key_encryption_key()?;
        let issuer = normalize_issuer(env_or("ISSUER", "http://localhost:8080"));
        // Cookie の Secure 属性。既定は issuer のスキームに従う（https なら有効）。
        let cookie_secure = env_parse("COOKIE_SECURE", issuer.starts_with("https://"))?;
        // web→api の /internal/* 呼び出しを保護する共有シークレット（ADR-0007 §5）。
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (v, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // 本番（https issuer）では開発用デフォルトのシークレットで起動しない（fail-fast）。
        ensure_production_secrets(
            &issuer,
            key_encryption_key_is_dev,
            internal_service_token_is_dev,
        )?;
        // 招待メール等の承諾リンクの土台。単一オリジン構成（ADR-0007）では issuer と同一オリジンに
        // web 画面が同居するため既定は issuer。web を別オリジンへ置く構成でのみ明示設定する。
        let public_web_base_url = match env_lookup("PUBLIC_WEB_BASE_URL") {
            Some(v) => normalize_issuer(v),
            None => issuer.clone(),
        };

        Ok(Self {
            issuer,
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8080"),
            database_url: env_or("DATABASE_URL", "mysql://idp:idp@127.0.0.1:3306/idp"),
            db_max_connections: env_parse("DB_MAX_CONNECTIONS", 10)?,
            log_format: match env_or("LOG_FORMAT", "json").to_ascii_lowercase().as_str() {
                "pretty" => LogFormat::Pretty,
                _ => LogFormat::Json,
            },
            auth_session_ttl: secs(env_parse("AUTH_SESSION_TTL_SECS", 600)?),
            authorization_code_ttl: secs(env_parse("AUTHORIZATION_CODE_TTL_SECS", 60)?),
            sso_idle_ttl: secs(env_parse("SSO_IDLE_TTL_SECS", 28_800)?),
            sso_absolute_ttl: secs(env_parse("SSO_ABSOLUTE_TTL_SECS", 86_400)?),
            access_token_ttl: secs(env_parse("ACCESS_TOKEN_TTL_SECS", 900)?),
            id_token_ttl: secs(env_parse("ID_TOKEN_TTL_SECS", 3_600)?),
            // Refresh Token は既定 30 日（offline_access scope で発行。rotation あり）。
            refresh_token_ttl: secs(env_parse("REFRESH_TOKEN_TTL_SECS", 2_592_000)?),
            clock_skew: secs(env_parse("CLOCK_SKEW_SECS", 60)?),
            // ゲスト招待トークンの有効期限（既定 7 日）。
            invitation_ttl: secs(env_parse("INVITATION_TTL_SECS", 604_800)?),
            // パスワードリセットトークンの有効期限（既定 1 時間）。
            password_reset_ttl: secs(env_parse("PASSWORD_RESET_TTL_SECS", 3_600)?),
            // 解決キャッシュの TTL（既定 60 秒）。付与・剥奪・テナント更新時は明示 invalidate するため、
            // TTL は「invalidate 経路の無い変更（DB 直接操作等）に対する最大許容ラグ」を表す。
            tenant_cache_ttl: secs(env_parse("TENANT_CACHE_TTL_SECS", 60)?),
            permission_cache_ttl: secs(env_parse("PERMISSION_CACHE_TTL_SECS", 60)?),
            cookie_secure,
            key_encryption_key,
            key_encryption_key_is_dev,
            key_rotation_lead_days: env_parse("KEY_ROTATION_LEAD_DAYS", 30)?,
            trust_forwarded_headers: env_parse("TRUST_FORWARDED_HEADERS", false)?,
            hsts_max_age: env_parse("HSTS_MAX_AGE", 0u64)?,
            internal_service_token,
            internal_service_token_is_dev,
            public_web_base_url,
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
    /// 利用者がブラウザで開く web 画面の公開ベース URL（末尾スラッシュ無し。招待メールの
    /// 承諾リンク等に使う。既定は issuer と同一オリジン。MT17）。
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }
}

fn normalize_issuer(raw: String) -> String {
    raw.trim_end_matches('/').to_string()
}

/// 本番相当（issuer が `https://`）で開発用デフォルトのシークレットが使われていたら起動を失敗させる。
///
/// 開発用デフォルト（`DEV_KEY_ENCRYPTION_KEY`・`DEV_INTERNAL_SERVICE_TOKEN`）はソースに埋め込まれた
/// 既知値であり、本番で使うと署名鍵の暗号化と `/internal/*` の保護が実質無効になる。warning での
/// 見逃しを防ぐため、http（ローカル開発）以外では設定漏れを構成エラーとして扱う。
fn ensure_production_secrets(
    issuer: &str,
    key_encryption_key_is_dev: bool,
    internal_service_token_is_dev: bool,
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

fn env_or(key: &str, default: &str) -> String {
    env_lookup(key).unwrap_or_else(|| default.to_string())
}

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
        assert!(ensure_production_secrets("https://idp.example.com", true, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, true).is_err());
        // 両方明示設定されていれば https でも起動できる。
        assert!(ensure_production_secrets("https://idp.example.com", false, false).is_ok());
        // http（ローカル開発）は開発用デフォルトを許容する（起動時 warning のみ）。
        assert!(ensure_production_secrets("http://localhost:8080", true, true).is_ok());
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
