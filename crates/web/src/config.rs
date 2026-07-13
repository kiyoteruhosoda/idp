//! web サービスの設定（ADR-0007）。
//!
//! web は DB を持たないため、api とは別の（小さな）設定を持つ。取得は必ず本モジュール経由で行い、
//! 生の環境変数を各所で直接参照しない。優先順位は「環境変数 > 既定値」。
//! （空文字列は「未設定」として扱う。Compose の `${VAR:-}` 対策は api の config と同じ方針。）
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use std::env;

/// 内部サービス認証トークンの開発用デフォルト（api 側と同値。ADR-0007 §5）。
/// 本番では必ず `INTERNAL_SERVICE_TOKEN` を api と共有の値で設定する。
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";
/// CSRF シークレットの開発用デフォルト（api 側 `DEV_CSRF_SECRET` と同値。32 バイト）。
/// 本番では必ず `CSRF_SECRET` を api と共有の base64 値で設定する。
const DEV_CSRF_SECRET: &[u8; 32] = b"idp-dev-insecure-csrf-secret-xxx";
/// `auth_session_id` Cookie のデフォルト TTL（秒）。api 側と合わせる（600 秒 = 10 分）。
const DEFAULT_AUTH_SESSION_TTL_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone)]
pub struct Config {
    bind_addr: String,
    api_base_url: String,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    cookie_secure: bool,
    auth_session_ttl_secs: u64,
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない（api 側と同キー `HSTS_MAX_AGE`）。
    hsts_max_age: u64,
    log_format: LogFormat,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        // 外部から見た issuer（Cookie の Secure 判定に使う。既定は http のローカル）。
        let issuer = normalize_issuer(env_or("ISSUER", "http://localhost:8080"));
        let cookie_secure = env_parse("COOKIE_SECURE", issuer.starts_with("https://"))?;
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (v, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // 本番（https issuer）では開発用デフォルトのトークンで起動しない（fail-fast。api 側と同方針）。
        ensure_production_secrets(&issuer, internal_service_token_is_dev, csrf_secret_is_dev)?;
        Ok(Self {
            bind_addr: env_or("WEB_BIND_ADDR", "0.0.0.0:8081"),
            // api への到達先。単一オリジン構成ではプロキシ内部アドレス、ローカルでは api の直アドレス。
            api_base_url: normalize_base_url(env_or("API_BASE_URL", "http://localhost:8080")),
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            cookie_secure,
            auth_session_ttl_secs: env_parse("AUTH_SESSION_TTL_SECS", DEFAULT_AUTH_SESSION_TTL_SECS)?,
            hsts_max_age: env_parse("HSTS_MAX_AGE", 0u64)?,
            log_format: match env_or("LOG_FORMAT", "json").to_ascii_lowercase().as_str() {
                "pretty" => LogFormat::Pretty,
                _ => LogFormat::Json,
            },
        })
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }
    /// api のベース URL（末尾スラッシュ無し）。API クライアントが各エンドポイントへ結合する。
    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }
    /// web→api の `/internal/*` 呼び出しに付与するサービス認証トークン（ADR-0007 §5）。
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    /// CSRF トークン署名鍵（HMAC-SHA256 用）。api と同じ `CSRF_SECRET` を共有する。
    pub fn csrf_secret(&self) -> &[u8; 32] {
        &self.csrf_secret
    }
    pub fn csrf_secret_is_dev(&self) -> bool {
        self.csrf_secret_is_dev
    }
    /// web が組み立てる Cookie に `Secure` を付けるか（api の応答値を Cookie 化する際に使う）。
    pub fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }
    /// `auth_session_id` Cookie の TTL（秒）。api 側の `AUTH_SESSION_TTL_SECS` と合わせる。
    pub fn auth_session_ttl_secs(&self) -> u64 {
        self.auth_session_ttl_secs
    }
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない。
    pub fn hsts_max_age(&self) -> u64 {
        self.hsts_max_age
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
}

fn normalize_issuer(raw: String) -> String {
    raw.trim_end_matches('/').to_string()
}

/// 本番相当（issuer が `https://`）で開発用デフォルトのシークレットが使われていたら起動を失敗させる。
fn ensure_production_secrets(
    issuer: &str,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    if issuer.starts_with("https://") && internal_service_token_is_dev {
        anyhow::bail!(
            "ISSUER is https ({issuer}) but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with api) in production."
        );
    }
    if issuer.starts_with("https://") && csrf_secret_is_dev {
        anyhow::bail!(
            "ISSUER is https ({issuer}) but CSRF_SECRET is not set; \
             refusing to start with the built-in development secret. \
             Set CSRF_SECRET (base64, 32 bytes, shared with api) in production."
        );
    }
    Ok(())
}

/// `CSRF_SECRET`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => {
            let bytes = STANDARD
                .decode(&v)
                .map_err(|e| anyhow::anyhow!("CSRF_SECRET must be base64: {e}"))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("CSRF_SECRET must decode to exactly 32 bytes"))?;
            Ok((arr, false))
        }
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

fn normalize_base_url(raw: String) -> String {
    raw.trim_end_matches('/').to_string()
}

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
    fn base_url_is_normalized_without_trailing_slash() {
        assert_eq!(
            normalize_base_url("http://api:8080/".to_string()),
            "http://api:8080"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        assert!(ensure_production_secrets("https://idp.example.com", true, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, true).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, false).is_ok());
        assert!(ensure_production_secrets("http://localhost:8080", true, true).is_ok());
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let key = "IDP_WEB_TEST_EMPTY";
        std::env::set_var(key, "");
        assert_eq!(env_or(key, "fallback"), "fallback");
        std::env::remove_var(key);
    }
}


