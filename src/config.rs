//! アプリケーション設定。
//!
//! 設定値の取得は **必ず本モジュール経由**で行う。生の環境変数・DSN を各所で直接参照しない。
//! 優先順位: 環境変数 > DB（system_settings テーブル）> 既定値。
//! MVP では DB 上書きは未実装のため、実質「環境変数 > 既定値」で解決する。
//!
//! 一部の getter（各種 TTL・クロックスキュー）は後続フェーズ（T2〜）で使用するため、
//! 現時点では未使用でも保持する。
#![allow(dead_code)]

use std::env;
use std::time::Duration;

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
    clock_skew: Duration,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            issuer: normalize_issuer(env_or("ISSUER", "http://localhost:8080")),
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
            clock_skew: secs(env_parse("CLOCK_SKEW_SECS", 60)?),
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
    pub fn clock_skew(&self) -> Duration {
        self.clock_skew
    }
}

fn normalize_issuer(raw: String) -> String {
    raw.trim_end_matches('/').to_string()
}

fn secs(v: u64) -> Duration {
    Duration::from_secs(v)
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T>(key: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(key) {
        Ok(v) => v
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
        Err(_) => Ok(default),
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
    fn env_parse_falls_back_to_default_when_unset() {
        // 未設定キーは既定値を返す。
        let v: u64 = env_parse("IDP_TEST_DEFINITELY_UNSET_KEY", 42).unwrap();
        assert_eq!(v, 42);
    }
}
