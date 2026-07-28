//! アプリケーションログ（`log` テーブル。CLAUDE.md「ログ」）。
//!
//! 監査ログ（[`crate::domain::audit`]）が「誰が何をしたか」の業務イベントを残すのに対し、こちらは
//! 「システムが何を失敗したか」の運用情報を残す。記録するのは **WARN / ERROR のみ**で、INFO 以下は
//! stdout の構造化ログに任せる（DB を肥大させないため）。
//!
//! 文言は多言語化せず**運用言語（英語）で統一する**（CLAUDE.md「国際化」の対象外）。PII は含めない。
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 記録対象のログレベル。DB では `VARCHAR` + `CHECK` に保存し、許可値は本 enum で集中管理する
/// （CLAUDE.md「DB モデリング」。DB ネイティブ ENUM は使わない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
        }
    }

    /// 保存文字列（大小無視）から復元する。未知の値は `None`。
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "ERROR" => Some(Self::Error),
            "WARN" | "WARNING" => Some(Self::Warn),
            _ => None,
        }
    }
}

/// ログの出力元サービス（ADR-0007 の api / web 分割）。web は DB を持たないため、自身のログを
/// api の内部エンドポイントへ送って記録する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogService {
    Api,
    Web,
}

impl LogService {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Web => "web",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "api" => Some(Self::Api),
            "web" => Some(Self::Web),
            _ => None,
        }
    }
}

/// 保存する列の長さ上限（DDL と一致させる）。超過分は保存側で切り詰める。
pub const MAX_TARGET_LEN: usize = 255;
pub const MAX_CORRELATION_ID_LEN: usize = 64;
/// `message` / `traceback` は TEXT だが、1 件で DB を圧迫しないよう上限を設ける。
pub const MAX_MESSAGE_LEN: usize = 4_000;
pub const MAX_TRACEBACK_LEN: usize = 8_000;

/// 書き込む 1 件（`tracing` イベントから組み立てる）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationLogRecord {
    pub occurred_at: DateTime<Utc>,
    pub level: LogLevel,
    pub service: LogService,
    pub target: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub traceback: Option<String>,
}

impl ApplicationLogRecord {
    /// 各列を DDL の上限へ収める（超過は末尾を落とす）。文字境界を壊さないよう `char` 単位で切る。
    pub fn truncated(mut self) -> Self {
        self.target = truncate(&self.target, MAX_TARGET_LEN);
        self.message = truncate(&self.message, MAX_MESSAGE_LEN);
        self.correlation_id = self
            .correlation_id
            .map(|v| truncate(&v, MAX_CORRELATION_ID_LEN));
        self.traceback = self.traceback.map(|v| truncate(&v, MAX_TRACEBACK_LEN));
        self
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect()
}

/// `log` から読み出した 1 行（管理コンソールの読み取りモデル）。
///
/// `level` / `service` は保存時の文字列そのままを保持する（過去に廃止された値も欠落なく表示するため、
/// enum へは restrict しない。[`AuditLogEntry`](crate::domain::audit::AuditLogEntry) と同じ方針）。
#[derive(Debug, Clone)]
pub struct ApplicationLogEntry {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub level: String,
    pub service: String,
    pub target: String,
    pub message: String,
    pub correlation_id: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub traceback: Option<String>,
}

/// 検索条件。指定した項目のみ AND で適用する。
#[derive(Debug, Clone, Default)]
pub struct ApplicationLogFilter {
    pub level: Option<LogLevel>,
    pub service: Option<LogService>,
    /// `target` の前方一致（モジュール単位の絞り込み）。
    pub target_prefix: Option<String>,
    pub correlation_id: Option<String>,
    /// 期間の下限・上限（`occurred_at`、含む）。
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// ページング（新しい順）。
    pub limit: i64,
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_levels_case_insensitively() {
        assert_eq!(LogLevel::parse("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse(" WARN "), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("info"), None);
    }

    #[test]
    fn parses_services() {
        assert_eq!(LogService::parse("api"), Some(LogService::Api));
        assert_eq!(LogService::parse("web"), Some(LogService::Web));
        assert_eq!(LogService::parse("worker"), None);
    }

    #[test]
    fn truncates_oversized_fields_on_char_boundaries() {
        let record = ApplicationLogRecord {
            occurred_at: Utc::now(),
            level: LogLevel::Error,
            service: LogService::Api,
            target: "t".repeat(MAX_TARGET_LEN + 10),
            // マルチバイト文字でもバイト境界を割らないこと。
            message: "あ".repeat(MAX_MESSAGE_LEN + 10),
            correlation_id: Some("c".repeat(MAX_CORRELATION_ID_LEN + 10)),
            tenant_id: None,
            traceback: None,
        }
        .truncated();
        assert_eq!(record.target.chars().count(), MAX_TARGET_LEN);
        assert_eq!(record.message.chars().count(), MAX_MESSAGE_LEN);
        assert_eq!(
            record.correlation_id.unwrap().chars().count(),
            MAX_CORRELATION_ID_LEN
        );
    }

    #[test]
    fn keeps_fields_within_limits_untouched() {
        let record = ApplicationLogRecord {
            occurred_at: Utc::now(),
            level: LogLevel::Warn,
            service: LogService::Web,
            target: "idp_web::handlers::login".to_string(),
            message: "login failed".to_string(),
            correlation_id: None,
            tenant_id: None,
            traceback: None,
        };
        assert_eq!(record.clone().truncated(), record);
    }
}
