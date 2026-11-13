//! Application log (`log` table. CLAUDE.md "Logs").
//!
//! Whereas the audit log ([`crate::domain::audit`]) records business events of "who did what", this records
//! operational information of "what the system failed at". Only **WARN / ERROR** are recorded; INFO and below are
//! left to structured stdout logs (to avoid bloating the DB).
//!
//! Messages are not localized and are **unified in the operating language (English)** (outside the scope of CLAUDE.md "i18n"). No PII.
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Log levels to record. Stored in the DB as `VARCHAR` + `CHECK`, with allowed values managed centrally by this enum
/// (CLAUDE.md "DB modeling". DB-native ENUMs are not used).
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

    /// Restores from the stored string (case-insensitive). Unknown values give `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "ERROR" => Some(Self::Error),
            "WARN" | "WARNING" => Some(Self::Warn),
            _ => None,
        }
    }
}

/// The service that emitted the log (the api / web split of ADR-0007). The web has no DB, so it sends its own logs
/// to an internal api endpoint to be recorded.
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

/// Length limits of stored columns (kept in sync with the DDL). Excess is truncated on save.
pub const MAX_TARGET_LEN: usize = 255;
pub const MAX_CORRELATION_ID_LEN: usize = 64;
/// `message` / `traceback` are TEXT, but have a limit so one entry does not overwhelm the DB.
pub const MAX_MESSAGE_LEN: usize = 4_000;
pub const MAX_TRACEBACK_LEN: usize = 8_000;

/// One entry to write (built from a `tracing` event).
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
    /// Fits each column within the DDL limit (drops the tail on overflow). Cuts per `char` so as not to break character boundaries.
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

/// One row read from `log` (the admin console's read model).
///
/// `level` / `service` keep the stored string as is (not restricted to the enum, so that values retired in the past are still shown;
/// same policy as [`AuditLogEntry`](crate::domain::audit::AuditLogEntry)).
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

/// Search conditions. Only the specified items are applied, combined with AND.
#[derive(Debug, Clone, Default)]
pub struct ApplicationLogFilter {
    pub level: Option<LogLevel>,
    pub service: Option<LogService>,
    /// Prefix match on `target` (narrowing by module).
    pub target_prefix: Option<String>,
    pub correlation_id: Option<String>,
    /// Lower and upper bounds of the period (`occurred_at`, inclusive).
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Paging (newest first).
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
            // Must not split byte boundaries even with multibyte characters.
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
            target: "assay_web::handlers::login".to_string(),
            message: "login failed".to_string(),
            correlation_id: None,
            tenant_id: None,
            traceback: None,
        };
        assert_eq!(record.clone().truncated(), record);
    }
}
