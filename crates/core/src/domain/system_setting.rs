//! システム設定（root/idp.system.admin が管理する IdP 全体設定。ADR-0009 §5、MT14）。
//!
//! 設定値の優先順位「環境変数 > DB（system_settings）> 既定値」のうち DB 層を表す。SMTP 等の運用設定を
//! 保持し、MT17（招待メール配送）・MT18（パスワードリセット）が参照する。秘匿値（SMTP パスワード）は
//! `is_secret = true` とし、暗号化して保存する（暗号化・復号は Application 層の責務）。
//!
//! 許可されるキーは本モジュールの定数で集中管理する（`CLAUDE.md`「動的呼び出しの制限」に従い、
//! 文字列の実行時解決ではなく明示的な定数で束ねる）。
#![allow(dead_code)]

/// システム設定 1 レコード（key-value）。`value` は保存形式そのまま（`is_secret` のときは暗号文）。
#[derive(Debug, Clone)]
pub struct SystemSetting {
    pub key: String,
    pub value: String,
    /// `true` のとき `value` は暗号文（AES-256-GCM の base64）。
    pub is_secret: bool,
}

// ── SMTP 設定キー（許可値の単一の出所）─────────────────────────────────────────
pub const SMTP_HOST: &str = "smtp.host";
pub const SMTP_PORT: &str = "smtp.port";
pub const SMTP_USERNAME: &str = "smtp.username";
/// SMTP パスワード（秘匿値。暗号化して保存する）。
pub const SMTP_PASSWORD: &str = "smtp.password";
pub const SMTP_FROM_ADDRESS: &str = "smtp.from_address";
pub const SMTP_USE_TLS: &str = "smtp.use_tls";

// ── ランタイム設定メタデータ（ADR-0010 / CFG1）───────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingOwner {
    Builtin,
    EnvLocked,
    DbManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultRisk {
    Safe,
    Review,
    Dangerous,
}

/// 設定値の型（DB 上書き値の入力検証に使う）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKind {
    /// 非負整数（TTL 秒数・日数等）。
    UnsignedInteger,
    /// 真偽値（`true` / `false`）。
    Boolean,
    /// 自由文字列（URL 等）。
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingDefinition {
    pub key: &'static str,
    pub owner: SettingOwner,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    pub default_value: Option<&'static str>,
    pub kind: SettingKind,
}

pub const RUNTIME_SETTING_DEFINITIONS: &[SettingDefinition] = &[
    SettingDefinition {
        key: "ISSUER",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Text,
        default_value: Some("http://localhost:8080"),
    },
    SettingDefinition {
        key: "BIND_ADDR",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some("0.0.0.0:8080"),
    },
    SettingDefinition {
        key: "DATABASE_URL",
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: Some("mysql://idp:idp@127.0.0.1:3306/idp"),
    },
    SettingDefinition {
        key: "DB_MAX_CONNECTIONS",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("10"),
    },
    SettingDefinition {
        key: "LOG_FORMAT",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some("json"),
    },
    // api と web の両方が消費する値。web が DB 設定を解決/materialize するまでは env locked。
    SettingDefinition {
        key: "AUTH_SESSION_TTL_SECS",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("600"),
    },
    SettingDefinition {
        key: "AUTHORIZATION_CODE_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
    },
    SettingDefinition {
        key: "SSO_IDLE_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("28800"),
    },
    SettingDefinition {
        key: "SSO_ABSOLUTE_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
    },
    SettingDefinition {
        key: "ACCESS_TOKEN_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("900"),
    },
    SettingDefinition {
        key: "ID_TOKEN_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
    },
    SettingDefinition {
        key: "REFRESH_TOKEN_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("2592000"),
    },
    SettingDefinition {
        key: "CLOCK_SKEW_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
    },
    SettingDefinition {
        key: "INVITATION_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("604800"),
    },
    SettingDefinition {
        key: "PASSWORD_RESET_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
    },
    SettingDefinition {
        key: "EMAIL_VERIFICATION_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
    },
    SettingDefinition {
        key: "TENANT_CACHE_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
    },
    SettingDefinition {
        key: "PERMISSION_CACHE_TTL_SECS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
    },
    // api と web の Cookie 属性を一致させる必要があるため、DB materialize までは env locked。
    SettingDefinition {
        key: "COOKIE_SECURE",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Boolean,
        default_value: None,
    },
    SettingDefinition {
        key: "KEY_ENCRYPTION_KEY",
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
    },
    SettingDefinition {
        key: "KEY_ROTATION_LEAD_DAYS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("30"),
    },
    SettingDefinition {
        key: "TRUST_FORWARDED_HEADERS",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
    },
    // api/web の security header を一致させる必要があるため、DB materialize までは env locked。
    SettingDefinition {
        key: "HSTS_MAX_AGE",
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("0"),
    },
    SettingDefinition {
        key: "INTERNAL_SERVICE_TOKEN",
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
    },
    SettingDefinition {
        key: "CSRF_SECRET",
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
    },
    SettingDefinition {
        key: "PUBLIC_WEB_BASE_URL",
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Text,
        default_value: None,
    },
];

pub fn runtime_setting_definition(key: &str) -> Option<&'static SettingDefinition> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .find(|def| def.key == key)
}

/// SMTP（メール配送）設定。参照時は平文パスワードを含めず「設定済みか否か」のみを外へ渡す
/// （[`SmtpSettingsView`]）。更新時は [`UpdateSmtpCommand`] を用いる。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmtpSettingsView {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    /// パスワードが設定済みか（平文は決して外へ出さない）。
    pub password_set: bool,
    pub from_address: String,
    pub use_tls: bool,
}

/// SMTP 設定の更新コマンド。`password` は `None` = 現行を維持、`Some("")` = 消去、`Some(x)` = 設定。
#[derive(Debug, Clone, Default)]
pub struct UpdateSmtpCommand {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub from_address: String,
    pub use_tls: bool,
}
