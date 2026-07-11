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
