//! システム設定（root/idp.system.admin が管理する IdP 全体設定。ADR-0009 §5、MT14）。
//!
//! 設定値の優先順位は「組み込み既定値 < 環境変数（ENV）< DB（system_settings）」。あとから DB で上書き
//! できるという思想で、より運用に近い層（DB）を優先する（ADR-0010 の DB_MANAGED は DB を正とする）。
//! 本モジュールはその DB 層を表す。SMTP 等の運用設定を保持し、MT17（招待メール配送）・
//! MT18（パスワードリセット）が参照する。秘匿値（SMTP パスワード）は `is_secret = true` とし、
//! 暗号化して保存する（暗号化・復号は Application 層の責務）。
//!
//! 例外として、DB を読む前や DB 内 secret の復号に必要な bootstrap 系（DB 接続情報・
//! `KEY_ENCRYPTION_KEY`・`CSRF_SECRET` 等）と、api/web で値を一致させる必要があるキーは `EnvLocked`
//! とし、DB 上書きを受け付けず ENV（無ければ既定値）を用いる（ADR-0010 §2）。
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
    /// api と web の**両方**が消費する値か（MT26 / ADR-0013）。web は DB を持たないため、
    /// `true` かつ `DbManaged` のキーは起動時に api の `/internal/runtime-settings` から
    /// DB 上書き値を取得して解決する。`EnvLocked` の共有キー（`CSRF_SECRET` 等）は
    /// DB 上書き自体が無いので `false`。
    pub shared_with_web: bool,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    pub default_value: Option<&'static str>,
    pub kind: SettingKind,
    /// この設定が何に使われるかの説明（設定画面に表示する運用者向けの一文）。運用言語（日本語）で統一する。
    pub description: &'static str,
}

pub const RUNTIME_SETTING_DEFINITIONS: &[SettingDefinition] = &[
    SettingDefinition {
        key: "ISSUER",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Text,
        default_value: Some("http://localhost:8080"),
        description: "OIDC issuer。発行する ID Token / アクセストークンの `iss` と各種メタデータの \
                      基底 URL になる。デプロイ先の公開 URL に一致させる。",
    },
    SettingDefinition {
        key: "BIND_ADDR",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some("0.0.0.0:8080"),
        description: "HTTP サーバが listen する bind アドレスとポート。",
    },
    SettingDefinition {
        key: "DATABASE_URL",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: Some("mysql://idp:idp@127.0.0.1:3306/idp"),
        description: "MariaDB への接続 DSN。DB を読む前に必要な bootstrap 値のため DB 上書き不可。",
    },
    SettingDefinition {
        key: "DB_MAX_CONNECTIONS",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("10"),
        description: "sqlx 接続プールの最大接続数。DB 負荷とスループットの上限を決める。",
    },
    SettingDefinition {
        key: "LOG_FORMAT",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some("json"),
        description: "ログ出力形式（`json` = 構造化ログ / `pretty` = 開発向け整形）。",
    },
    // api と web の両方が消費する値（MT26 / ADR-0013）。web は起動時に api から DB 上書き値を
    // 取得して解決するため DB 管理できる。反映には api・web 双方の再起動が必要。
    SettingDefinition {
        key: "AUTH_SESSION_TTL_SECS",
        shared_with_web: true,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("600"),
        description: "認可フロー中の一時ログインセッション（auth_session）の有効期限（秒）。\
                      ログイン〜同意完了までに許す時間。api・web の両方が使うため、変更の反映には\
                      両サービスの再起動が必要。",
    },
    SettingDefinition {
        key: "AUTHORIZATION_CODE_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "認可コードの有効期限（秒）。code をトークンに交換できる猶予。短いほど安全。",
    },
    SettingDefinition {
        key: "SSO_IDLE_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("28800"),
        description: "SSO セッションのアイドルタイムアウト（秒）。無操作でログイン状態が切れるまでの時間。",
    },
    SettingDefinition {
        key: "SSO_ABSOLUTE_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "SSO セッションの絶対上限（秒）。操作の有無に関わらず再ログインを要求するまでの時間。",
    },
    SettingDefinition {
        key: "ACCESS_TOKEN_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("900"),
        description: "アクセストークンの有効期限（秒）。API 呼び出しに使うトークンの寿命。",
    },
    SettingDefinition {
        key: "ID_TOKEN_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
        description: "ID Token の有効期限（秒）。RP がユーザー認証結果として検証する JWT の寿命。",
    },
    SettingDefinition {
        key: "REFRESH_TOKEN_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("2592000"),
        description: "リフレッシュトークンの有効期限（秒）。`offline_access` で発行し、\
                      アクセストークンの再取得に使う（既定 30 日）。",
    },
    SettingDefinition {
        key: "CLOCK_SKEW_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "トークン検証で許容する時刻ずれ（秒）。`nbf` / `exp` 判定のサーバ間クロックスキュー吸収。",
    },
    SettingDefinition {
        key: "INVITATION_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("604800"),
        description: "ゲスト招待トークンの有効期限（秒）。招待メールの承諾リンクが使える期間（既定 7 日）。",
    },
    SettingDefinition {
        key: "PASSWORD_RESET_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
        description: "パスワードリセットトークンの有効期限（秒）。リセットメールのリンクが使える期間。",
    },
    SettingDefinition {
        key: "EMAIL_VERIFICATION_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "メール検証トークンの有効期限（秒）。確認メールのリンクが使える期間。",
    },
    SettingDefinition {
        key: "TENANT_CACHE_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "テナント解決（id → tenant）キャッシュの TTL（秒）。ホットパスの DB 参照を減らす。",
    },
    SettingDefinition {
        key: "PERMISSION_CACHE_TTL_SECS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "scope→権限解決キャッシュの TTL（秒）。付与・剥奪時は即時 invalidate される。",
    },
    // api と web の Cookie 属性を一致させる必要がある共有キー（MT26 / ADR-0013）。DB 値は両サービスが
    // 同じ経路（api の /internal/runtime-settings）から受け取るため、DB 管理でも属性がずれない。
    // 未設定時の既定は各サービスが**自分の公開オリジンのスキーム**から導く（ADR-0012 §2）。
    SettingDefinition {
        key: "COOKIE_SECURE",
        shared_with_web: true,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Boolean,
        default_value: None,
        description: "セッション Cookie に `Secure` 属性を付けるか。HTTPS 配置では `true` 必須。\
                      api・web の両方が使うため、変更の反映には両サービスの再起動が必要。",
    },
    SettingDefinition {
        key: "KEY_ENCRYPTION_KEY",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
        description: "署名鍵（SigningKeys.private_key_encrypted）を暗号化する 32 バイト鍵。\
                      DB 内 secret の復号に必要な bootstrap 値のため DB 上書き不可。",
    },
    SettingDefinition {
        key: "KEY_ROTATION_LEAD_DAYS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("30"),
        description: "署名鍵ローテーションの先行日数。`not_after` のこの日数前に次期鍵を生成し旧鍵を退役させる。",
    },
    SettingDefinition {
        key: "TRUST_FORWARDED_HEADERS",
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "リバースプロキシの `X-Forwarded-For` / `X-Forwarded-Proto` を信頼するか。\
                      信頼できるプロキシ配下でのみ `true` にする（クライアント IP・スキーム判定に影響）。",
    },
    // api/web の security header を一致させる必要がある共有キー（MT26 / ADR-0013）。
    SettingDefinition {
        key: "HSTS_MAX_AGE",
        shared_with_web: true,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("0"),
        description: "HSTS レスポンスヘッダの `max-age`（秒）。0 で HSTS を付与しない。HTTPS 配置では\
                      正の値を設定。api・web の両方が使うため、変更の反映には両サービスの再起動が必要。",
    },
    SettingDefinition {
        key: "INTERNAL_SERVICE_TOKEN",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
        description: "web→api の `/internal/*` 呼び出しを保護する共有トークン。api/web で一致必須のため DB 上書き不可。",
    },
    SettingDefinition {
        key: "CSRF_SECRET",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
        description: "CSRF トークンを導出する HMAC 鍵（32 バイト）。api/web で一致必須のため DB 上書き不可。",
    },
    // api（相手の URL としてリダイレクト・メールリンクに使う）と web（自オリジンとして Secure 判定・
    // 絶対 URL 生成に使う）で同一値必須のため EnvLocked（ADR-0012 §2。DbManaged から変更）。
    SettingDefinition {
        key: "PUBLIC_WEB_BASE_URL",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Text,
        default_value: None,
        description: "利用者がブラウザで開く web 画面の公開ベース URL。api は /authorize からログイン・\
                      同意画面への 302 とメールリンク生成に、web は自オリジンとして使う。api/web で\
                      一致必須のため DB 上書き不可。未設定なら issuer と同一オリジン。",
    },
    // api/web の Cookie 属性を一致させる必要があるため EnvLocked（ADR-0012 §2）。
    SettingDefinition {
        key: "COOKIE_DOMAIN",
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: None,
        description: "サービス横断 Cookie（sso_session_id・auth_session_id）に付与する Domain 属性\
                      （例 `example.com`）。api/web を別サブドメインで公開する構成でのみ設定する。\
                      未設定 = host-only（単一オリジン構成の従来挙動）。",
    },
];

pub fn runtime_setting_definition(key: &str) -> Option<&'static SettingDefinition> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .find(|def| def.key == key)
}

/// api と web の両方が消費する DB 管理キー（MT26 / ADR-0013）。api はこの一覧の DB 上書き値だけを
/// `/internal/runtime-settings` で web へ渡す。secret は決して共有しない（web は bootstrap secret を
/// 自分の ENV から読む）。
pub fn shared_with_web_setting_keys() -> impl Iterator<Item = &'static str> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .filter(|def| def.shared_with_web && !def.secret)
        .map(|def| def.key)
}

/// 指定キーが web と共有する DB 管理キーか。
pub fn is_shared_with_web(key: &str) -> bool {
    runtime_setting_definition(key)
        .map(|def| def.shared_with_web && !def.secret)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// web と共有するキーは DB 上書きを受け付けられなければ意味が無い（`EnvLocked` のまま
    /// `shared_with_web` を立てると、api は DB 値を無視するのに web へは配れる、という不整合になる）。
    #[test]
    fn shared_with_web_keys_are_db_managed_and_not_secret() {
        for def in RUNTIME_SETTING_DEFINITIONS
            .iter()
            .filter(|def| def.shared_with_web)
        {
            assert_eq!(
                def.owner,
                SettingOwner::DbManaged,
                "{} is shared with web but not DB-managed",
                def.key
            );
            assert!(!def.secret, "{} is shared with web but secret", def.key);
        }
    }

    /// 定義キーの重複は「どちらが効くか」が探索順に依存する事故になるため禁止する。
    #[test]
    fn runtime_setting_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for def in RUNTIME_SETTING_DEFINITIONS {
            assert!(seen.insert(def.key), "duplicate setting key: {}", def.key);
        }
    }
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
