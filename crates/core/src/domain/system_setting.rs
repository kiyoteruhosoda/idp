//! System settings (assay-wide settings managed by root/idp.system.admin; ADR-0009 §5, MT14).
//!
//! Precedence of setting values is "built-in default < environment variable (ENV) < DB
//! (system_settings)". Following the idea that the DB can override later, the layer closer to
//! operations (DB) wins (ADR-0010's DB_MANAGED treats the DB as authoritative). This module
//! represents that DB layer. It holds operational settings such as SMTP, referenced by MT17
//! (invitation mail delivery) and MT18 (password reset). Secrets (SMTP password) have
//! `is_secret = true` and are stored encrypted (encryption / decryption is the Application layer's
//! job).
//!
//! As exceptions, bootstrap values needed before reading the DB or to decrypt DB secrets (DB
//! connection info, `KEY_ENCRYPTION_KEY`, `CSRF_SECRET`, etc.) and keys whose values must match
//! between api/web are `EnvLocked`; they accept no DB override and use ENV (or the default if
//! absent) (ADR-0010 §2).
//!
//! Allowed keys are managed centrally as constants in this module (per `CLAUDE.md` "Restricting
//! dynamic calls", bundled as explicit constants rather than runtime string resolution).
#![allow(dead_code)]

/// One system setting record (key-value). `value` is in stored form (ciphertext when `is_secret`).
#[derive(Debug, Clone)]
pub struct SystemSetting {
    pub key: String,
    pub value: String,
    /// When `true`, `value` is ciphertext (base64 of AES-256-GCM).
    pub is_secret: bool,
}

// ── SMTP setting keys (single source of allowed values) ──────────────────────────────────
pub const SMTP_HOST: &str = "smtp.host";
pub const SMTP_PORT: &str = "smtp.port";
pub const SMTP_USERNAME: &str = "smtp.username";
/// SMTP password (secret; stored encrypted).
pub const SMTP_PASSWORD: &str = "smtp.password";
pub const SMTP_FROM_ADDRESS: &str = "smtp.from_address";
pub const SMTP_USE_TLS: &str = "smtp.use_tls";

// ── SMS gateway setting keys (AP13; single source of allowed values) ─────────────────────
/// URL to POST send requests to. Empty = SMS sending disabled.
pub const SMS_GATEWAY_URL: &str = "sms.gateway_url";
/// Auth header name (e.g. `Authorization`). Empty = no auth header.
pub const SMS_AUTH_HEADER: &str = "sms.auth_header";
/// Auth header value (secret; stored encrypted).
pub const SMS_AUTH_TOKEN: &str = "sms.auth_token";
/// Sender display (the value a provider treats as `sender id` / `from`). Empty = unspecified.
pub const SMS_SENDER_ID: &str = "sms.sender_id";

// ── Runtime setting metadata (ADR-0010 / CFG1) ───────────────────────────────

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

/// Type of a setting value (used to validate DB override input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingKind {
    /// Non-negative integer (TTL seconds, days, etc.).
    UnsignedInteger,
    /// Boolean (`true` / `false`).
    Boolean,
    /// Free-form string.
    Text,
    /// Public base URL of a service (`ISSUER` etc.). Must be an absolute URL with a scheme and
    /// host.
    PublicBaseUrl,
    /// Choose one of fixed values. Values not among the choices are refused at save time (even if
    /// saved, `Config` would fail at the next startup).
    Choice(&'static [SettingChoice]),
}

/// One choice of a [`SettingKind::Choice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingChoice {
    pub value: &'static str,
    /// Whether this value could lock out the users of that tenant (all tenants if global).
    ///
    /// When switching to a `true` value, **a confirmation is inserted before saving** (ADR-0058;
    /// not repeating #63). Whether a confirmation is needed is decided only from here, never by
    /// branching on key names — when someone adding a key writes the choices, the screen and API
    /// confirmation come with it.
    pub locks_out: bool,
}

impl SettingDefinition {
    /// Whether a confirmation should be inserted before saving when changing to `value` (decided
    /// only by the definition's [`SettingChoice::locks_out`]).
    pub fn needs_confirmation(&self, value: &str) -> bool {
        match self.kind {
            SettingKind::Choice(choices) => choices
                .iter()
                .any(|choice| choice.value == value && choice.locks_out),
            _ => false,
        }
    }
}

/// Unit of a setting — one for the whole IdP, or overridable by tenants (ADR-0058 §3).
///
/// It is an **orthogonal axis** to the source ([`SettingOwner`]). The source says "where the value
/// comes from", the unit says "whose decision it is". There is only one criterion: ⚠ **"does it
/// break unless there is one for the whole IdP"** (if not, move it down). Do not split by "whether
/// root wants to keep hold of it".
///
/// It is a required field of the definition, so anyone adding a key must choose one — no shape
/// where keys silently keep being added as global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingScope {
    /// One for the whole IdP. Tenants cannot change it (issuer, cookies, deployment, process
    /// behavior, token lifetimes; ADR-0058 §5, §7).
    Global,
    /// Tenants can override it. ⚠ **A tenant having no row means "follow the global value"**
    /// (ADR-0058 §2).
    TenantOverridable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingDefinition {
    pub key: &'static str,
    /// Unit (ADR-0058 §3). Only `TenantOverridable` can be written to the tenant table
    /// (`tenant_settings`).
    pub scope: SettingScope,
    pub owner: SettingOwner,
    /// Whether the value is consumed by **both** api and web (MT26 / ADR-0013). web has no DB, so
    /// keys that are `true` and `DbManaged` are resolved at startup by fetching DB overrides from
    /// api's `/internal/runtime-settings`. Shared `EnvLocked` keys (`CSRF_SECRET` etc.) have no DB
    /// override at all, so they are `false`.
    pub shared_with_web: bool,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    pub default_value: Option<&'static str>,
    pub kind: SettingKind,
    /// Description of what this setting is used for (one sentence for operators shown on the
    /// settings screen). Kept in the operations language (Japanese).
    pub description: &'static str,
}

pub const RUNTIME_SETTING_DEFINITIONS: &[SettingDefinition] = &[
    // Consumed by both api and web (web uses it for its own origin when `PUBLIC_WEB_BASE_URL` is
    // unset and to validate `COOKIE_DOMAIN`). Moved from `EnvLocked` to DB-managed in ADR-0017.
    SettingDefinition {
        key: "ISSUER",
        scope: SettingScope::Global,
        shared_with_web: true,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::PublicBaseUrl,
        default_value: Some("http://localhost:8080"),
        description: "OIDC issuer。発行する ID Token / アクセストークンの `iss` と、ディスカバリ \
                      文書（`/.well-known/openid-configuration`）に載る各エンドポイント URL の基底に \
                      なる。ブラウザと RP から見た api の公開 URL に一致させる。api・web の両方が \
                      使うため、変更の反映には両サービスの再起動が必要。**変更すると RP 側にも \
                      新しい issuer の設定（discovery・`iss` 検証・SAML メタデータ再取り込み）が \
                      要る。**",
    },
    SettingDefinition {
        key: "BIND_ADDR",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some("json"),
        description: "ログ出力形式（`json` = 構造化ログ / `pretty` = 開発向け整形）。",
    },
    // A value consumed by both api and web (MT26 / ADR-0013). web fetches DB overrides from api at
    // startup to resolve it, so it can be DB-managed. Applying it needs restarts of both api and
    // web.
    SettingDefinition {
        key: "AUTH_SESSION_TTL_SECS",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("28800"),
        description: "SSO セッションのアイドルタイムアウト（秒）。無操作でログイン状態が切れるまでの時間。",
    },
    SettingDefinition {
        key: "SSO_ABSOLUTE_TTL_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "SSO セッションの絶対上限（秒）。操作の有無に関わらず再ログインを要求するまでの時間。",
    },
    SettingDefinition {
        key: "SSO_BOUND_TTL_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("2592000"),
        description: "端末の鍵に結び付いた SSO セッション（Chrome の DBSC）の長さ（秒。task #887）。結び付いていて、\
                      かつその端末を利用者が「自分の端末」に登録しているときだけ、作った時刻から数えてこの長さにする \
                      （使わなくても切れない）。それ以外は `SSO_ABSOLUTE_TTL_SECS`。`SSO_ABSOLUTE_TTL_SECS` より \
                      短くしても延ばさないだけで、縮めはしない。",
    },
    SettingDefinition {
        key: "ACCESS_TOKEN_TTL_SECS",
        scope: SettingScope::Global,
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
        key: "MANAGEMENT_TOKEN_TTL_SECS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("300"),
        description: "管理 API のアクセストークンの有効期限（秒）。IdP 自身を操作するトークンの寿命で、通常のアクセストークンより短く保つ。",
    },
    SettingDefinition {
        key: "ID_TOKEN_TTL_SECS",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("604800"),
        description: "ゲスト招待トークンの有効期限（秒）。招待メールの承諾リンクが使える期間（既定 7 日）。",
    },
    SettingDefinition {
        key: "ACCOUNT_SETUP_TTL_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "アカウント設定リンクの有効期限（秒）。管理者が利用者を作った・パスワードを\
                      再発行したときに渡す、パスワードの設定とパスキーの登録ができるリンクが\
                      使える期間（既定 24 時間）。",
    },
    SettingDefinition {
        key: "PASSWORD_RESET_TTL_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
        description: "パスワードリセットトークンの有効期限（秒）。リセットメールのリンクが使える期間。",
    },
    SettingDefinition {
        key: "PASSWORD_RESET_CONSOLE_LINK_ENABLED",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Boolean,
        default_value: Some("true"),
        description: "SMTP で送れないとき、パスワードリセットのリンクをサーバのコンソール\
                      （標準出力。`docker logs`）へ出すか。メール配送が無い環境で、パスワードを\
                      忘れた管理者が自力で復旧するための唯一の経路になる。リンクを見られた者は\
                      その利用者のパスワードを再設定できるため、コンソール出力を運用者以外が\
                      読める環境では無効にする。SMTP を設定するとメール配送が優先されるが、\
                      **SMTP 設定の読み出しに失敗したとき（DB 障害・KEY_ENCRYPTION_KEY 不一致で\
                      パスワードを復号できない等）も、復旧手段を残すためコンソールへ出す**。\
                      メール配送を設定した環境でもコンソールに出ることがあるため、\
                      「SMTP を設定したから出ない」とは考えない。",
    },
    SettingDefinition {
        key: "EMAIL_VERIFICATION_TTL_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "メール検証トークンの有効期限（秒）。確認メールのリンクが使える期間。",
    },
    SettingDefinition {
        key: "TENANT_CACHE_TTL_SECS",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "scope→権限解決キャッシュの TTL（秒）。付与・剥奪時は即時 invalidate される。",
    },
    // Account lockout policy (user authentication / auth policy spec §17). Makes the previously
    // hard-coded "10 failures / 15-minute lock" adjustable in operations. Applies uniformly to all
    // paths: OIDC login, portal login, and admin console login.
    SettingDefinition {
        key: "LOGIN_MAX_FAILED_ATTEMPTS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("10"),
        description: "アカウントロックまでの連続ログイン失敗の許容回数。成功でリセットされる。",
    },
    SettingDefinition {
        key: "LOGIN_LOCK_DURATION_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("900"),
        description: "連続失敗でロックした際のロック時間（秒）。経過後は自動で再試行できる（恒久ロックはしない）。",
    },
    SettingDefinition {
        key: "LOGIN_MAX_LOCK_DURATION_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("86400"),
        description: "段階的ロックの上限（秒。AP6）。ロック時間は失敗が重なるたびに \
                      `LOGIN_LOCK_DURATION_SECS` から倍々で伸び、この値で頭打ちになる。\
                      `LOGIN_LOCK_DURATION_SECS` 以下にすると段階化しない（従来どおりの固定時間）。",
    },
    // ── Password policy (AP7; spec §11.2) ────────────────────────────── Applies uniformly to
    // every path that sets a password (self-registration, forced change, self-service change,
    // reset).
    SettingDefinition {
        key: "PASSWORD_MIN_LENGTH",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("8"),
        description: "新しいパスワードに要求する最小文字数（バイト長で判定する）。既存のパスワードは \
                      次の変更まで再判定されない。",
    },
    SettingDefinition {
        key: "PASSWORD_HISTORY_COUNT",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("5"),
        description: "再利用を禁じる直近パスワードの数（**現行を含む**）。`1` は現行と同じ値だけを \
                      拒否し、`0` は履歴を見ない。退役したハッシュはこの件数だけ保持し、超えた分は \
                      削除する。",
    },
    SettingDefinition {
        key: "PASSWORD_MAX_AGE_DAYS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("0"),
        description: "パスワードの有効日数。経過後は**次のログインで**パスワード変更画面へ誘導する \
                      （ログイン自体は拒否しない）。`0` は無期限。設定時刻が未記録の利用者は \
                      アカウント作成時刻を起点に測る。",
    },
    SettingDefinition {
        key: "PASSWORD_BREACH_CHECK_ENABLED",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "漏えい済みパスワードを拒否するか。有効にすると `PASSWORD_BREACH_API_BASE_URL` \
                      への外向き HTTPS が必要になる（送るのは SHA-1 の先頭 5 桁のみ。パスワードも \
                      利用者も渡らない）。照合先へ到達できないときは拒否せずに通す。",
    },
    SettingDefinition {
        key: "PASSWORD_BREACH_API_BASE_URL",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(crate::domain::password_policy::DEFAULT_BREACH_API_BASE_URL),
        description: "漏えい済みパスワードの照合先（k-匿名性のレンジ API）。`{base}/{接頭辞5桁}` を \
                      GET する。閉じた環境では互換のミラーを立ててここを向ける。",
    },
    SettingDefinition {
        key: "UNREGISTERED_DEVICE_ALERTS_ENABLED",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "利用者が登録していない端末（ブラウザ）でログインしたとき、運用者の知らせの宛先へ \
                      知らせるか（task #872）。利用者は「アカウントのセキュリティ」→「端末」でいつも使う \
                      端末を登録でき、登録した端末では鳴らない。端末の登録・取り消し・期限切れもこれが \
                      有効なテナントだけ知らせる。送り先は `SECURITY_ALERT_WEBHOOK_URL`（環境変数）。\
                      出来事は有効・無効にかかわらず監査ログに残る。",
    },
    SettingDefinition {
        key: "REGISTERED_DEVICE_REQUIRED",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "登録した端末からだけログインできるようにするか（task #916・ADR-0079）。有効にすると、\
                      この組織に属する利用者は、登録した端末（ブラウザ）か認証アプリの承認でしかログインを \
                      終えられない。登録していない端末で正しく入ろうとすると、パスキーで確かめてその端末を \
                      登録する画面へ進む（パスキーが無ければ入れない）。家の中か外かは見分けない。⚠ 有効に \
                      する前に、全員がいつもの端末を登録していることを確かめる（登録していない人が居るうちは \
                      有効にできない）。",
    },
    SettingDefinition {
        key: "SSH_KEYS_ENABLED",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "利用者が「アカウントのセキュリティ」→「SSH の鍵」で sk 型の SSH 公開鍵を登録できるか \
                      （task #885。ADR-0072）。登録した鍵は、`idp.ssh-keys:read` を持つ機械クライアントが \
                      `GET /{tenant}/admin/ssh-keys` で読み、各機器へ配る。無効の組織では画面に出ず、口は空の \
                      一覧を返す（登録済みの鍵は消さない）。登録・取り消しは監査ログに残り、\
                      `SECURITY_ALERT_WEBHOOK_URL` があれば知らせる。",
    },
    SettingDefinition {
        key: "OUTBOUND_TRUSTED_HOSTS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "外へ送る要求（バックチャネルログアウト・外部 IdP）で、名前を引いた結果が内部の住所でも \
                      送ってよい名前（カンマ区切り。`example.com` は `*.example.com` も含む。task #585）。\
                      既定は空（内部の住所に引ける宛先へは送らない）。公開名が内側の前段へ引ける配置 \
                      （split DNS）でだけ、その公開ドメインを書く。",
    },
    SettingDefinition {
        key: "PASSWORD_BREACH_CHECK_TIMEOUT_SECS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3"),
        description: "漏えい照合の 1 リクエストの上限時間（秒）。超えたら拒否せずに通す（外部の \
                      不調でパスワード変更が止まらないようにする）。",
    },
    // Default effect when no authentication policy (authentication_policies) matches (same spec
    // §9.4).
    SettingDefinition {
        key: "AUTH_POLICY_DEFAULT_EFFECT",
        // Decided by the tenant (ADR-0058 §4). api reads the tenant's value on every lookup.
        scope: SettingScope::TenantOverridable,
        // ⚠ Not distributed to web (ADR-0058 §10). When the admin console (AP1) shows the default
        // effect above the list, it draws the tenant's value carried in api's list response. A
        // startup snapshot cannot represent per-tenant values.
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Choice(&[
            SettingChoice { value: "allow", locks_out: false },
            SettingChoice { value: "deny", locks_out: true },
        ]),
        default_value: Some("allow"),
        description: "認証ポリシーが 1 件も一致しない場合の既定動作（`allow` / `deny`）。`deny` にすると\
                      許可ポリシーを明示したクライアント・ユーザーしかログインできなくなるため注意。",
    },
    // How far the app assignment check goes (phased rollout of ADR-0054).
    SettingDefinition {
        key: "APPLICATION_ASSIGNMENT_ENFORCEMENT",
        // Decided by the tenant (ADR-0058 §4). Tenants whose rosters are ready can flip to
        // `enforce`.
        scope: SettingScope::TenantOverridable,
        // Not distributed to web (web's code never read it; ADR-0058 §10). The app list's "only
        // recording for now" is drawn from the tenant's value in api's response (`enforcement`).
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Choice(&[
            SettingChoice { value: "record_only", locks_out: false },
            SettingChoice { value: "enforce", locks_out: true },
        ]),
        default_value: Some("record_only"),
        description: "アプリの利用者割り当ての判定をどこまでやるか（`record_only` / `enforce`）。\
                      `record_only` は判定を走らせるが断らず、「割り当てが無いのに来た人」を監査ログ\
                      （`application.access_denied` の成功行）へ残す。**移行の漏れが無いことを\
                      ログで確かめてから** `enforce` にすること。⚠ `enforce` にした瞬間、名簿に\
                      載っていない利用者は「個別」のアプリへ入れなくなる。",
    },
    // Shared keys whose cookie attributes must match between api and web (MT26 / ADR-0013). Both
    // services receive the DB value through the same route (api's /internal/runtime-settings), so
    // attributes do not diverge even when DB-managed. When unset, each service derives the default
    // from **the scheme of its own public origin** (ADR-0012 §2).
    SettingDefinition {
        key: "COOKIE_SECURE",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("30"),
        description: "署名鍵ローテーションの先行日数。`not_after` のこの日数前に後継鍵を公開する。",
    },
    SettingDefinition {
        key: "KEY_ROTATION_PUBLISH_LEAD_HOURS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("24"),
        description: "後継鍵を JWKS へ公開してから署名に使い始めるまでの時間。\
                      JWKS をキャッシュしている RP が新しい kid を取り込む猶予。\
                      0 にすると公開と同時に署名へ切り替わる（キャッシュを持つ RP の検証が落ちうる）。",
    },
    SettingDefinition {
        key: "APP_LOG_RETENTION_DAYS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("30"),
        description: "エラー・警告ログ（`log` テーブル）の保持日数。これより古い行は定期的に削除する。\
                      `0` を指定すると削除しない（テーブルが際限なく増えるため、外部でログを退避して \
                      いる場合にのみ選ぶこと）。",
    },
    SettingDefinition {
        key: "AUDIT_LOG_RETENTION_DAYS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("0"),
        description: "監査ログ（`audit_log` テーブル）の保持日数。これより古い行は定期的に削除する。\
                      既定の `0` は**削除しない**。監査ログの保存期間は法令・契約で決まる運用側の \
                      判断であり、既定値で消し始めてよいものではないため、明示的に指定したときだけ \
                      削除する。",
    },
    SettingDefinition {
        key: "TOKEN_ENDPOINT_MAX_CONCURRENCY",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("8"),
        description: "`/token`・`/introspect`・`/revoke` を同時に処理する最大数（SEC10）。この 3 つは \
                      client_secret を Argon2id（19 MiB）で照合するため、上限がピークメモリ \
                      （上限 × 19 MiB）と CPU を決める。溢れた要求は待たせず 503 で落とす。\
                      `0` は無制限（メモリ増幅型 DoS に対する防御線が無くなるため非推奨）。",
    },
    SettingDefinition {
        key: "TOKEN_ENDPOINT_RATE_LIMIT_MAX_REQUESTS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("300"),
        description: "`/token`・`/introspect`・`/revoke` の接続元 IP 単位のレート制限（SEC10）。\
                      単一の送信元が同時実行枠を占有して正規の RP を締め出すのを防ぐ。`0` は無効。\
                      接続元 IP が分かるとき（`TRUST_FORWARDED_HEADERS = true`）のみ効く。",
    },
    SettingDefinition {
        key: "TOKEN_ENDPOINT_RATE_LIMIT_WINDOW_SECS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("60"),
        description: "`TOKEN_ENDPOINT_RATE_LIMIT_MAX_REQUESTS` を数えるウィンドウ（秒）。",
    },
    SettingDefinition {
        key: "API_DOCS_ENABLED",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "Swagger UI（`/api/docs`）と OpenAPI 文書（`/api/openapi.json`）を配信するか。\
                      既定は無効。api 面は公開されるため、有効にすると管理 API を含む全エンドポイントの\
                      仕様が無認証で読める（秘密は含まないが攻撃対象の把握を助ける）。開発・検証環境で\
                      のみ有効にすること。",
    },
    SettingDefinition {
        key: "CORS_ALLOWED_ORIGINS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "ブラウザからの越境アクセス（CORS）を追加で許可するオリジンのカンマ区切り \
                      （例 `https://app.example.com,https://admin.example.com`）。既定は空で、\
                      許可されるのはテナント内 public クライアントの `redirect_uris` から導いた \
                      オリジンだけ。公開メタデータ（`/.well-known/*`・`/saml/metadata`）は本設定に \
                      関わらず誰でも取得できる。api はブラウザ Cookie を読まないため \
                      `Access-Control-Allow-Credentials` は付けない。",
    },
    SettingDefinition {
        key: "EXPIRED_RECORD_PURGE_INTERVAL_SECS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("3600"),
        description: "期限切れレコード（認可セッション・authorization code・refresh token・SSO \
                      セッション・失効 jti・パスキーチャレンジ・各種一時トークン）を掃除する間隔（秒）。\
                      いずれも期限を過ぎれば認証には使えないため、頻度は容量とレイテンシのための\
                      調整値である。`0` を指定すると掃除しない（表が際限なく増えるため非推奨）。",
    },
    SettingDefinition {
        key: "STEP_UP_MAX_AGE_SECS",
        scope: SettingScope::TenantOverridable,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: false,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("300"),
        description: "Step-up 認証（AP5）の再確認間隔（秒）。パスワード変更・認証器の追加削除などの \
                      重要操作は、直近の本人確認からこの秒数を超えていると本人確認をやり直させる。\
                      短くするほど盗まれたセッションで悪用できる窓が狭まり、長くするほど操作の \
                      たびの再入力が減る。",
    },
    SettingDefinition {
        key: "BACKCHANNEL_LOGOUT_MAX_ATTEMPTS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("8"),
        description: "Back-channel logout 通知の再送上限回数。指数バックオフ（30 秒 → 最大 1 時間）で \
                      再試行し、この回数に達した通知は打ち切る（打ち切りの記録は残る）。`0` は \
                      「1 度も送らない」ではなく「送信を無効化する」意味になるため指定しないこと。",
    },
    SettingDefinition {
        key: "BACKCHANNEL_LOGOUT_POLL_INTERVAL_SECS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("15"),
        description: "Back-channel logout 送信ワーカーが送信キューを確認する間隔（秒）。短くするほど \
                      通知が速く届くが、DB へのポーリングが増える。",
    },
    SettingDefinition {
        key: "BACKCHANNEL_LOGOUT_RETENTION_DAYS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::UnsignedInteger,
        default_value: Some("7"),
        description: "Back-channel logout 送信キューの決着済み（送信成功・打ち切り）の行を保持する \
                      日数。これより古い行は定期的に削除する。`0` を指定すると削除しない。",
    },
    SettingDefinition {
        key: "TRUST_FORWARDED_HEADERS",
        scope: SettingScope::Global,
        // web uses the same gate too (SEC1). Since ADR-0018 the login entrance is web, and the IP
        // web assembles is passed in the body to api's rate limiter and audit log. If only web
        // trusted the headers unconditionally, api's gate would be bypassed on the login path
        // (evading IP rate limits, polluting the audit log).
        shared_with_web: true,
        owner: SettingOwner::DbManaged,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "リバースプロキシの `X-Forwarded-For` / `X-Forwarded-Proto` を信頼するか。\
                      信頼できるプロキシ配下でのみ `true` にする（クライアント IP・スキーム判定に影響）。\
                      api と web の両方に効く。",
    },
    // Shared key whose security headers must match between api/web (MT26 / ADR-0013).
    SettingDefinition {
        key: "HSTS_MAX_AGE",
        scope: SettingScope::Global,
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
        key: "SILENT_AUTH_FRAME_ANCESTORS",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "画面を出さずに試す往復（`prompt=none`）を枠（iframe）に入れてよい親（空白区切り。\
                      例 `https://*.nolumia.com`。task #888・ADR-0076）。各アプリが切れたログインを見えない枠で \
                      問い合わせて続けるための口で、`/authorize` と `/login` の引き継ぎの 302 にだけ効く。\
                      ほかの画面は枠に入れない。空なら枠を許さない。web も環境変数から同じ値を読む。",
    },
    SettingDefinition {
        key: "SECURITY_ALERT_WEBHOOK_URL",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "セキュリティの知らせ（登録していない端末でのログインなど。task #872）を送る \
                      Webhook の URL（nolumia notice の `POST /api/notices` と同じ形の JSON を送る）。\
                      空なら送らない。通信先なので環境変数でだけ決める（画面・DB から変えさせない）。",
    },
    SettingDefinition {
        key: "SECURITY_ALERT_WEBHOOK_TOKEN_FILE",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "セキュリティの知らせの Webhook に `Authorization: Bearer` で載せる鍵を読むファイルの \
                      パス（task #872）。値そのものは環境変数にも DB にも置かない。",
    },
    SettingDefinition {
        key: "APP_APPROVER_PACKAGE_NAME",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "認証アプリ（「アプリで続ける」。task #892・ADR-0077）の Android のパッケージ名。\
                      空なら認証アプリの口は全部閉じる（404）。Key Attestation と assetlinks.json の両方に使う。",
    },
    SettingDefinition {
        key: "APP_APPROVER_SIGNING_CERT_SHA256",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "認証アプリの署名の証明書の SHA-256（`AB:CD:…` の形・カンマ区切りで複数可）。\
                      Key Attestation で受けるアプリと、assetlinks.json で App Link を許すアプリを決める。",
    },
    SettingDefinition {
        key: "APP_APPROVER_EXTRA_ATTESTATION_ROOTS_FILE",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: Some(""),
        description: "Google の根に加えて信じる Key Attestation の根（PEM の証明書のファイル）。\
                      ⚠ stg の確かめの台本のためだけに使い、本番では空にする。",
    },
    SettingDefinition {
        key: "APP_APPROVER_ALLOW_SOFTWARE_ATTESTATION",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Boolean,
        default_value: Some("false"),
        description: "ソフトウェアの鍵と、起動が検証されていない端末の鍵も受けるか。\
                      ⚠ stg の確かめの台本のためだけに使い、本番では false のままにする。",
    },
    SettingDefinition {
        key: "INTERNAL_SERVICE_TOKEN",
        scope: SettingScope::Global,
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
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: true,
        restart_required: true,
        default_risk: DefaultRisk::Dangerous,
        kind: SettingKind::Text,
        default_value: None,
        description: "CSRF トークンを導出する HMAC 鍵（32 バイト）。api/web で一致必須のため DB 上書き不可。",
    },
    // Must be the same value in api (used as the other side's URL for redirects and mail links) and
    // web (used as its own origin for Secure decisions and absolute URL generation), so EnvLocked
    // (ADR-0012 §2; changed from DbManaged).
    SettingDefinition {
        key: "PUBLIC_WEB_BASE_URL",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Review,
        kind: SettingKind::Text,
        default_value: None,
        description: "利用者がブラウザで開く web 画面の公開ベース URL。api は /authorize からログイン・\
                      同意画面への 302 とメールリンク生成に、web は自オリジンとして使う。api/web で\
                      一致必須のため DB 上書き不可。未設定なら issuer と同一オリジン。**ホスト名を\
                      変えると登録済みの Passkey が使えなくなる（WebAuthn の RP ID はこの URL の\
                      ホスト名から導出する。ADR-0019 決定 2）。**",
    },
    // EnvLocked because api/web cookie cleanup behavior must match (ADR-0012 §2).
    SettingDefinition {
        key: "COOKIE_DOMAIN",
        scope: SettingScope::Global,
        shared_with_web: false,
        owner: SettingOwner::EnvLocked,
        secret: false,
        restart_required: true,
        default_risk: DefaultRisk::Safe,
        kind: SettingKind::Text,
        default_value: None,
        description: "旧 ADR-0012 構成でブラウザに残った Domain 付きセッション Cookie\
                      （sso_session_id・auth_session_id）を掃除するための旧 Domain 値\
                      （例 `example.com`）。セッション Cookie は常に host-only で発行される\
                      （ADR-0018 決定 2・4）ため、移行期間だけ設定し、掃除が済んだら未設定へ戻す。\
                      未設定（既定）= 掃除なし。",
    },
];

pub fn runtime_setting_definition(key: &str) -> Option<&'static SettingDefinition> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .find(|def| def.key == key)
}

/// DB-managed keys consumed by both api and web (MT26 / ADR-0013). api passes only the DB overrides
/// in this list to web via `/internal/runtime-settings`. Secrets are never shared (web reads
/// bootstrap secrets from its own ENV).
pub fn shared_with_web_setting_keys() -> impl Iterator<Item = &'static str> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .filter(|def| def.shared_with_web && !def.secret)
        .map(|def| def.key)
}

/// Whether the given key is a DB-managed key shared with web.
pub fn is_shared_with_web(key: &str) -> bool {
    runtime_setting_definition(key)
        .map(|def| def.shared_with_web && !def.secret)
        .unwrap_or(false)
}

/// List of keys tenants can override (ADR-0058 §3).
pub fn tenant_overridable_setting_keys() -> impl Iterator<Item = &'static str> {
    RUNTIME_SETTING_DEFINITIONS
        .iter()
        .filter(|def| def.scope == SettingScope::TenantOverridable)
        .map(|def| def.key)
}

/// Whether tenants can override the given key. ⚠ Keys not in the definitions are `false`
/// (misspellings do not pass).
pub fn is_tenant_overridable(key: &str) -> bool {
    runtime_setting_definition(key)
        .map(|def| def.scope == SettingScope::TenantOverridable)
        .unwrap_or(false)
}

/// Validates that a value about to be saved is valid for the key's type ([`SettingKind`]).
///
/// **Both global (`system_settings`) and tenant (`tenant_settings`; ADR-0058) saves pass through
/// here.** Changing the rule on only one side would create values that can be saved globally but
/// not for a tenant.
///
/// Empty strings are handled by callers as "clearing the override", so they are not passed here.
pub fn validate_setting_value(def: &SettingDefinition, value: &str) -> Result<(), String> {
    let key = def.key;
    match def.kind {
        SettingKind::UnsignedInteger => {
            // Validate within the u32 range so that even the smallest consuming type on the
            // `Config` side (u32 for `KEY_ROTATION_LEAD_DAYS` etc.) always parses (saving an
            // out-of-range value would fail the restart with a config error).
            value.parse::<u32>().map(|_| ()).map_err(|_| {
                format!(
                    "setting {key} must be a non-negative integer (max {})",
                    u32::MAX
                )
            })
        }
        SettingKind::Boolean => {
            if value == "true" || value == "false" {
                Ok(())
            } else {
                Err(format!("setting {key} must be true or false"))
            }
        }
        SettingKind::Text => Ok(()),
        SettingKind::PublicBaseUrl => validate_public_base_url(key, value),
        SettingKind::Choice(choices) => {
            if choices.iter().any(|choice| choice.value == value) {
                Ok(())
            } else {
                let allowed: Vec<&str> = choices.iter().map(|choice| choice.value).collect();
                Err(format!(
                    "setting {key} must be one of: {}",
                    allowed.join(", ")
                ))
            }
        }
    }
}

/// Validates that a value is valid as a public base URL ([`SettingKind::PublicBaseUrl`]).
///
/// `ISSUER` is the base of the ID Token `iss` and every URL in the discovery document. Saving a
/// broken value would make **token verification at every RP fail** from the next startup, so it is
/// rejected at save time. A trailing slash is normalized by [`crate::config`], so it is allowed
/// here.
pub fn validate_public_base_url(key: &str, value: &str) -> Result<(), String> {
    let url = url::Url::parse(value.trim()).map_err(|_| {
        format!("setting {key} must be an absolute URL (e.g. https://idp.example.com)")
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "setting {key} must use the http or https scheme, got `{}`",
            url.scheme()
        ));
    }
    if url.host_str().unwrap_or_default().is_empty() {
        return Err(format!("setting {key} must include a host name"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("setting {key} must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "setting {key} must not contain a query string or fragment"
        ));
    }
    Ok(())
}

/// Whether the issuer is production-like (= whether startup with the default development secrets
/// should be refused).
///
/// The criterion is "**it exposes something other than local loopback**". Not just https: even
/// http, if it claims a host other than loopback, is treated as a production deployment terminating
/// TLS in front (SEC11).
///
/// Back when the decision was by scheme alone, a deployment terminating TLS at a proxy with
/// `ISSUER=http://id.example.com` escaped the fail-fast, and `/internal/*` was open with the
/// well-known `INTERNAL_SERVICE_TOKEN` embedded in the source (leaving nginx's `/internal/` 404 as
/// the only defense).
///
/// The predicate lives here so that **startup fail-fast and the pre-save bootability check
/// ([`ensure_override_is_bootable`]) use the same decision**. If only one side changed the rule,
/// values that can be saved but cannot boot would appear. The decision itself lives in the contract
/// shared by api / web (`assay_contracts::deployment`). If web had its own decision, "api starts
/// but web does not" could happen.
pub fn requires_production_secrets(issuer: &str) -> bool {
    assay_contracts::deployment::requires_production_secrets(issuer)
}

/// Whether the bootstrap secrets used at startup are still the development defaults (ADR-0017).
///
/// These are `EnvLocked` and cannot be fixed from the DB. Making `ISSUER` https makes both api and
/// web refuse to start with the default development secrets, so letting this combination be saved
/// leads to "save → restart → never starts again", the settings screen disappears with it, and the
/// only recovery is editing the DB directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DevelopmentSecrets {
    pub key_encryption_key: bool,
    pub internal_service_token: bool,
    pub csrf_secret: bool,
}

impl DevelopmentSecrets {
    /// Environment variable names of secrets still at development defaults (tells operators what to
    /// set).
    pub fn unset_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if self.key_encryption_key {
            keys.push("KEY_ENCRYPTION_KEY");
        }
        if self.internal_service_token {
            keys.push("INTERNAL_SERVICE_TOKEN");
        }
        if self.csrf_secret {
            keys.push("CSRF_SECRET");
        }
        keys
    }
}

/// Deployment state of the running process needed for the pre-save bootability check (ADR-0017).
///
/// Collects, among the conditions that fail-fast at startup, **those whose outcome depends on the
/// value of `ISSUER`**. All are `EnvLocked` values that cannot be fixed from the DB, so the only
/// way to prevent "save → restart → never starts again" is to refuse saving the `ISSUER` side.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentState {
    pub development_secrets: DevelopmentSecrets,
    /// `COOKIE_DOMAIN` (`EnvLocked`). `None` = host-only, so the consistency check does not run at
    /// all.
    pub cookie_domain: Option<String>,
    /// The **explicitly set** `PUBLIC_WEB_BASE_URL` (`EnvLocked`). `None` = it follows the issuer's
    /// origin, so changing the issuer never makes the schemes diverge.
    pub public_web_base_url_override: Option<String>,
}

/// Checks whether **the next startup succeeds** with the DB override value about to be saved
/// (ADR-0017).
///
/// DB overrides take effect only after a restart, so values that would fail startup can only be
/// stopped at save time. If startup fails, not only do api and web stay down, the settings screen
/// goes down too, so fixing it from the screen becomes impossible (the only recovery is editing the
/// DB directly).
///
/// Only `ISSUER` is checked. Other `DbManaged` keys never stop startup as long as the value format
/// passes (the format is validated by [`SettingKind`]).
pub fn ensure_override_is_bootable(
    key: &str,
    value: &str,
    state: &DeploymentState,
) -> Result<(), String> {
    if key != "ISSUER" {
        return Ok(());
    }

    // 1. An https issuer requires production secrets (same condition as
    //    `config::ensure_production_secrets`).
    if requires_production_secrets(value) {
        let missing = state.development_secrets.unset_keys();
        if !missing.is_empty() {
            return Err(format!(
                "refusing to store an https ISSUER while the built-in development secrets are in \
                 use ({}); both api and web refuse to start in that state and this settings screen \
                 would be gone. Set them as environment variables first, restart, then set ISSUER \
                 here",
                missing.join(", ")
            ));
        }
    }

    // 2. In deployments with `COOKIE_DOMAIN` set, unless the issuer's host is under that domain and
    //    its scheme matches `PUBLIC_WEB_BASE_URL`, **both api and web fail to start** (ADR-0012's
    //    fail-fast). Checked with exactly the same function as at startup, without duplicating the
    //    rule.
    if let Some(domain) = &state.cookie_domain {
        // If `PUBLIC_WEB_BASE_URL` is unset it follows the issuer, so put the new issuer in both.
        let web_origin = state
            .public_web_base_url_override
            .as_deref()
            .unwrap_or(value);
        assay_contracts::cookie_domain::validate_cookie_domain(domain, &[value, web_origin])
            .map_err(|e| {
                format!(
                    "refusing to store an ISSUER that breaks the configured COOKIE_DOMAIN; \
                     api and web would both fail to start and this settings screen would be gone: \
                     {e}"
                )
            })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys shared with web are meaningless unless they accept DB overrides (setting
    /// `shared_with_web` while `EnvLocked` would be inconsistent: api ignores the DB value yet it
    /// is distributed to web).
    #[test]
    fn tenant_overridable_keys_are_db_managed_and_not_secret() {
        // If tenants can override it, the global value should be changeable from the screen too.
        // Keeping `EnvLocked` would invert things: "global can only be changed by ENV, but tenants
        // can change it on screen". Secrets need a separate decryption path (ADR-0058 §8, SMTP).
        for key in tenant_overridable_setting_keys() {
            let def = runtime_setting_definition(key).unwrap();
            assert_eq!(def.owner, SettingOwner::DbManaged, "{key}");
            assert!(!def.secret, "{key}");
        }
    }

    /// Keys tenants can override are read on every lookup (ADR-0058 §9), so they take effect
    /// without a restart. ⚠ Setting this back to true makes the settings screen keep showing
    /// "waiting for restart" (although it is in effect). Conversely, if some key only takes effect
    /// after a restart, its consumer still reads `Config`.
    #[test]
    fn tenant_overridable_keys_take_effect_without_a_restart() {
        for key in tenant_overridable_setting_keys() {
            let def = runtime_setting_definition(key).unwrap();
            assert!(!def.restart_required, "{key}");
        }
    }

    /// ⚠ Keys tenants can override are not distributed to web (ADR-0058 §10). web receives a single
    /// startup snapshot from api (ADR-0013), which cannot represent values differing per tenant.
    #[test]
    fn tenant_overridable_keys_are_not_shared_with_web() {
        for key in tenant_overridable_setting_keys() {
            assert!(!is_shared_with_web(key), "{key}");
        }
    }

    /// ⚠ Token lifetimes cannot be changed by tenants (ADR-0058 §7). 300 seconds is the basis for
    /// "the upper bound until revoking a permission takes effect" (ADR-0056); no endpoint to loosen
    /// it is made.
    #[test]
    fn token_lifetimes_stay_with_the_whole_idp() {
        for key in [
            "ACCESS_TOKEN_TTL_SECS",
            "ID_TOKEN_TTL_SECS",
            "REFRESH_TOKEN_TTL_SECS",
            "MANAGEMENT_TOKEN_TTL_SECS",
            "AUTHORIZATION_CODE_TTL_SECS",
        ] {
            assert!(!is_tenant_overridable(key), "{key}");
        }
    }

    /// Keys that would break if moved down stay global (ADR-0058 §5): those whose safety rests on
    /// being the same value at issuance and revocation, those needed before resolving the tenant,
    /// and those that silently break unless api and web agree. ⚠ Making the tenant resolution cache
    /// lifetime a tenant setting would let a tenant stop its own resolution.
    #[test]
    fn keys_that_break_when_split_stay_with_the_whole_idp() {
        for key in [
            "ISSUER",
            "COOKIE_SECURE",
            "COOKIE_DOMAIN",
            "HSTS_MAX_AGE",
            "PUBLIC_WEB_BASE_URL",
            "AUTH_SESSION_TTL_SECS",
            "TENANT_CACHE_TTL_SECS",
            "DATABASE_URL",
            "KEY_ENCRYPTION_KEY",
        ] {
            assert!(!is_tenant_overridable(key), "{key}");
        }
    }

    /// The two keys that set the decision defaults are decided by the tenant and read on every
    /// lookup (ADR-0058 §4, §9). Leaving `restart_required` set would make the screen say "restart
    /// needed" while it actually takes effect without waiting for a restart — operators would
    /// misread the time between changing the value and restarting as "not yet in effect".
    #[test]
    fn decision_keys_are_decided_by_the_tenant_without_a_restart() {
        for key in [
            "AUTH_POLICY_DEFAULT_EFFECT",
            "APPLICATION_ASSIGNMENT_ENFORCEMENT",
        ] {
            let def = runtime_setting_definition(key).unwrap();
            assert_eq!(def.scope, SettingScope::TenantOverridable, "{key}");
            assert!(!def.shared_with_web, "{key}");
            assert!(!def.restart_required, "{key}");
        }
    }

    /// Keys not in the definitions cannot be overridden (a misspelling does not become a "silently
    /// ignored row").
    #[test]
    fn unknown_keys_are_not_tenant_overridable() {
        assert!(!is_tenant_overridable("PASSWORD_MIN_LENGHT"));
    }

    #[test]
    fn setting_values_are_checked_against_their_kind() {
        let integer = runtime_setting_definition("PASSWORD_MIN_LENGTH").unwrap();
        assert!(validate_setting_value(integer, "12").is_ok());
        assert!(validate_setting_value(integer, "-1").is_err());
        assert!(validate_setting_value(integer, "twelve").is_err());

        let boolean = runtime_setting_definition("PASSWORD_BREACH_CHECK_ENABLED").unwrap();
        assert!(validate_setting_value(boolean, "true").is_ok());
        assert!(validate_setting_value(boolean, "yes").is_err());

        let url = runtime_setting_definition("ISSUER").unwrap();
        assert!(validate_setting_value(url, "https://idp.example.com").is_ok());
        assert!(validate_setting_value(url, "idp.example.com").is_err());

        // Values not among the choices cannot be saved (even if saved, `Config` would fail at the
        // next startup).
        let choice = runtime_setting_definition("AUTH_POLICY_DEFAULT_EFFECT").unwrap();
        assert!(validate_setting_value(choice, "deny").is_ok());
        assert!(validate_setting_value(choice, "denyy").is_err());
    }

    /// Values that could lock users out (policy default deny, assignment enforce) let the need for
    /// confirmation be read from the definition. Since there is no branching on key names,
    /// confirmation follows even if the key's unit changes.
    #[test]
    fn values_that_can_lock_people_out_need_confirmation() {
        let effect = runtime_setting_definition("AUTH_POLICY_DEFAULT_EFFECT").unwrap();
        assert!(effect.needs_confirmation("deny"));
        assert!(!effect.needs_confirmation("allow"));

        let enforcement = runtime_setting_definition("APPLICATION_ASSIGNMENT_ENFORCEMENT").unwrap();
        assert!(enforcement.needs_confirmation("enforce"));
        assert!(!enforcement.needs_confirmation("record_only"));

        // Keys that are not choices get no confirmation.
        let integer = runtime_setting_definition("PASSWORD_MIN_LENGTH").unwrap();
        assert!(!integer.needs_confirmation("0"));
    }

    /// The default of a key with choices is one of the choices, and on the side that does not lock
    /// anyone out.
    #[test]
    fn choice_defaults_are_safe_choices() {
        for def in RUNTIME_SETTING_DEFINITIONS {
            let SettingKind::Choice(choices) = def.kind else {
                continue;
            };
            let default = def.default_value.expect("a choice needs a default");
            assert!(
                choices.iter().any(|c| c.value == default),
                "{}: default {default} is not a choice",
                def.key
            );
            assert!(!def.needs_confirmation(default), "{}", def.key);
        }
    }

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

    /// ISSUER can be changed from the DB (ADR-0017). If this went back to `EnvLocked`, it would
    /// silently return to a state where the row shows on the settings screen but cannot be saved
    /// (`editable` becomes false).
    #[test]
    fn issuer_is_db_managed_and_shared_with_web() {
        let def = runtime_setting_definition("ISSUER").expect("ISSUER is defined");
        assert_eq!(def.owner, SettingOwner::DbManaged);
        assert!(def.shared_with_web);
        assert_eq!(def.kind, SettingKind::PublicBaseUrl);
        assert!(def.restart_required);
    }

    #[test]
    fn public_base_urls_require_a_scheme_and_host() {
        assert!(validate_public_base_url("ISSUER", "https://idp.example.com").is_ok());
        // A trailing slash is accepted because `config` normalizes it.
        assert!(validate_public_base_url("ISSUER", "https://idp.example.com/").is_ok());
        assert!(validate_public_base_url("ISSUER", "http://localhost:8080").is_ok());
        // Host only, a different scheme, credentials, and queries are rejected.
        assert!(validate_public_base_url("ISSUER", "idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "ftp://idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "https://user:pw@idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "https://idp.example.com?a=1").is_err());
        assert!(validate_public_base_url("ISSUER", "").is_err());
    }

    /// If an https ISSUER could be saved, after a restart neither api nor web would start, and the
    /// screen to fix it would disappear too. While default development secrets remain, it is
    /// stopped at save time (ADR-0017).
    #[test]
    fn an_https_issuer_is_refused_while_development_secrets_are_in_use() {
        let dev = DeploymentState {
            development_secrets: DevelopmentSecrets {
                key_encryption_key: true,
                internal_service_token: false,
                csrf_secret: true,
            },
            ..DeploymentState::default()
        };
        let err = ensure_override_is_bootable("ISSUER", "https://idp.example.com", &dev)
            .expect_err("must be refused");
        assert!(err.contains("KEY_ENCRYPTION_KEY"), "{err}");
        assert!(err.contains("CSRF_SECRET"), "{err}");
        assert!(!err.contains("INTERNAL_SERVICE_TOKEN"), "{err}");

        // http (local development) can still start, so it passes.
        assert!(ensure_override_is_bootable("ISSUER", "http://localhost:8080", &dev).is_ok());
        // If the secrets are production values, https passes too.
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://idp.example.com",
            &DeploymentState::default()
        )
        .is_ok());
        // Other keys do not affect bootability.
        assert!(ensure_override_is_bootable("HSTS_MAX_AGE", "https://x", &dev).is_ok());
    }

    /// In deployments with `COOKIE_DOMAIN` set, if the issuer leaves that domain or its scheme
    /// diverges from `PUBLIC_WEB_BASE_URL`, **both api and web fail to start** (ADR-0012's
    /// fail-fast). The development secret check alone would let it through, and the moment the
    /// restart button is pressed both services enter a boot loop and the settings screen disappears
    /// with them. It is stopped at save time (ADR-0017).
    #[test]
    fn an_issuer_that_breaks_the_locked_cookie_domain_is_refused() {
        let state = |web: Option<&str>| DeploymentState {
            development_secrets: DevelopmentSecrets::default(),
            cookie_domain: Some("example.com".to_string()),
            public_web_base_url_override: web.map(str::to_string),
        };

        // Passes if under the same domain and the scheme matches the explicitly set web origin.
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://api.example.com",
            &state(Some("https://id.example.com"))
        )
        .is_ok());

        // Values leaving the domain are refused (browsers reject the Domain cookie and login does
        // not work).
        let err = ensure_override_is_bootable(
            "ISSUER",
            "https://api.other.com",
            &state(Some("https://id.example.com")),
        )
        .expect_err("outside COOKIE_DOMAIN must be refused");
        assert!(err.contains("COOKIE_DOMAIN"), "{err}");

        // Values whose scheme diverges from the explicitly set web origin are also refused (the
        // Secure attribute would be asymmetric).
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "http://api.example.com",
            &state(Some("https://id.example.com"))
        )
        .is_err());

        // If `PUBLIC_WEB_BASE_URL` is unset, web follows the issuer, so the schemes do not diverge.
        assert!(
            ensure_override_is_bootable("ISSUER", "http://api.example.com", &state(None)).is_ok()
        );

        // With `COOKIE_DOMAIN` unset (host-only), the consistency check does not even run.
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://api.other.com",
            &DeploymentState::default()
        )
        .is_ok());
    }

    /// Duplicate definition keys are forbidden because "which one wins" would depend on lookup
    /// order.
    #[test]
    fn runtime_setting_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for def in RUNTIME_SETTING_DEFINITIONS {
            assert!(seen.insert(def.key), "duplicate setting key: {}", def.key);
        }
    }
}

/// SMTP (mail delivery) settings. On read, only "configured or not" goes out, never the plaintext
/// password ([`SmtpSettingsView`]). Updates use [`UpdateSmtpCommand`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmtpSettingsView {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    /// Whether the password is set (the plaintext is never exposed).
    pub password_set: bool,
    pub from_address: String,
    pub use_tls: bool,
}

/// SMS gateway settings for display (no plaintext token, only "configured or not").
#[derive(Debug, Clone, Default)]
pub struct SmsSettingsView {
    pub gateway_url: String,
    pub auth_header: String,
    /// Whether the auth token is set (the plaintext is never exposed).
    pub auth_token_set: bool,
    pub sender_id: String,
}

/// Update command for SMS gateway settings.
/// `auth_token`: `None` = keep current, `Some("")` = clear, `Some(x)` = set (same rule as SMTP).
#[derive(Debug, Clone, Default)]
pub struct UpdateSmsCommand {
    pub gateway_url: String,
    pub auth_header: String,
    pub auth_token: Option<String>,
    pub sender_id: String,
}

/// Update command for SMTP settings. `password`: `None` = keep current, `Some("")` = clear,
/// `Some(x)` = set.
#[derive(Debug, Clone, Default)]
pub struct UpdateSmtpCommand {
    pub host: String,
    pub port: Option<u16>,
    pub username: String,
    pub password: Option<String>,
    pub from_address: String,
    pub use_tls: bool,
}
