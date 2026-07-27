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
    /// 自由文字列。
    Text,
    /// サービスの公開ベース URL（`ISSUER` 等）。スキームとホストを持つ絶対 URL であること。
    PublicBaseUrl,
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
    // api と web の両方が消費する（web は `PUBLIC_WEB_BASE_URL` 未設定時の自オリジンと
    // `COOKIE_DOMAIN` の検証に使う）。ADR-0017 で `EnvLocked` から DB 管理へ移した。
    SettingDefinition {
        key: "ISSUER",
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
                      使うため、変更の反映には両サービスの再起動が必要。**ホスト名を変えると \
                      登録済みの Passkey が使えなくなり（WebAuthn の RP ID が変わる）、RP 側にも \
                      新しい issuer の設定が要る。**",
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
    // api/web の Cookie 掃除挙動を一致させる必要があるため EnvLocked（ADR-0012 §2）。
    SettingDefinition {
        key: "COOKIE_DOMAIN",
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

/// 公開ベース URL（[`SettingKind::PublicBaseUrl`]）として妥当かを検証する。
///
/// `ISSUER` は ID Token の `iss` とディスカバリ文書の各 URL の基底になる。壊れた値を保存すると
/// 次回起動から**全 RP のトークン検証が落ちる**ため、保存の時点で弾く。末尾スラッシュは
/// [`crate::config`] が正規化するのでここでは許容する。
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

/// issuer が本番相当（https）か。
///
/// https では開発用の既定 secret での起動を拒否する（`config::ensure_production_secrets`）。
/// **起動時の fail-fast と、保存前の起動可否検査（[`ensure_override_is_bootable`]）が同じ判定を
/// 使う**ようにするため、述語をここに置く。片方だけがスキームの判定規則を変えると、保存はできるのに
/// 起動できない値が生まれる。
pub fn requires_production_secrets(issuer: &str) -> bool {
    issuer.trim().to_ascii_lowercase().starts_with("https://")
}

/// 起動時に使われた bootstrap secret が開発用の既定値のままか（ADR-0017）。
///
/// これらは `EnvLocked` で DB からは直せない。`ISSUER` を https にすると api も web も開発用既定
/// secret での起動を拒否するため、この組み合わせをそのまま保存させると「保存 → 再起動 → 二度と
/// 起動しない」に至り、設定画面ごと消えて復旧手段が DB の直接編集しか残らない。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DevelopmentSecrets {
    pub key_encryption_key: bool,
    pub internal_service_token: bool,
    pub csrf_secret: bool,
}

impl DevelopmentSecrets {
    /// 開発用既定のまま使われている secret の環境変数名（設定すべきものを運用者へ示す）。
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

/// 保存前の起動可否検査に必要な、実行中プロセスの配置状態（ADR-0017）。
///
/// 起動時に fail-fast する条件のうち、**`ISSUER` の値によって成否が変わるもの**を集めて渡す。
/// いずれも `EnvLocked` で DB からは直せない値なので、`ISSUER` 側を保存させないことでしか
/// 「保存 → 再起動 → 二度と起動しない」を防げない。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentState {
    pub development_secrets: DevelopmentSecrets,
    /// `COOKIE_DOMAIN`（`EnvLocked`）。`None` = host-only で、そもそも整合検証が走らない。
    pub cookie_domain: Option<String>,
    /// **明示設定された** `PUBLIC_WEB_BASE_URL`（`EnvLocked`）。`None` = issuer と同一オリジンへ
    /// 追従するため、issuer を変えてもスキームがずれることはない。
    pub public_web_base_url_override: Option<String>,
}

/// 保存しようとしている DB 上書き値で**次回の起動が成功するか**を検査する（ADR-0017）。
///
/// DB 上書きは再起動して初めて効くので、起動を失敗させる値は保存の時点でしか止められない。
/// 失敗させたときは、起動しない api と web が残るだけでなく設定画面も落ちるため、画面からの
/// 修正ができなくなる（復旧手段が DB の直接編集しか残らない）。
///
/// 検査するのは `ISSUER` だけである。他の `DbManaged` キーは値の書式さえ通れば起動を止めない
/// （書式は [`SettingKind`] 側で検証する）。
pub fn ensure_override_is_bootable(
    key: &str,
    value: &str,
    state: &DeploymentState,
) -> Result<(), String> {
    if key != "ISSUER" {
        return Ok(());
    }

    // 1. https の issuer は本番 secret を要求する（`config::ensure_production_secrets` と同じ条件）。
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

    // 2. `COOKIE_DOMAIN` を設定した配置では、issuer のホストがそのドメイン配下で、かつ
    //    `PUBLIC_WEB_BASE_URL` とスキームが一致していなければ **api も web も起動に失敗する**
    //    （ADR-0012 の fail-fast）。起動時とまったく同じ関数で検査し、判定規則を二重化しない。
    if let Some(domain) = &state.cookie_domain {
        // `PUBLIC_WEB_BASE_URL` 未設定なら issuer に追従するので、新しい issuer を両方に置く。
        let web_origin = state
            .public_web_base_url_override
            .as_deref()
            .unwrap_or(value);
        idp_contracts::cookie_domain::validate_cookie_domain(domain, &[value, web_origin])
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

    /// ISSUER は DB から変えられる（ADR-0017）。ここが `EnvLocked` に戻ると、設定画面に行は出るのに
    /// 保存できない（`editable` が false になる）状態へ静かに戻る。
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
        // 末尾スラッシュは `config` が正規化するので受ける。
        assert!(validate_public_base_url("ISSUER", "https://idp.example.com/").is_ok());
        assert!(validate_public_base_url("ISSUER", "http://localhost:8080").is_ok());
        // ホストだけ・スキーム違い・資格情報・クエリは弾く。
        assert!(validate_public_base_url("ISSUER", "idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "ftp://idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "https://user:pw@idp.example.com").is_err());
        assert!(validate_public_base_url("ISSUER", "https://idp.example.com?a=1").is_err());
        assert!(validate_public_base_url("ISSUER", "").is_err());
    }

    /// https の ISSUER を保存できてしまうと、再起動で api も web も起動しなくなり、直す画面ごと
    /// 消える。開発用既定 secret が残っている間は保存の時点で止める（ADR-0017）。
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

        // http（ローカル開発）はそのまま起動できるので通す。
        assert!(ensure_override_is_bootable("ISSUER", "http://localhost:8080", &dev).is_ok());
        // secret が本番値なら https も通す。
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://idp.example.com",
            &DeploymentState::default()
        )
        .is_ok());
        // 他のキーは起動可否に関わらない。
        assert!(ensure_override_is_bootable("HSTS_MAX_AGE", "https://x", &dev).is_ok());
    }

    /// `COOKIE_DOMAIN` を設定した配置では、issuer がそのドメインから外れる／`PUBLIC_WEB_BASE_URL` と
    /// スキームがずれると **api も web も起動に失敗する**（ADR-0012 の fail-fast）。開発用 secret の
    /// 検査だけでは素通りしてしまい、再起動ボタンを押した瞬間に両サービスが起動ループへ入って
    /// 設定画面ごと消える。保存の時点で止める（ADR-0017）。
    #[test]
    fn an_issuer_that_breaks_the_locked_cookie_domain_is_refused() {
        let state = |web: Option<&str>| DeploymentState {
            development_secrets: DevelopmentSecrets::default(),
            cookie_domain: Some("example.com".to_string()),
            public_web_base_url_override: web.map(str::to_string),
        };

        // 同一ドメイン配下で、明示された web オリジンとスキームも揃っていれば通る。
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://api.example.com",
            &state(Some("https://id.example.com"))
        )
        .is_ok());

        // ドメインの外へ出る値は拒否する（ブラウザが Domain Cookie を拒み、ログインが回らない）。
        let err = ensure_override_is_bootable(
            "ISSUER",
            "https://api.other.com",
            &state(Some("https://id.example.com")),
        )
        .expect_err("outside COOKIE_DOMAIN must be refused");
        assert!(err.contains("COOKIE_DOMAIN"), "{err}");

        // 明示された web オリジンとスキームがずれる値も拒否する（Secure 属性が非対称になる）。
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "http://api.example.com",
            &state(Some("https://id.example.com"))
        )
        .is_err());

        // `PUBLIC_WEB_BASE_URL` 未設定なら web は issuer に追従するのでスキームはずれない。
        assert!(
            ensure_override_is_bootable("ISSUER", "http://api.example.com", &state(None)).is_ok()
        );

        // `COOKIE_DOMAIN` 未設定（host-only）ではそもそも整合検証が走らない。
        assert!(ensure_override_is_bootable(
            "ISSUER",
            "https://api.other.com",
            &DeploymentState::default()
        )
        .is_ok());
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
