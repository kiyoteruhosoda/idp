//! アプリケーション設定。
//!
//! 設定値の取得は **必ず本モジュール経由**で行う。生の環境変数・DSN を各所で直接参照しない。
//!
//! 優先順位: **組み込み既定値 < 環境変数（ENV）< DB（system_settings テーブル）**。
//! 「あとから DB で上書きできる」という思想で、より運用に近い層（DB）を優先する。
//! ただし DB 上書きを受け付けるのは `DbManaged` のキーだけ。`EnvLocked`（DB を読む前や DB 内 secret の
//! 復号に必要な bootstrap 系、api/web で値を一致させたいキー）は DB を参照せず ENV > 既定値 で解決する
//! （ADR-0010）。`Builtin` は常に既定値。
//!
//! 一部の getter（各種 TTL・クロックスキュー）は後続フェーズ（T2〜）で使用するため、
//! 現時点では未使用でも保持する。
#![allow(dead_code)]

use crate::domain::authentication_policy::{DefaultPolicyEffect, LockoutPolicy};
use crate::domain::system_setting::{
    requires_production_secrets, runtime_setting_definition, DefaultRisk, DeploymentState,
    DevelopmentSecrets, SettingOwner, RUNTIME_SETTING_DEFINITIONS,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use idp_contracts::cookies::CookiePolicy;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

/// 秘密鍵暗号化キーの開発用デフォルト（ちょうど 32 バイト）。本番では必ず `KEY_ENCRYPTION_KEY`
/// を設定する。運用では DB 外の鍵管理（KMS 等）へ移行する。
const DEV_KEY_ENCRYPTION_KEY: &[u8; 32] = b"idp-dev-insecure-key-0123456789!";

/// サービス間内部認証トークンの開発用デフォルト（ADR-0007 §5）。本番では必ず
/// `INTERNAL_SERVICE_TOKEN` を設定する。web→api の `/internal/*` 呼び出しを保護する共有シークレット。
const DEV_INTERNAL_SERVICE_TOKEN: &str = "idp-dev-insecure-internal-service-token";

/// CSRF トークン HMAC 鍵の開発用デフォルト（ちょうど 32 バイト）。本番では必ず
/// `CSRF_SECRET` を web と api で同じ値に設定する（SEC7）。
pub const DEV_CSRF_SECRET: &[u8; 32] = b"idp-dev-insecure-csrf-secret-xxx";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    Builtin,
    Env,
    Db,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSetting {
    pub key: String,
    pub owner: SettingOwner,
    pub source: SettingSource,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: DefaultRisk,
    /// 画面表示用の安全判定（値や fingerprint は含めない）。
    pub status: SettingSafetyStatus,
    /// 危険/安全判定の根拠。secret の平文・fingerprint は含めない。
    pub reason: String,
    /// 起動時に解決された有効値（表示用）。secret のときは常に `None`（平文を外へ出さない）。
    pub value: Option<String>,
    /// 組み込み既定値（表示用）。secret のときは `None`。
    pub default_value: Option<String>,
    /// この設定が何に使われるかの説明（運用者向け。設定画面に表示する）。
    pub description: String,
}

impl ResolvedSetting {
    /// **保存済みだが実行中のプロセスへ未反映**か（MT27）。
    ///
    /// `resolved_settings` は起動時のスナップショットで、`db_current` は現在 `system_settings` に
    /// 保存されている上書き値（未設定は `None`）である。この 2 つがずれていれば、設定画面で保存した
    /// 値はまだ効いていない。
    ///
    /// 保存しても挙動が変わらないことは画面から見えず、運用者は「保存したのに直らない」という
    /// 誤った結論に至る。判定をここに置くのは、比較のルール（とくに**上書きの解除**も未反映で
    /// ある点）を表示側で再現させないためである。
    ///
    /// 判定するのは `DbManaged` かつ非 secret かつ `restart_required` のキーだけである。
    ///
    /// - `restart_required` が false のキーは参照のたびに DB を読むため常に反映済み。
    /// - secret は起動時スナップショットに平文を残さない（`value` が常に `None`）ため比較できない。
    /// - **`DbManaged` 以外は DB 行があっても比較しない。** `EnvLocked` / `Builtin` のキーは解決時に
    ///   DB を一切参照しないため `source` が `Db` になり得ず、残存行と突き合わせると永遠に未反映と
    ///   出続ける。しかも `editable` が false なので画面から消せず、警告が消せないまま居座る。
    ///   出所区分が `DbManaged` から変わったキー（`PUBLIC_WEB_BASE_URL`・`COOKIE_DOMAIN` は
    ///   ADR-0012 で `EnvLocked` へ移した）の `system_settings` 行が残っている環境で実際に起きる。
    ///   これらの行はそもそも設定の解決に影響しない（無視される）ので、未反映ではない。
    pub fn is_pending_restart(&self, db_current: Option<&str>) -> bool {
        if !self.restart_required || self.secret || self.owner != SettingOwner::DbManaged {
            return false;
        }
        match db_current {
            // DB に上書きがある: 起動時にも同じ値を DB から採っていれば反映済み。
            Some(value) => {
                !(self.source == SettingSource::Db && self.value.as_deref() == Some(value))
            }
            // DB に上書きが無い: 起動時に DB から採っていたなら、解除がまだ効いていない。
            None => self.source == SettingSource::Db,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSafetyStatus {
    Safe,
    NeedsAction,
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
    /// メール検証トークンの有効期限（SEC6b）。
    email_verification_ttl: Duration,
    /// アカウントロックのポリシー（失敗許容回数・ロック時間。ユーザー認証・認証ポリシー仕様書 §17）。
    login_lockout: LockoutPolicy,
    /// 認証ポリシーが 1 件も一致しないときの既定動作（同仕様 §9.4）。
    auth_policy_default_effect: DefaultPolicyEffect,
    /// テナント解決キャッシュの TTL（ADR-0009 §7。id → tenant のホットパス）。
    tenant_cache_ttl: Duration,
    /// scope→権限解決キャッシュの TTL（ADR-0009 §7。付与・剥奪時は即時 invalidate される）。
    permission_cache_ttl: Duration,
    /// Cookie の属性方針（`Secure` と旧 `Domain` Cookie の掃除。ADR-0018 決定 2・4）。web と同じ値を設定する。
    cookie_policy: CookiePolicy,
    key_encryption_key: [u8; 32],
    key_encryption_key_is_dev: bool,
    /// 署名鍵ローテーション: `not_after` のこの日数前に新鍵を生成して旧鍵を退役させる（K2）。
    key_rotation_lead_days: u32,
    /// エラー・警告ログ（`log` テーブル）の保持日数。`0` は削除しない。
    app_log_retention_days: u32,
    /// リバースプロキシが付与する `X-Forwarded-For` / `X-Forwarded-Proto` を信頼するか（S1）。
    trust_forwarded_headers: bool,
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない（S1）。
    hsts_max_age: u64,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    /// CSRF トークン HMAC 鍵（`CSRF_SECRET`）。web と api で同じ値を設定する（SEC7）。
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    /// 利用者がブラウザで開く web 画面の公開ベース URL（招待メールの承諾リンク等。MT17）。
    /// api/web で同一値必須のため EnvLocked（ADR-0012 §2）。
    public_web_base_url: String,
    /// **明示設定された** `PUBLIC_WEB_BASE_URL`（`None` = issuer へ追従）。
    ///
    /// 解決後の値（`public_web_base_url`）からは「issuer に追従しているのか、たまたま同値を明示
    /// したのか」を区別できない。`ISSUER` の DB 上書きを保存してよいかの判定（ADR-0017）は
    /// この区別を要する — 追従なら issuer を変えてもスキームはずれないが、明示設定なら
    /// `COOKIE_DOMAIN` 配置でスキーム不一致になり起動しなくなる。
    public_web_base_url_override: Option<String>,
    resolved_settings: Vec<ResolvedSetting>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_and_db_settings(&HashMap::new())
    }

    pub fn from_env_and_db_settings(db_settings: &HashMap<String, String>) -> anyhow::Result<Self> {
        let resolver = ConfigResolver::new(db_settings);
        let (key_encryption_key, key_encryption_key_is_dev) = load_key_encryption_key()?;
        let issuer = normalize_issuer(resolver.string("ISSUER", "http://localhost:8080"));
        // Cookie の Secure 属性。既定は issuer のスキームに従う（https なら有効）。
        let cookie_secure = resolver.parse("COOKIE_SECURE", issuer.starts_with("https://"))?;
        // web→api の /internal/* 呼び出しを保護する共有シークレット（ADR-0007 §5）。
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (validate_internal_service_token(v)?, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // CSRF トークン HMAC 鍵（SEC7）。web と api で同じ値を設定する。
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // 本番相当（ループバック以外の公開オリジン）では開発用デフォルトのシークレットで
        // 起動しない（fail-fast。SEC11）。
        ensure_production_secrets(
            &issuer,
            key_encryption_key_is_dev,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        // 招待メール等の承諾リンクの土台。単一オリジン構成（ADR-0007）では issuer と同一オリジンに
        // web 画面が同居するため既定は issuer。web を別オリジンへ置く構成でのみ明示設定する。
        let public_web_base_url_override = resolver
            .optional_string("PUBLIC_WEB_BASE_URL")
            .map(normalize_issuer);
        let public_web_base_url = public_web_base_url_override
            .clone()
            .unwrap_or_else(|| issuer.clone());
        // 旧 ADR-0012 構成の Domain 付き Cookie を掃除するための COOKIE_DOMAIN（ADR-0018 決定 4）。
        // 設定時は issuer / public_web_base_url 双方の親ドメインであり public suffix でないことを
        // 起動時に検証する（削除 Cookie がブラウザに受理されない値を弾く fail-fast）。
        let cookie_domain = match resolver.optional_string("COOKIE_DOMAIN") {
            Some(raw) => Some(
                idp_contracts::cookie_domain::validate_cookie_domain(
                    &raw,
                    &[issuer.as_str(), public_web_base_url.as_str()],
                )
                .map_err(|e| anyhow::anyhow!(e))?,
            ),
            None => None,
        };
        let cookie_policy = CookiePolicy::new(cookie_secure, cookie_domain.as_deref());

        Ok(Self {
            issuer,
            bind_addr: resolver.string("BIND_ADDR", "0.0.0.0:8080"),
            database_url: resolver.string("DATABASE_URL", "mysql://idp:idp@127.0.0.1:3306/idp"),
            db_max_connections: resolver.parse("DB_MAX_CONNECTIONS", 10)?,
            log_format: match resolver
                .string("LOG_FORMAT", "json")
                .to_ascii_lowercase()
                .as_str()
            {
                "pretty" => LogFormat::Pretty,
                _ => LogFormat::Json,
            },
            auth_session_ttl: secs(resolver.parse("AUTH_SESSION_TTL_SECS", 600)?),
            authorization_code_ttl: secs(resolver.parse("AUTHORIZATION_CODE_TTL_SECS", 60)?),
            sso_idle_ttl: secs(resolver.parse("SSO_IDLE_TTL_SECS", 28_800)?),
            sso_absolute_ttl: secs(resolver.parse("SSO_ABSOLUTE_TTL_SECS", 86_400)?),
            access_token_ttl: secs(resolver.parse("ACCESS_TOKEN_TTL_SECS", 900)?),
            id_token_ttl: secs(resolver.parse("ID_TOKEN_TTL_SECS", 3_600)?),
            // Refresh Token は既定 30 日（offline_access scope で発行。rotation あり）。
            refresh_token_ttl: secs(resolver.parse("REFRESH_TOKEN_TTL_SECS", 2_592_000)?),
            clock_skew: secs(resolver.parse("CLOCK_SKEW_SECS", 60)?),
            invitation_ttl: secs(resolver.parse("INVITATION_TTL_SECS", 604_800)?),
            password_reset_ttl: secs(resolver.parse("PASSWORD_RESET_TTL_SECS", 3_600)?),
            email_verification_ttl: secs(resolver.parse("EMAIL_VERIFICATION_TTL_SECS", 86_400)?),
            login_lockout: LockoutPolicy {
                // i32 に収まらない巨大値は「実質ロックしない」として i32::MAX へ飽和させる
                //（`as` キャストだと負数へラップし、初回失敗で即ロックという逆の挙動になる。
                //  DB 保存値で起動を失敗させるとロックアウト設定の修正自体ができなくなるため
                //  fail-fast にはしない）。
                max_failed_attempts: i32::try_from(
                    resolver.parse("LOGIN_MAX_FAILED_ATTEMPTS", 10u32)?,
                )
                .unwrap_or(i32::MAX),
                lock_duration_secs: resolver.parse("LOGIN_LOCK_DURATION_SECS", 900u64)?,
            },
            auth_policy_default_effect: DefaultPolicyEffect::parse(
                &resolver.string("AUTH_POLICY_DEFAULT_EFFECT", "allow"),
            )
            .map_err(|e| anyhow::anyhow!("invalid value for AUTH_POLICY_DEFAULT_EFFECT: {e}"))?,
            tenant_cache_ttl: secs(resolver.parse("TENANT_CACHE_TTL_SECS", 60)?),
            permission_cache_ttl: secs(resolver.parse("PERMISSION_CACHE_TTL_SECS", 60)?),
            cookie_policy,
            key_encryption_key,
            key_encryption_key_is_dev,
            key_rotation_lead_days: resolver.parse("KEY_ROTATION_LEAD_DAYS", 30)?,
            app_log_retention_days: resolver.parse("APP_LOG_RETENTION_DAYS", 30)?,
            trust_forwarded_headers: resolver.parse("TRUST_FORWARDED_HEADERS", false)?,
            hsts_max_age: resolver.parse("HSTS_MAX_AGE", 0u64)?,
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            public_web_base_url,
            public_web_base_url_override,
            resolved_settings: resolver.resolved_settings(),
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

    pub fn email_verification_ttl(&self) -> Duration {
        self.email_verification_ttl
    }
    /// アカウントロックのポリシー（失敗許容回数・ロック時間。全ログイン経路へ一律適用する）。
    pub fn login_lockout(&self) -> LockoutPolicy {
        self.login_lockout
    }
    /// 認証ポリシーが 1 件も一致しないときの既定動作（`allow` / `deny`）。
    pub fn auth_policy_default_effect(&self) -> DefaultPolicyEffect {
        self.auth_policy_default_effect
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
        self.cookie_policy.secure()
    }
    /// Cookie の属性方針。api はブラウザ Cookie を発行しない（ADR-0018 決定 2）ため現在は
    /// `cookie_secure` / `cookie_domain` の解決結果の入れ物としてのみ使う。
    pub fn cookie_policy(&self) -> &CookiePolicy {
        &self.cookie_policy
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
    /// エラー・警告ログの保持日数（`0` = 削除しない）。
    pub fn app_log_retention_days(&self) -> u32 {
        self.app_log_retention_days
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
    /// CSRF トークン HMAC 鍵（SEC7）。ログイン・同意フォームの CSRF トークン導出に使う。
    /// web と api で同じ値（`CSRF_SECRET` 環境変数）を設定する。
    pub fn csrf_secret(&self) -> &[u8; 32] {
        &self.csrf_secret
    }
    /// 開発用デフォルトの CSRF シークレットを使っているか（本番では起動を拒否する）。
    pub fn csrf_secret_is_dev(&self) -> bool {
        self.csrf_secret_is_dev
    }

    /// ランタイム設定の DB 上書きを保存する前の「その値で次回起動できるか」判定へ渡す、
    /// 実行中プロセスの配置状態（ADR-0017）。
    ///
    /// 起動時 fail-fast の条件のうち `ISSUER` の値で成否が変わるもの（開発用既定 secret の使用状況・
    /// `COOKIE_DOMAIN` / 明示設定された `PUBLIC_WEB_BASE_URL`）をまとめて渡す。
    pub fn deployment_state(&self) -> DeploymentState {
        DeploymentState {
            development_secrets: DevelopmentSecrets {
                key_encryption_key: self.key_encryption_key_is_dev,
                internal_service_token: self.internal_service_token_is_dev,
                csrf_secret: self.csrf_secret_is_dev,
            },
            cookie_domain: self.cookie_domain().map(str::to_string),
            public_web_base_url_override: self.public_web_base_url_override.clone(),
        }
    }
    /// 利用者がブラウザで開く web 画面の公開ベース URL（末尾スラッシュ無し。招待メールの
    /// 承諾リンク等に使う。既定は issuer と同一オリジン。MT17）。
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }
    /// 旧 ADR-0012 構成の `Domain` 付き Cookie を掃除するための `COOKIE_DOMAIN`（ADR-0018 決定 4）。
    /// `None` = 掃除なし（既定）。セッション Cookie は常に host-only で発行される（web 側）。
    pub fn cookie_domain(&self) -> Option<&str> {
        self.cookie_policy.legacy_cleanup_domain()
    }

    pub fn resolved_settings(&self) -> &[ResolvedSetting] {
        &self.resolved_settings
    }
}

struct ConfigResolver<'a> {
    db_settings: &'a HashMap<String, String>,
}

impl<'a> ConfigResolver<'a> {
    fn new(db_settings: &'a HashMap<String, String>) -> Self {
        Self { db_settings }
    }

    /// 有効値を解決する。優先順位は「既定値 < ENV < DB」。
    ///
    /// DB を優先するのは `DbManaged` のキーだけ（あとから DB で上書きできるという思想）。
    /// それ以外（`EnvLocked` / 未定義キー）は DB を参照せず ENV のみを見る。DB・ENV とも無ければ
    /// `None`（呼び出し側が既定値へフォールバック）。
    fn optional_string(&self, key: &str) -> Option<String> {
        let db_allowed = runtime_setting_definition(key)
            .map(|def| def.owner == SettingOwner::DbManaged)
            .unwrap_or(false);
        // DB 管理キーは DB 値を最優先（ENV を上書きする）。
        if db_allowed {
            if let Some(v) = self.db_settings.get(key).filter(|v| !v.is_empty()) {
                return Some(v.clone());
            }
        }
        env_lookup(key)
    }

    fn string(&self, key: &str, default: &str) -> String {
        self.optional_string(key)
            .unwrap_or_else(|| default.to_string())
    }

    fn parse<T>(&self, key: &str, default: T) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.optional_string(key) {
            Some(v) => v
                .parse::<T>()
                .map_err(|e| anyhow::anyhow!("invalid value for {key}: {e}")),
            None => Ok(default),
        }
    }

    /// 有効値の出所を返す（[`optional_string`] と同じ優先順位: 既定値 < ENV < DB）。
    fn source(&self, key: &str) -> SettingSource {
        let db_allowed = runtime_setting_definition(key)
            .map(|def| def.owner == SettingOwner::DbManaged)
            .unwrap_or(false);
        // DB 管理キーで DB 値があれば DB が有効（ENV より優先）。
        if db_allowed
            && self
                .db_settings
                .get(key)
                .filter(|v| !v.is_empty())
                .is_some()
        {
            return SettingSource::Db;
        }
        if env_lookup(key).is_some() {
            return SettingSource::Env;
        }
        SettingSource::Builtin
    }

    fn safety_status(&self, key: &str, default_risk: DefaultRisk) -> SettingSafetyStatus {
        match key {
            "KEY_ENCRYPTION_KEY" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "INTERNAL_SERVICE_TOKEN" if env_lookup(key).is_none() => {
                SettingSafetyStatus::NeedsAction
            }
            "CSRF_SECRET" if env_lookup(key).is_none() => SettingSafetyStatus::NeedsAction,
            "COOKIE_SECURE" => match self.optional_string(key) {
                Some(v) if v.eq_ignore_ascii_case("false") => SettingSafetyStatus::NeedsAction,
                None => SettingSafetyStatus::NeedsAction,
                _ => SettingSafetyStatus::Safe,
            },
            "HSTS_MAX_AGE" => match self.optional_string(key) {
                Some(v) if v != "0" => SettingSafetyStatus::Safe,
                _ => SettingSafetyStatus::NeedsAction,
            },
            _ if default_risk == DefaultRisk::Dangerous
                && self.source(key) == SettingSource::Builtin =>
            {
                SettingSafetyStatus::NeedsAction
            }
            _ => SettingSafetyStatus::Safe,
        }
    }

    fn safety_reason(&self, key: &str, default_risk: DefaultRisk) -> String {
        match key {
            "KEY_ENCRYPTION_KEY" | "INTERNAL_SERVICE_TOKEN" | "CSRF_SECRET"
                if env_lookup(key).is_none() =>
            {
                "開発用の既知 secret が使われています。環境変数でランダム値を設定してください。".to_string()
            }
            "COOKIE_SECURE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "Cookie Secure が無効または組み込み既定です。HTTPS 配置では true にしてください。".to_string()
            }
            "HSTS_MAX_AGE" if self.safety_status(key, default_risk) == SettingSafetyStatus::NeedsAction => {
                "HSTS が無効です。HTTPS 配置では正の max-age を設定してください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Dangerous => {
                "危険な組み込み既定値が使われています。環境変数または DB 管理値で上書きしてください。".to_string()
            }
            _ if self.source(key) == SettingSource::Builtin && default_risk == DefaultRisk::Review => {
                "組み込み既定値です。配置環境に適しているか確認してください。".to_string()
            }
            _ => "現在の出所では要対応項目は検出されていません。".to_string(),
        }
    }

    fn resolved_settings(&self) -> Vec<ResolvedSetting> {
        RUNTIME_SETTING_DEFINITIONS
            .iter()
            .map(|def| ResolvedSetting {
                key: def.key.to_string(),
                owner: def.owner,
                source: match def.owner {
                    SettingOwner::Builtin => SettingSource::Builtin,
                    SettingOwner::EnvLocked | SettingOwner::DbManaged => self.source(def.key),
                },
                secret: def.secret,
                restart_required: def.restart_required,
                default_risk: def.default_risk,
                status: self.safety_status(def.key, def.default_risk),
                reason: self.safety_reason(def.key, def.default_risk),
                value: (!def.secret)
                    .then(|| {
                        self.optional_string(def.key)
                            .or_else(|| def.default_value.map(str::to_string))
                    })
                    .flatten(),
                default_value: (!def.secret)
                    .then(|| def.default_value.map(str::to_string))
                    .flatten(),
                description: def.description.to_string(),
            })
            .collect()
    }
}

/// 公開ベース URL を正規化する: 末尾スラッシュを落とし、**スキームを小文字化**する。
///
/// URI のスキームは大小を区別しない（RFC 3986 §3.1）。`HTTPS://idp.example.com` のような表記でも
/// https と判定できないと、Cookie の `Secure` 判定と本番シークレットの fail-fast（どちらもスキームを
/// 見る）がすり抜ける。ホスト・パスはそのまま残す（issuer は ID Token の `iss` と完全一致させる
/// 必要があるため、こちらで勝手に変えない）。
fn normalize_issuer(raw: String) -> String {
    let trimmed = raw.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
        None => trimmed.to_string(),
    }
}

/// 本番相当の配置で開発用デフォルトのシークレットが使われていたら起動を失敗させる。
///
/// 開発用デフォルト（`DEV_KEY_ENCRYPTION_KEY`・`DEV_INTERNAL_SERVICE_TOKEN`・`DEV_CSRF_SECRET`）は
/// ソースに埋め込まれた既知値であり、本番で使うと署名鍵の暗号化・`/internal/*` の保護・CSRF 防御が
/// 実質無効になる。warning での見逃しを防ぐため、ローカルループバック以外の配置では設定漏れを
/// 構成エラーとする（SEC11。前段で TLS を終端して `ISSUER` を http にした配置も本番扱いになる）。
fn ensure_production_secrets(
    issuer: &str,
    key_encryption_key_is_dev: bool,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    // 判定規則は domain に単一化する（保存前の起動可否検査と同じ述語を使うため。ADR-0017）。
    if !requires_production_secrets(issuer) {
        return Ok(());
    }
    if key_encryption_key_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but KEY_ENCRYPTION_KEY is not set; \
             refusing to start with the built-in development key. \
             Set KEY_ENCRYPTION_KEY (base64, 32 bytes) in production."
        );
    }
    if internal_service_token_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with web) in production."
        );
    }
    if csrf_secret_is_dev {
        anyhow::bail!(
            "ISSUER ({issuer}) is not a local loopback origin but CSRF_SECRET is not set; \
             refusing to start with the built-in development key. \
             Set CSRF_SECRET (base64, 32 bytes, shared with web) in production."
        );
    }
    Ok(())
}

/// `KEY_ENCRYPTION_KEY`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
fn load_key_encryption_key() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("KEY_ENCRYPTION_KEY") {
        Some(v) => Ok((decode_secret_32("KEY_ENCRYPTION_KEY", &v)?, false)),
        None => Ok((*DEV_KEY_ENCRYPTION_KEY, true)),
    }
}

/// `CSRF_SECRET`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => Ok((decode_secret_32("CSRF_SECRET", &v)?, false)),
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

/// `INTERNAL_SERVICE_TOKEN` の最低要件を検査する（SEC11）。判定は web と共有の契約に置く。
fn validate_internal_service_token(value: String) -> anyhow::Result<String> {
    idp_contracts::deployment::validate_internal_service_token(&value)
        .map_err(|e| anyhow::anyhow!(e))
}

/// base64 の 32 バイトシークレット（`KEY_ENCRYPTION_KEY`・`CSRF_SECRET`）を復号する。
///
/// `.env.*.example` のプレースホルダ `CHANGE-ME` が残ったまま起動されるケースが実際に多い
/// （素の base64 エラーは `Invalid symbol 45, offset 6` としか出ず原因に辿り着けない）ため、
/// プレースホルダは base64 復号より先に検出し、対処（`openssl rand -base64 32`）まで案内する。
fn decode_secret_32(name: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.trim();
    if value.contains("CHANGE-ME") {
        anyhow::bail!(
            "{name} is still the .env template placeholder \"CHANGE-ME\"; \
             replace it with a real value (generate with `openssl rand -base64 32`)"
        );
    }
    let bytes = STANDARD.decode(value).map_err(|e| {
        anyhow::anyhow!("{name} must be base64 (generate with `openssl rand -base64 32`): {e}")
    })?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("{name} must decode to 32 bytes, got {}", b.len()))
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

/// 環境変数を文字列で引く（未設定・空は既定値）。設定解決は [`ConfigResolver`] へ移行済みで、
/// 現在はフォールバック挙動を検証するテストからのみ使う。
#[cfg(test)]
fn env_or(key: &str, default: &str) -> String {
    env_lookup(key).unwrap_or_else(|| default.to_string())
}

/// 環境変数をパースして引く（未設定・空は既定値）。[`env_or`] と同じくテスト専用の補助。
#[cfg(test)]
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
    use std::sync::{Mutex, MutexGuard};

    /// プロセス共有の環境変数を触るテストを直列化するためのロック。
    ///
    /// `cargo test` は 1 プロセス内の複数スレッドでテストを並列実行し、`std::env` は
    /// プロセス全体で共有される。環境変数を設定/削除しつつ `Config` を組み立てるテストが
    /// 並行すると、あるテストが設定した値を別テストが読んでしまい非決定的に失敗する
    /// （例: `KEY_ROTATION_LEAD_DAYS` の 14 と 7 の取り違え）。該当テストはこのロックを
    /// 取得して直列化する。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `ENV_LOCK` を取得する。ロック保持中に別テストが panic して poison しても、
    /// 排他自体は保たれているため内側の値を取り出して継続する。
    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// ループバック以外の公開オリジンを使うテストは本番相当と判定される（SEC11）ため、開発用
    /// 既定 secret のままでは `Config` を組み立てられない。テスト用の値を注入する。
    fn set_production_secrets() {
        std::env::set_var("KEY_ENCRYPTION_KEY", STANDARD.encode([1u8; 32]));
        std::env::set_var("CSRF_SECRET", STANDARD.encode([2u8; 32]));
        std::env::set_var("INTERNAL_SERVICE_TOKEN", "t".repeat(32));
    }

    fn clear_production_secrets() {
        std::env::remove_var("KEY_ENCRYPTION_KEY");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
    }

    /// MT27: 起動時スナップショットと現在の DB 上書き値がずれていれば「保存済み・未反映」。
    #[test]
    fn pending_restart_compares_the_startup_snapshot_with_the_stored_override() {
        let setting = |source: SettingSource, value: Option<&str>| ResolvedSetting {
            key: "COOKIE_SECURE".to_string(),
            owner: SettingOwner::DbManaged,
            source,
            secret: false,
            restart_required: true,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: value.map(str::to_string),
            default_value: Some("false".to_string()),
            description: String::new(),
        };

        // 起動時に DB から採った値と保存値が一致 → 反映済み。
        assert!(!setting(SettingSource::Db, Some("true")).is_pending_restart(Some("true")));
        // 保存値が変わった → 未反映。
        assert!(setting(SettingSource::Db, Some("true")).is_pending_restart(Some("false")));
        // 起動時は ENV/既定値で、あとから DB 上書きを保存した → 未反映。
        assert!(setting(SettingSource::Env, Some("false")).is_pending_restart(Some("true")));
        // **上書きの解除も未反映**（起動時は DB から採っていた）。ここを取りこぼすと、
        // 「解除したのに元の値に戻らない」が画面から見えない。
        assert!(setting(SettingSource::Db, Some("true")).is_pending_restart(None));
        // 起動時も現在も DB 上書きが無い → 反映済み。
        assert!(!setting(SettingSource::Env, Some("false")).is_pending_restart(None));
    }

    /// 出所区分が `DbManaged` から `EnvLocked` へ変わったキー（ADR-0012 の
    /// `PUBLIC_WEB_BASE_URL`・`COOKIE_DOMAIN`）の `system_settings` 行が残っていても未反映にしない。
    ///
    /// `EnvLocked` は解決時に DB を見ないので `source` が `Db` になり得ず、突き合わせると永遠に
    /// 未反映と出る。しかも `editable` が false で画面から消せないため、再起動しても消えない警告が
    /// 居座ることになる。残存行は設定の解決に影響しない（無視される）ので未反映ではない。
    #[test]
    fn stale_rows_for_env_locked_keys_are_not_reported_as_pending() {
        let env_locked = ResolvedSetting {
            key: "PUBLIC_WEB_BASE_URL".to_string(),
            owner: SettingOwner::EnvLocked,
            // EnvLocked は DB を参照しないため、DB 行があっても source は Env / Builtin にしかならない。
            source: SettingSource::Env,
            secret: false,
            restart_required: true,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: Some("https://idp.example.com".to_string()),
            default_value: None,
            description: String::new(),
        };
        assert!(!env_locked.is_pending_restart(Some("https://old.example.com")));
        assert!(!env_locked.is_pending_restart(None));

        // Builtin（常に既定値）も同じ理由で対象外。
        let builtin = ResolvedSetting {
            key: "BIND_ADDR".to_string(),
            owner: SettingOwner::Builtin,
            source: SettingSource::Builtin,
            ..env_locked.clone()
        };
        assert!(!builtin.is_pending_restart(Some("0.0.0.0:9999")));
    }

    /// 再起動不要のキーは参照のたびに DB を読むため常に反映済み。secret は平文をスナップショットに
    /// 残さない（比較できない）ため未反映とは判定しない。
    #[test]
    fn pending_restart_is_never_reported_for_live_or_secret_settings() {
        let base = ResolvedSetting {
            key: "SMTP_HOST".to_string(),
            owner: SettingOwner::DbManaged,
            source: SettingSource::Db,
            secret: false,
            restart_required: false,
            default_risk: DefaultRisk::Safe,
            status: SettingSafetyStatus::Safe,
            reason: String::new(),
            value: Some("old".to_string()),
            default_value: None,
            description: String::new(),
        };
        assert!(!base.is_pending_restart(Some("new")));

        let secret = ResolvedSetting {
            secret: true,
            restart_required: true,
            value: None,
            ..base.clone()
        };
        assert!(!secret.is_pending_restart(Some("new")));
    }

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
        // スキームは大小を区別しない（RFC 3986 §3.1）ため小文字化する。これが無いと
        // `HTTPS://` 表記で Cookie の Secure 判定・本番シークレットの fail-fast がすり抜ける。
        // ホストは ID Token の `iss` と完全一致させる必要があるためそのまま残す。
        assert_eq!(
            normalize_issuer("HTTPS://IdP.example.com/".to_string()),
            "https://IdP.example.com"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        // https issuer + 開発用デフォルト → 構成エラー（fail-fast）。
        assert!(ensure_production_secrets("https://idp.example.com", true, false, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, true, false).is_err());
        assert!(ensure_production_secrets("https://idp.example.com", false, false, true).is_err());
        // 全部明示設定されていれば https でも起動できる。
        assert!(ensure_production_secrets("https://idp.example.com", false, false, false).is_ok());
        // http（ローカル開発）は開発用デフォルトを許容する（起動時 warning のみ）。
        assert!(ensure_production_secrets("http://localhost:8080", true, true, true).is_ok());
    }

    #[test]
    fn secret_decode_rejects_template_placeholder_with_guidance() {
        // `.env.*.example` の CHANGE-ME 残りは base64 エラーではなく原因と対処を明示する。
        let err = decode_secret_32("KEY_ENCRYPTION_KEY", "CHANGE-ME").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHANGE-ME"), "message was: {msg}");
        assert!(
            msg.contains("openssl rand -base64 32"),
            "message was: {msg}"
        );
    }

    #[test]
    fn secret_decode_accepts_32_bytes_and_reports_bad_input() {
        let encoded = STANDARD.encode([7u8; 32]);
        assert_eq!(
            decode_secret_32("KEY_ENCRYPTION_KEY", &encoded).unwrap(),
            [7u8; 32]
        );
        // 前後空白は許容する（.env の手編集で紛れ込みやすい）。
        assert_eq!(
            decode_secret_32("KEY_ENCRYPTION_KEY", &format!(" {encoded}\n")).unwrap(),
            [7u8; 32]
        );
        let short = decode_secret_32("CSRF_SECRET", &STANDARD.encode([7u8; 16])).unwrap_err();
        assert!(short.to_string().contains("32 bytes, got 16"));
        let not_base64 = decode_secret_32("CSRF_SECRET", "not/base64!!").unwrap_err();
        assert!(not_base64.to_string().contains("openssl rand -base64 32"));
    }

    #[test]
    fn db_managed_settings_override_builtin_defaults() {
        let _env = env_guard();
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 7);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Db);
        assert_eq!(rotation.owner, SettingOwner::DbManaged);
    }

    #[test]
    fn db_managed_settings_override_env() {
        // 「あとから DB で上書きできる」思想: DB_MANAGED キーは DB 値が ENV を上書きする。
        let _env = env_guard();
        std::env::set_var("KEY_ROTATION_LEAD_DAYS", "14");
        let db = HashMap::from([("KEY_ROTATION_LEAD_DAYS".to_string(), "7".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 7);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Db);
        // ENV しか無ければ ENV が有効（既定値 < ENV）。
        std::env::set_var("KEY_ROTATION_LEAD_DAYS", "21");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.key_rotation_lead_days(), 21);
        let rotation = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "KEY_ROTATION_LEAD_DAYS")
            .unwrap();
        assert_eq!(rotation.source, SettingSource::Env);
        std::env::remove_var("KEY_ROTATION_LEAD_DAYS");
    }

    /// MT26 / ADR-0013: api と web が共有するランタイム設定も DB 上書きを受け付ける
    /// （web は起動時に api の `/internal/runtime-settings` から同じ値を受け取る）。
    #[test]
    fn shared_web_runtime_settings_are_db_managed() {
        let _env = env_guard();
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
        let db = HashMap::from([
            ("AUTH_SESSION_TTL_SECS".to_string(), "1200".to_string()),
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.auth_session_ttl(), Duration::from_secs(1_200));
        assert!(config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 31_536_000);
        for key in ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"] {
            let setting = config
                .resolved_settings()
                .iter()
                .find(|setting| setting.key == key)
                .unwrap();
            assert_eq!(setting.owner, SettingOwner::DbManaged, "{key}");
            assert_eq!(setting.source, SettingSource::Db, "{key}");
        }
    }

    #[test]
    fn env_locked_settings_ignore_db_values() {
        let _env = env_guard();
        std::env::remove_var("DB_MAX_CONNECTIONS");
        let db = HashMap::from([("DB_MAX_CONNECTIONS".to_string(), "99".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.db_max_connections(), 10);
        let db_max = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "DB_MAX_CONNECTIONS")
            .unwrap();
        assert_eq!(db_max.owner, SettingOwner::EnvLocked);
        assert_eq!(db_max.source, SettingSource::Builtin);
    }

    #[test]
    fn resolved_settings_flag_dangerous_bootstrap_defaults_without_exposing_values() {
        let _env = env_guard();
        std::env::remove_var("KEY_ENCRYPTION_KEY");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        for key in [
            "KEY_ENCRYPTION_KEY",
            "INTERNAL_SERVICE_TOKEN",
            "CSRF_SECRET",
            "COOKIE_SECURE",
            "HSTS_MAX_AGE",
        ] {
            let setting = settings.iter().find(|setting| setting.key == key).unwrap();
            assert_eq!(setting.status, SettingSafetyStatus::NeedsAction);
            assert!(!setting.reason.contains("idp-dev-insecure"));
        }
    }

    #[test]
    fn explicit_secure_cookie_and_hsts_are_marked_safe() {
        let _env = env_guard();
        std::env::set_var("COOKIE_SECURE", "true");
        std::env::set_var("HSTS_MAX_AGE", "31536000");

        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        let settings = config.resolved_settings();
        let cookie = settings
            .iter()
            .find(|setting| setting.key == "COOKIE_SECURE")
            .unwrap();
        let hsts = settings
            .iter()
            .find(|setting| setting.key == "HSTS_MAX_AGE")
            .unwrap();
        assert_eq!(cookie.status, SettingSafetyStatus::Safe);
        assert_eq!(hsts.status, SettingSafetyStatus::Safe);

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
    }

    #[test]
    fn cookie_domain_is_validated_at_startup() {
        let _env = env_guard();
        set_production_secrets();
        std::env::set_var("ISSUER", "http://api.example.com");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com");

        // 両オリジンの親ドメインなら受理し、正規化した値を保持する。
        std::env::set_var("COOKIE_DOMAIN", ".Example.com");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.cookie_domain(), Some("example.com"));

        // 片方の親でない・public suffix は起動を失敗させる（fail-fast）。
        std::env::set_var("COOKIE_DOMAIN", "other.com");
        assert!(Config::from_env_and_db_settings(&HashMap::new()).is_err());
        std::env::set_var("COOKIE_DOMAIN", "com");
        assert!(Config::from_env_and_db_settings(&HashMap::new()).is_err());

        // 未設定 = host-only（従来挙動）。
        std::env::remove_var("COOKIE_DOMAIN");
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.cookie_domain(), None);

        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        clear_production_secrets();
    }

    /// ADR-0017: ISSUER は DB 上書きを受ける（ディスカバリ文書と `iss` が `http://localhost:8080`
    /// のまま直せない、という状態を無くすため）。ENV より DB が優先される。
    #[test]
    fn issuer_is_overridden_by_db_settings() {
        let _env = env_guard();
        // DB 上書き後の issuer はループバック以外なので本番相当になる（SEC11）。
        set_production_secrets();
        std::env::set_var("ISSUER", "http://localhost:8080");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");

        let db = HashMap::from([("ISSUER".to_string(), "http://idp.example.test/".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        // 末尾スラッシュは正規化される（`iss` と完全一致させるため）。
        assert_eq!(config.issuer(), "http://idp.example.test");
        // PUBLIC_WEB_BASE_URL 未設定なら issuer と同一オリジン。DB 上書きがそこまで届く。
        assert_eq!(config.public_web_base_url(), "http://idp.example.test");

        let setting = config
            .resolved_settings()
            .iter()
            .find(|s| s.key == "ISSUER")
            .cloned()
            .unwrap();
        assert_eq!(setting.owner, SettingOwner::DbManaged);
        assert_eq!(setting.source, SettingSource::Db);
        assert_eq!(setting.value.as_deref(), Some("http://idp.example.test/"));

        // DB 上書きが無ければ ENV へ戻る。
        let config = Config::from_env_and_db_settings(&HashMap::new()).unwrap();
        assert_eq!(config.issuer(), "http://localhost:8080");

        std::env::remove_var("ISSUER");
        clear_production_secrets();
    }

    #[test]
    fn public_web_base_url_is_env_locked_and_ignores_db() {
        // ADR-0012 §2: api/web で同一値必須のため DbManaged → EnvLocked へ変更。DB 値は無視される。
        let _env = env_guard();
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("ISSUER");
        let db = HashMap::from([(
            "PUBLIC_WEB_BASE_URL".to_string(),
            "http://db-managed.example.com".to_string(),
        )]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        // DB 値ではなく既定（issuer と同一オリジン）へフォールバックする。
        assert_eq!(config.public_web_base_url(), config.issuer());
        let setting = config
            .resolved_settings()
            .iter()
            .find(|setting| setting.key == "PUBLIC_WEB_BASE_URL")
            .unwrap();
        assert_eq!(setting.owner, SettingOwner::EnvLocked);
        assert_eq!(setting.source, SettingSource::Builtin);
    }

    /// レビュー修正の回帰テスト: `LOGIN_MAX_FAILED_ATTEMPTS` の i32 超過値は負数へラップさせず
    /// i32::MAX へ飽和させる（ラップすると初回失敗で即ロックという逆の挙動になる）。
    #[test]
    fn oversized_lockout_threshold_saturates_instead_of_wrapping() {
        let _env = env_guard();
        std::env::remove_var("LOGIN_MAX_FAILED_ATTEMPTS");
        let db = HashMap::from([(
            "LOGIN_MAX_FAILED_ATTEMPTS".to_string(),
            u32::MAX.to_string(),
        )]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.login_lockout().max_failed_attempts, i32::MAX);
        // 通常値はそのまま。
        let db = HashMap::from([("LOGIN_MAX_FAILED_ATTEMPTS".to_string(), "5".to_string())]);
        let config = Config::from_env_and_db_settings(&db).unwrap();
        assert_eq!(config.login_lockout().max_failed_attempts, 5);
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
