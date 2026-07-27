//! web サービスの設定（ADR-0007）。
//!
//! web は DB を持たないため、api とは別の（小さな）設定を持つ。取得は必ず本モジュール経由で行い、
//! 生の環境変数を各所で直接参照しない。優先順位は
//! **「既定値 < 環境変数（ENV）< api 経由の DB 上書き値」**（MT26 / ADR-0013）。
//! （空文字列は「未設定」として扱う。Compose の `${VAR:-}` 対策は api の config と同じ方針。）
//!
//! api 経由の DB 上書きを受けるのは、api と web の**両方が消費する**共有キー
//! （`ISSUER`・`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS`）だけ。web 固有のキー
//! （`WEB_BIND_ADDR`・`API_BASE_URL`）と bootstrap secret（`INTERNAL_SERVICE_TOKEN`・
//! `CSRF_SECRET`）、api/web で一致必須の `PUBLIC_WEB_BASE_URL`・`COOKIE_DOMAIN` は ENV > 既定値のまま。
#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use idp_contracts::cookies::CookiePolicy;
use std::collections::HashMap;
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
    /// web 自身の公開オリジン（ADR-0012 §2。Cookie `Secure` 判定・絶対 URL 生成に使う）。
    /// api 側の `PUBLIC_WEB_BASE_URL` と同一値を設定する。未設定なら issuer と同一オリジン
    /// （単一オリジン構成）。
    public_web_base_url: String,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    csrf_secret: [u8; 32],
    csrf_secret_is_dev: bool,
    /// Cookie の属性方針（`Secure` + サービス横断 Cookie の `Domain`。ADR-0012 §2・§3）。
    /// `Domain` は api 側の `COOKIE_DOMAIN` と同一値を設定する。`None` = host-only（従来挙動）。
    cookie_policy: CookiePolicy,
    auth_session_ttl_secs: u64,
    /// HSTS `max-age`（秒）。0 = HSTS ヘッダを付与しない（api 側と同キー `HSTS_MAX_AGE`）。
    hsts_max_age: u64,
    log_format: LogFormat,
    /// api 経由の DB 上書き値を採用した共有キー（起動ログ用。値は含めない）。
    shared_settings_from_api: Vec<String>,
    /// 起動時に api から受け取った共有ランタイム設定のスナップショット（MT27）。
    ///
    /// 設定画面で「web に未反映の共有キー」を出すために保持する。api の再起動でスナップショットが
    /// 更新されても web は起動時の値を使い続けるため、両者を突き合わせないと**api だけが新しい値で
    /// 動いている**状態が誰にも見えない（ADR-0013 §Consequences）。secret はこの経路に載らない
    /// （ADR-0013 §3）ので保持して問題ない。
    shared_runtime_settings: HashMap<String, String>,
}

/// api へ問い合わせるために必要な最小の設定（MT26 / ADR-0013）。
///
/// **共有キー（`COOKIE_SECURE`・`HSTS_MAX_AGE`・`AUTH_SESSION_TTL_SECS`）には触れない。**
/// ここで ENV の共有キーをパースしてしまうと、ENV に不正値があるだけで（DB に正しい上書きが
/// あっても）api へ問い合わせる前に起動が失敗し、`ENV < DB` の優先順位で復旧できなくなる。
///
/// 一方 bootstrap secret は `EnvLocked` で DB からは直せないため、**ここで fail-fast する**
/// （api 未到達のときに「api へ繋がらない」ではなく本来の設定誤りを先に見せるため）。
///
/// `ISSUER` は DB 上書きを受ける（ADR-0017）が、ここではまだ api へ問い合わせていないので ENV 値で
/// 判定する。DB 上書きが https で ENV が http の構成では本段では素通りし、共有設定を受け取ってから
/// [`Config::from_env_and_shared_settings`] が同じ検査で落とす。api 側も保存時に同じ組み合わせを
/// 拒否する（`domain::system_setting::ensure_override_is_bootable`）ため、この経路には通常入らない。
#[derive(Debug, Clone)]
pub struct Bootstrap {
    api_base_url: String,
    internal_service_token: String,
    internal_service_token_is_dev: bool,
    log_format: LogFormat,
}

impl Bootstrap {
    pub fn from_env() -> anyhow::Result<Self> {
        let issuer = normalize_base_url(env_or("ISSUER", "http://localhost:8080"));
        let public_web_base_url = normalize_base_url(env_or("PUBLIC_WEB_BASE_URL", &issuer));
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (v, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        // base64 の形式検証も兼ねる（DB では直せない値なので早く落とす）。
        let (_, csrf_secret_is_dev) = load_csrf_secret()?;
        ensure_production_secrets(
            &issuer,
            &public_web_base_url,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        Ok(Self {
            api_base_url: normalize_base_url(env_or("API_BASE_URL", "http://localhost:8080")),
            internal_service_token,
            internal_service_token_is_dev,
            log_format: parse_log_format(),
        })
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }
    pub fn internal_service_token(&self) -> &str {
        &self.internal_service_token
    }
    pub fn internal_service_token_is_dev(&self) -> bool {
        self.internal_service_token_is_dev
    }
    pub fn log_format(&self) -> LogFormat {
        self.log_format
    }
}

impl Config {
    /// 環境変数と既定値だけで組み立てる（api の DB 上書きを反映しない）。api を起動しない
    /// テスト専用。実際の起動経路は
    /// [`from_env_and_shared_settings`](Self::from_env_and_shared_settings)。
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_env_and_shared_settings(&HashMap::new())
    }

    /// api から受け取った共有ランタイム設定の DB 上書き値を最優先に、設定を解決する
    /// （MT26 / ADR-0013。優先順位は 既定値 < ENV < `shared`）。
    ///
    /// `shared` に無いキーは従来どおり ENV → 既定値へフォールバックする。とくに `COOKIE_SECURE` の
    /// 既定は **web 自身の公開オリジン**のスキームであり（ADR-0012 §2）、api の既定を引き継がない。
    pub fn from_env_and_shared_settings(shared: &HashMap<String, String>) -> anyhow::Result<Self> {
        let resolver = SharedSettingResolver::new(shared);
        // api の公開オリジン（= OIDC issuer。ブラウザを api へ向けるリダイレクトの基点）。
        // ADR-0017 で DB 管理へ移したため、api から受け取った上書き値を最優先で採る。
        let issuer = normalize_base_url(resolver.string("ISSUER", "http://localhost:8080"));
        // web 自身の公開オリジン（ADR-0012 §2）。未設定は issuer と同一オリジン（単一オリジン構成）。
        let public_web_base_url = normalize_base_url(env_or("PUBLIC_WEB_BASE_URL", &issuer));
        // Cookie の Secure 属性。既定は自オリジン（PUBLIC_WEB_BASE_URL）のスキームに従う
        // （ADR-0012 §2。issuer ではなく web 自身の公開スキームで判定する）。
        let cookie_secure =
            resolver.parse("COOKIE_SECURE", public_web_base_url.starts_with("https://"))?;
        // サービス横断 Cookie の Domain 属性。api 側と同じ検証（親ドメイン整合・public suffix 拒否）を
        // 起動時に行う（不整合はログインループになるため fail-fast）。
        let cookie_domain = match env_lookup("COOKIE_DOMAIN") {
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
        let (internal_service_token, internal_service_token_is_dev) =
            match env_lookup("INTERNAL_SERVICE_TOKEN") {
                Some(v) => (v, false),
                None => (DEV_INTERNAL_SERVICE_TOKEN.to_string(), true),
            };
        let (csrf_secret, csrf_secret_is_dev) = load_csrf_secret()?;
        // 本番（https issuer）では開発用デフォルトのトークンで起動しない（fail-fast。api 側と同方針）。
        ensure_production_secrets(
            &issuer,
            &public_web_base_url,
            internal_service_token_is_dev,
            csrf_secret_is_dev,
        )?;
        Ok(Self {
            bind_addr: env_or("WEB_BIND_ADDR", "0.0.0.0:8081"),
            // api への到達先。単一オリジン構成ではプロキシ内部アドレス、ローカルでは api の直アドレス。
            api_base_url: normalize_base_url(env_or("API_BASE_URL", "http://localhost:8080")),
            public_web_base_url,
            internal_service_token,
            internal_service_token_is_dev,
            csrf_secret,
            csrf_secret_is_dev,
            cookie_policy,
            auth_session_ttl_secs: resolver
                .parse("AUTH_SESSION_TTL_SECS", DEFAULT_AUTH_SESSION_TTL_SECS)?,
            hsts_max_age: resolver.parse("HSTS_MAX_AGE", 0u64)?,
            log_format: parse_log_format(),
            shared_settings_from_api: resolver.applied_keys(),
            shared_runtime_settings: shared.clone(),
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
    /// web 自身の公開オリジン（末尾スラッシュ無し。ADR-0012 §2）。
    pub fn public_web_base_url(&self) -> &str {
        &self.public_web_base_url
    }
    /// web が組み立てる Cookie に `Secure` を付けるか（api の応答値を Cookie 化する際に使う）。
    pub fn cookie_secure(&self) -> bool {
        self.cookie_policy.secure()
    }
    /// サービス横断 Cookie（sso_session_id・auth_session_id）に付与する `Domain` 属性（ADR-0012 §3）。
    /// api と同じ値を設定する。`None` = host-only（単一オリジン構成の従来挙動）。
    pub fn cookie_domain(&self) -> Option<&str> {
        self.cookie_policy.domain()
    }
    /// Cookie の属性方針。Cookie の発行・失効は必ずこれを経由する（ADR-0012 §3。`Domain` を
    /// 渡し忘れた発行箇所が生まれないようにするため）。通常は `WebState::set_cookies()` を使う。
    pub fn cookie_policy(&self) -> &CookiePolicy {
        &self.cookie_policy
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
    /// api 経由の DB 上書き値を採用した共有キー名（起動ログ用。**値は含めない**）。
    pub fn shared_settings_from_api(&self) -> &[String] {
        &self.shared_settings_from_api
    }

    /// 起動時に api から受け取った共有ランタイム設定。設定画面が現在の api のスナップショットと
    /// 突き合わせ、web への未反映を検出するために使う（MT27）。
    pub fn shared_runtime_settings(&self) -> &HashMap<String, String> {
        &self.shared_runtime_settings
    }
}

/// 起動時に web が適用した共有設定と、api が現在配っている共有設定を突き合わせ、**web に未反映の
/// キー**を返す（MT27）。返すのはキー名だけで、値は含めない。
///
/// api の再起動は新しい値の公開そのもの（ADR-0013 §1-a）なので、api が再起動して web が
/// そのままなら、api だけが新しい値で動いている。逆向き（web だけが新しい値）はスナップショット
/// 方式により構造的に起きない。
pub fn stale_shared_settings(
    applied: &HashMap<String, String>,
    current: &HashMap<String, String>,
) -> Vec<String> {
    let mut keys: Vec<String> = current
        .iter()
        .filter(|(key, value)| applied.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        // 上書きが解除されたキー（api 側から消えた）も未反映。
        .chain(
            applied
                .keys()
                .filter(|key| !current.contains_key(*key))
                .cloned(),
        )
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// 「既定値 < ENV < api 経由の DB 上書き値」で共有キーを解決する（MT26 / ADR-0013）。
///
/// どのキーが DB 由来だったかを記録し、起動ログで運用者に見せる（設定画面の値と実際に効いている値が
/// 食い違ったときの切り分けに要る）。
struct SharedSettingResolver<'a> {
    shared: &'a HashMap<String, String>,
    applied: std::cell::RefCell<Vec<String>>,
}

impl<'a> SharedSettingResolver<'a> {
    fn new(shared: &'a HashMap<String, String>) -> Self {
        Self {
            shared,
            applied: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// 有効値を文字列で解決する（DB 上書き > ENV。どちらも無ければ `None`）。
    fn optional_string(&self, key: &str) -> Option<String> {
        if let Some(v) = self.shared.get(key).filter(|v| !v.is_empty()) {
            self.applied.borrow_mut().push(key.to_string());
            return Some(v.clone());
        }
        env_lookup(key)
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

    /// 有効値を文字列で解決する（DB 上書き > ENV > 既定値）。
    fn string(&self, key: &str, default: &str) -> String {
        self.optional_string(key)
            .unwrap_or_else(|| default.to_string())
    }

    fn applied_keys(&self) -> Vec<String> {
        self.applied.borrow().clone()
    }
}

/// 本番相当で開発用デフォルトのシークレットが使われていたら起動を失敗させる。
///
/// 本番相当の判定には **issuer と web 自身の公開オリジンの両方**を見る（ADR-0012 §2 で web は
/// 自身の公開オリジンを持つようになったため）。どちらか一方でも `https://` なら公開配置とみなす。
/// issuer だけを見ていると、`PUBLIC_WEB_BASE_URL` が https の公開配置で `ISSUER` を内部 http URL に
/// 取り違えた構成が素通りし、api と共有する `CSRF_SECRET` が既知の開発用値のまま動いてしまう
/// （CSRF トークンを誰でも偽造できる）。
fn ensure_production_secrets(
    issuer: &str,
    public_web_base_url: &str,
    internal_service_token_is_dev: bool,
    csrf_secret_is_dev: bool,
) -> anyhow::Result<()> {
    let public_origin = if issuer.starts_with("https://") {
        issuer
    } else if public_web_base_url.starts_with("https://") {
        public_web_base_url
    } else {
        return Ok(());
    };
    if internal_service_token_is_dev {
        anyhow::bail!(
            "the public origin is https ({public_origin}) but INTERNAL_SERVICE_TOKEN is not set; \
             refusing to start with the built-in development token. \
             Set INTERNAL_SERVICE_TOKEN (shared with api) in production."
        );
    }
    if csrf_secret_is_dev {
        anyhow::bail!(
            "the public origin is https ({public_origin}) but CSRF_SECRET is not set; \
             refusing to start with the built-in development secret. \
             Set CSRF_SECRET (base64, 32 bytes, shared with api) in production."
        );
    }
    Ok(())
}

/// `CSRF_SECRET`（base64、32 バイト）を読み込む。未設定なら開発用デフォルトを使う。
///
/// `.env.*.example` のプレースホルダ `CHANGE-ME` が残ったまま起動されるケースが実際に多い
/// （素の base64 エラーでは原因に辿り着けない）ため、プレースホルダは base64 復号より先に
/// 検出し、対処（`openssl rand -base64 32`）まで案内する（api 側 `decode_secret_32` と同方針）。
fn load_csrf_secret() -> anyhow::Result<([u8; 32], bool)> {
    match env_lookup("CSRF_SECRET") {
        Some(v) => {
            let v = v.trim();
            if v.contains("CHANGE-ME") {
                anyhow::bail!(
                    "CSRF_SECRET is still the .env template placeholder \"CHANGE-ME\"; \
                     replace it with a real value (generate with `openssl rand -base64 32`, \
                     shared with api)"
                );
            }
            let bytes = STANDARD.decode(v).map_err(|e| {
                anyhow::anyhow!(
                    "CSRF_SECRET must be base64 (generate with `openssl rand -base64 32`): {e}"
                )
            })?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("CSRF_SECRET must decode to exactly 32 bytes"))?;
            Ok((arr, false))
        }
        None => Ok((*DEV_CSRF_SECRET, true)),
    }
}

/// 公開ベース URL を正規化する: 末尾スラッシュを落とし、**スキームを小文字化**する。
///
/// URI のスキームは大小を区別しない（RFC 3986 §3.1）。`HTTPS://id.example.com` のような表記でも
/// https と判定できないと、Cookie の `Secure` 判定と本番シークレットの fail-fast（どちらも
/// スキームを見る）がすり抜ける。ホスト・パスはそのまま残す（issuer は ID Token の `iss` と
/// 完全一致させる必要があるため、こちらで勝手に変えない）。
fn normalize_base_url(raw: String) -> String {
    let trimmed = raw.trim_end_matches('/');
    match trimmed.split_once("://") {
        Some((scheme, rest)) => format!("{}://{rest}", scheme.to_ascii_lowercase()),
        None => trimmed.to_string(),
    }
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

/// `LOG_FORMAT`（`EnvLocked`）を読む。未知の値は既定の JSON へ倒す（ログ初期化を失敗させない）。
fn parse_log_format() -> LogFormat {
    match env_or("LOG_FORMAT", "json").to_ascii_lowercase().as_str() {
        "pretty" => LogFormat::Pretty,
        _ => LogFormat::Json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// プロセス共有の環境変数を触るテストを直列化するためのロック（`cargo test` はスレッド並列）。
    /// `Config::from_env*` を呼ぶテストは必ずこれを取得する。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `ENV_LOCK` を取得する。ロック保持中に別テストが panic して poison しても、排他自体は
    /// 保たれているため内側の値を取り出して継続する。
    fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn base_url_is_normalized_without_trailing_slash() {
        assert_eq!(
            normalize_base_url("http://api:8080/".to_string()),
            "http://api:8080"
        );
    }

    #[test]
    fn base_url_scheme_is_lowercased_but_host_is_left_alone() {
        // スキームは大小を区別しない（RFC 3986 §3.1）。https 判定（Cookie の Secure・本番
        // シークレットの fail-fast）が `HTTPS://` 表記をすり抜けないように正規化する。
        assert_eq!(
            normalize_base_url("HTTPS://ID.Example.com/".to_string()),
            "https://ID.Example.com"
        );
        // スキームを持たない値は素通しする（誤って壊さない）。
        assert_eq!(
            normalize_base_url("id.example.com".to_string()),
            "id.example.com"
        );
    }

    #[test]
    fn production_secrets_are_required_when_issuer_is_https() {
        let issuer = "https://idp.example.com";
        assert!(ensure_production_secrets(issuer, issuer, true, false).is_err());
        assert!(ensure_production_secrets(issuer, issuer, false, true).is_err());
        assert!(ensure_production_secrets(issuer, issuer, false, false).is_ok());
        assert!(ensure_production_secrets(
            "http://localhost:8080",
            "http://localhost:8081",
            true,
            true
        )
        .is_ok());
    }

    #[test]
    fn production_secrets_are_required_when_only_the_web_origin_is_https() {
        // ADR-0012 §2: web は自身の公開オリジンを持つ。https で公開されている以上、ISSUER の
        // スキームがどうであれ開発用シークレット（api と共有する CSRF 鍵）では起動させない。
        let err = ensure_production_secrets(
            "http://api-internal:8080",
            "https://id.example.com",
            false,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("https://id.example.com"), "{err}");
        assert!(err.contains("CSRF_SECRET"), "{err}");
        assert!(ensure_production_secrets(
            "http://api-internal:8080",
            "https://id.example.com",
            true,
            false
        )
        .is_err());
    }

    #[test]
    fn uppercase_https_scheme_is_still_treated_as_production() {
        // `HTTPS://` 表記でも fail-fast が効く（`from_env` は normalize_base_url を通すため、
        // ensure_production_secrets には小文字化済みの値が渡る）。
        let public_web_base_url = normalize_base_url("HTTPS://id.example.com".to_string());
        assert!(ensure_production_secrets(
            "http://api-internal:8080",
            &public_web_base_url,
            false,
            true
        )
        .is_err());
    }

    #[test]
    fn empty_env_var_is_treated_as_unset() {
        let key = "IDP_WEB_TEST_EMPTY";
        std::env::set_var(key, "");
        assert_eq!(env_or(key, "fallback"), "fallback");
        std::env::remove_var(key);
    }

    #[test]
    fn self_origin_and_cookie_domain_resolution() {
        let _env = env_guard();
        // 別ドメイン構成: Secure 判定は issuer ではなく自オリジン（PUBLIC_WEB_BASE_URL）に従う
        // （ADR-0012 §2）。http の自オリジンなら Secure なし。
        std::env::set_var("ISSUER", "http://api.example.com");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com/");
        std::env::set_var("COOKIE_DOMAIN", "example.com");
        let config = Config::from_env().unwrap();
        assert_eq!(config.public_web_base_url(), "http://id.example.com");
        assert!(!config.cookie_secure());
        assert_eq!(config.cookie_domain(), Some("example.com"));

        // 両オリジンの親でない COOKIE_DOMAIN は起動を失敗させる（fail-fast）。
        std::env::set_var("COOKIE_DOMAIN", "other.com");
        assert!(Config::from_env().is_err());

        // 未設定 = host-only、自オリジンは issuer と同一（単一オリジン構成の従来挙動）。
        std::env::remove_var("COOKIE_DOMAIN");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        let config = Config::from_env().unwrap();
        assert_eq!(config.public_web_base_url(), "http://api.example.com");
        assert_eq!(config.cookie_domain(), None);

        // https の自オリジンなら Secure を付ける。判定の基準は issuer ではなく自オリジンであること
        // （ADR-0012 §2）を、http の issuer と組み合わせて固定する。
        // https 公開では開発用シークレットを拒否するため、本物の値を与える。
        std::env::set_var("INTERNAL_SERVICE_TOKEN", "test-internal-service-token");
        std::env::set_var("CSRF_SECRET", STANDARD.encode([7u8; 32]));
        std::env::set_var("PUBLIC_WEB_BASE_URL", "https://id.example.com");
        let config = Config::from_env().unwrap();
        assert!(config.cookie_secure(), "Secure follows the web origin");

        // COOKIE_SECURE の明示指定は自オリジンのスキームより優先する（プロキシ終端構成の逃げ道）。
        std::env::set_var("COOKIE_SECURE", "false");
        assert!(!Config::from_env().unwrap().cookie_secure());
        std::env::set_var("COOKIE_SECURE", "true");
        std::env::set_var("PUBLIC_WEB_BASE_URL", "http://id.example.com");
        assert!(Config::from_env().unwrap().cookie_secure());

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        std::env::remove_var("ISSUER");
    }

    /// MT26 / ADR-0013: api 経由の DB 上書き値は ENV・既定値より優先する。
    /// MT27: 起動時に web が適用した共有設定と api の現在値がずれていれば「web に未反映」。
    #[test]
    fn stale_shared_settings_reports_keys_the_web_has_not_picked_up() {
        let applied = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);

        // 完全に一致していれば未反映なし。
        assert!(stale_shared_settings(&applied, &applied).is_empty());

        // 値が変わったキーだけを挙げる。
        let changed = HashMap::from([
            ("COOKIE_SECURE".to_string(), "false".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
        ]);
        assert_eq!(
            stale_shared_settings(&applied, &changed),
            vec!["COOKIE_SECURE".to_string()]
        );

        // api 側に新しく増えたキーも未反映。
        let added = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "900".to_string()),
        ]);
        assert_eq!(
            stale_shared_settings(&applied, &added),
            vec!["AUTH_SESSION_TTL_SECS".to_string()]
        );

        // **上書きが解除された（api 側から消えた）キーも未反映**。ここを落とすと、
        // 解除したのに web だけ古い上書きで動き続けている状態が画面から見えない。
        let removed = HashMap::from([("COOKIE_SECURE".to_string(), "true".to_string())]);
        assert_eq!(
            stale_shared_settings(&applied, &removed),
            vec!["HSTS_MAX_AGE".to_string()]
        );
    }

    /// ADR-0017: `ISSUER` も api 経由の DB 上書きを受ける共有キーになった。web がこれを取りこぼすと、
    /// 単一オリジン構成で web の自オリジン（`PUBLIC_WEB_BASE_URL` 未設定時 = issuer）だけが古い
    /// `http://localhost:8080` のまま残り、api とブラウザ経路がずれる。
    #[test]
    fn issuer_from_api_overrides_env_for_the_web_origin() {
        let _env = env_guard();
        std::env::set_var("ISSUER", "http://localhost:8080");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");

        let shared = HashMap::from([("ISSUER".to_string(), "http://idp.example.test".to_string())]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert_eq!(config.public_web_base_url(), "http://idp.example.test");
        assert_eq!(config.shared_settings_from_api(), ["ISSUER"]);

        // 上書きが無ければ ENV に戻る。
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert_eq!(config.public_web_base_url(), "http://localhost:8080");

        std::env::remove_var("ISSUER");
    }

    #[test]
    fn shared_settings_from_api_take_precedence_over_env_and_defaults() {
        let _env = env_guard();
        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        // ENV 側にはあえて DB と異なる値を置き、DB が勝つことを固定する。
        std::env::set_var("COOKIE_SECURE", "false");
        std::env::set_var("HSTS_MAX_AGE", "1");
        std::env::set_var("AUTH_SESSION_TTL_SECS", "60");

        let shared = HashMap::from([
            ("COOKIE_SECURE".to_string(), "true".to_string()),
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "1200".to_string()),
        ]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert!(config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 31_536_000);
        assert_eq!(config.auth_session_ttl_secs(), 1_200);
        let mut applied = config.shared_settings_from_api().to_vec();
        applied.sort();
        assert_eq!(
            applied,
            ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"]
        );

        // DB 上書きが無ければ ENV へ、ENV も無ければ既定値へ落ちる。
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert!(!config.cookie_secure());
        assert_eq!(config.hsts_max_age(), 1);
        assert_eq!(config.auth_session_ttl_secs(), 60);
        assert!(config.shared_settings_from_api().is_empty());

        std::env::remove_var("COOKIE_SECURE");
        std::env::remove_var("HSTS_MAX_AGE");
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        let config = Config::from_env_and_shared_settings(&HashMap::new()).unwrap();
        assert!(
            !config.cookie_secure(),
            "http origin defaults to non-Secure"
        );
        assert_eq!(config.hsts_max_age(), 0);
        assert_eq!(
            config.auth_session_ttl_secs(),
            DEFAULT_AUTH_SESSION_TTL_SECS
        );
    }

    /// 空文字列の DB 上書きは「未設定」として ENV へ落とす（api 側が上書き解除に空文字列を
    /// 使うため。`system_settings.update_runtime_setting`）。
    #[test]
    fn empty_shared_override_falls_back_to_env() {
        let _env = env_guard();
        std::env::set_var("HSTS_MAX_AGE", "42");
        let shared = HashMap::from([("HSTS_MAX_AGE".to_string(), String::new())]);
        let config = Config::from_env_and_shared_settings(&shared).unwrap();
        assert_eq!(config.hsts_max_age(), 42);
        assert!(config.shared_settings_from_api().is_empty());
        std::env::remove_var("HSTS_MAX_AGE");
    }

    /// 不正な DB 上書き値は起動を失敗させる（値を黙って捨てて既定へ落ちると、設定画面の表示と
    /// 実挙動が食い違ったまま動いてしまう）。
    #[test]
    fn invalid_shared_override_fails_startup() {
        let _env = env_guard();
        std::env::remove_var("HSTS_MAX_AGE");
        let shared = HashMap::from([("HSTS_MAX_AGE".to_string(), "not-a-number".to_string())]);
        let err = Config::from_env_and_shared_settings(&shared)
            .unwrap_err()
            .to_string();
        assert!(err.contains("HSTS_MAX_AGE"), "{err}");
    }

    /// ENV の共有キーが壊れていても bootstrap は通り、DB 上書きで復旧できる（MT26 / ADR-0013）。
    /// bootstrap が共有キーをパースしてしまうと、`ENV < DB` の優先順位があるのに api へ
    /// 問い合わせる前に落ちてしまい、DB からは直せなくなる。
    #[test]
    fn bootstrap_ignores_malformed_shared_env_values_so_db_can_recover_them() {
        let _env = env_guard();
        std::env::set_var("HSTS_MAX_AGE", "not-a-number");
        std::env::set_var("AUTH_SESSION_TTL_SECS", "soon");
        std::env::set_var("API_BASE_URL", "http://api:8080/");

        // bootstrap は api へ到達するための値だけを読む → 壊れた共有キーは無視される。
        let bootstrap = Bootstrap::from_env().expect("bootstrap must not parse shared keys");
        assert_eq!(bootstrap.api_base_url(), "http://api:8080");

        // 壊れた ENV は DB 上書きで救える。
        let shared = HashMap::from([
            ("HSTS_MAX_AGE".to_string(), "31536000".to_string()),
            ("AUTH_SESSION_TTL_SECS".to_string(), "900".to_string()),
        ]);
        let config = Config::from_env_and_shared_settings(&shared).expect("DB values recover ENV");
        assert_eq!(config.hsts_max_age(), 31_536_000);
        assert_eq!(config.auth_session_ttl_secs(), 900);

        // DB 上書きが無ければ従来どおり構成エラー（壊れた ENV を黙って無視はしない）。
        assert!(Config::from_env_and_shared_settings(&HashMap::new()).is_err());

        std::env::remove_var("HSTS_MAX_AGE");
        std::env::remove_var("AUTH_SESSION_TTL_SECS");
        std::env::remove_var("API_BASE_URL");
    }

    /// bootstrap でも本番シークレットの fail-fast は効く（`EnvLocked` で DB からは直せないため、
    /// api 未到達より先に本来の設定誤りを見せる）。
    #[test]
    fn bootstrap_still_rejects_development_secrets_on_a_public_origin() {
        let _env = env_guard();
        std::env::set_var("ISSUER", "https://api.example.com");
        std::env::remove_var("INTERNAL_SERVICE_TOKEN");
        std::env::remove_var("CSRF_SECRET");
        let err = Bootstrap::from_env().unwrap_err().to_string();
        assert!(err.contains("INTERNAL_SERVICE_TOKEN"), "{err}");
        std::env::remove_var("ISSUER");
    }
}
