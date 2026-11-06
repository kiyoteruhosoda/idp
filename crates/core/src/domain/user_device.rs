//! 利用者の端末（task #872。ADR-0071）。
//!
//! 「自分の端末」の一覧を持ち、**それ以外の端末からのログインに気付けるようにする**ための型。
//! 端末は、web がブラウザに置く長く残る Cookie（端末の印）で見分ける。印の平文は web とブラウザの
//! 間だけにあり、assay は SHA-256（[`DeviceRef`]）だけを持つ。
//!
//! # 端末の印で何が分かり、何が分からないか
//!
//! 印は「同じブラウザのプロファイルから来た」ことしか示さない。Cookie を消した・シークレット
//! ウィンドウ・別のブラウザは**新しい端末**になる。逆に、印を盗まれれば別の端末が登録済みの端末を
//! 名乗れる（印を端末の鍵へ結び付けるのは task #875）。ここで気付けるのは、パスワードやパスキーを
//! 盗まれて**別の端末で新しくログインされた**場合である。
//!
//! # 判定に使わないもの
//!
//! ブラウザの名乗り（User-Agent）と国は表示と知らせのためだけに持つ。どちらも送る側が自由に書ける
//! ので、「登録済みか」の判定は印だけで行う。

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::domain::crypto;
use crate::domain::sso_session::SsoSession;
use crate::domain::values::AuthenticationMethod;

/// 登録してから使われないまま、この日数が過ぎた端末は登録が切れる。
pub const UNUSED_DEVICE_EXPIRY_DAYS: i64 = 180;

/// 端末を登録できるのは、パスキーで本人を確かめてからこの秒数のあいだだけ。
pub const REGISTRATION_PASSKEY_MAX_AGE_SECS: i64 = 300;

/// ログイン状態が作られてから、端末を結び付けてよい秒数。
///
/// web はログインの応答を返すその場で結び付けを頼むので、通常は 1 秒もかからない。古いセッションへ
/// 後から別の端末を結び付けさせない（他人のセッション id を知った者が、自分の印で上書きできない）。
pub const OBSERVATION_WINDOW_SECS: i64 = 120;

/// 端末の名前の長さの上限（文字数）。
pub const MAX_DEVICE_NAME_CHARS: usize = 100;

/// 端末の印（Cookie の値）の平文の長さ（16 進の文字数）。web が [`crypto::random_hex`] の 32 バイトで作る。
pub const DEVICE_TOKEN_HEX_LEN: usize = 64;

/// 端末の印の SHA-256（DB に置く値）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceRef(String);

impl DeviceRef {
    /// web から届いた印の平文から作る。形が違う値（長さ・16 進以外）は受け付けない。
    ///
    /// ⚠ 平文は誰でも作れる乱数なので、形を確かめるのは「壊れた値や巨大な値を DB へ流さない」ためだけ。
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        if token.len() != DEVICE_TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self(crypto::sha256_hex(&token.to_ascii_lowercase())))
    }

    /// DB から読んだ指紋を包む。
    pub fn from_hash(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 国コード（Cloudflare の `CF-IPCountry`。ISO 3166-1 alpha-2、`XX`＝不明、`T1`＝Tor）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryCode(String);

impl CountryCode {
    /// 2 文字の英数字だけを受け付ける（大文字へ揃える）。それ以外と「不明」（`XX`）は `None`。
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.len() != 2 || !raw.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        let upper = raw.to_ascii_uppercase();
        if upper == "XX" {
            return None;
        }
        Some(Self(upper))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 名前を整える。前後の空白を落とし、空・長すぎ・制御文字入りは `None`。
pub fn normalize_device_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.chars().count() > MAX_DEVICE_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return None;
    }
    Some(name.to_string())
}

/// 登録済みの端末。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDevice {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device: DeviceRef,
    pub name: String,
    pub user_agent: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub last_country: Option<CountryCode>,
    pub last_ip: Option<String>,
}

impl UserDevice {
    /// 新しく登録する端末。登録した時刻を「最後に使った時刻」とする。
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        id: Uuid,
        user_id: Uuid,
        device: DeviceRef,
        name: String,
        user_agent: Option<String>,
        country: Option<CountryCode>,
        ip: Option<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            user_id,
            device,
            name,
            user_agent,
            registered_at: now,
            last_used_at: now,
            last_country: country,
            last_ip: ip,
        }
    }

    /// 登録が切れる時刻（最後に使ってから [`UNUSED_DEVICE_EXPIRY_DAYS`] 日）。
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.last_used_at + Duration::days(UNUSED_DEVICE_EXPIRY_DAYS)
    }
}

/// パスキーで本人を確かめてから [`REGISTRATION_PASSKEY_MAX_AGE_SECS`] 秒以内か。
///
/// パスキーでログインした直後（セッションの方式に `WebAuthn` があり `auth_time` が新しい）か、
/// 後からパスキーで確かめた直後（`passkey_verified_at`）。⚠ `step_up_at` は見ない ——パスワードの
/// 再確認でも進むので、そこからは「パスキーで確かめたか」が分からない。
pub fn passkey_verified_recently(
    session: &SsoSession,
    passkey_verified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let max_age = Duration::seconds(REGISTRATION_PASSKEY_MAX_AGE_SECS);
    (session.used_method(AuthenticationMethod::WebAuthn) && now - session.auth_time <= max_age)
        || passkey_verified_at.is_some_and(|at| now - at <= max_age)
}

/// この時刻より前から使われていない端末は登録が切れている。
pub fn unused_device_cutoff(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::days(UNUSED_DEVICE_EXPIRY_DAYS)
}

/// ログインした端末の判定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInDevice {
    /// 登録済みの端末（名前）。
    Registered { device_id: Uuid, name: String },
    /// 登録していない端末（印はある）。
    Unregistered,
    /// 印が届かなかった（web が置けなかった・壊れた値）。登録していない端末として扱う。
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_tokens_must_be_64_hex_characters() {
        let token = "a".repeat(64);
        let reference = DeviceRef::from_token(&token).expect("valid token");
        assert_eq!(reference.as_str().len(), 64);
        assert_ne!(reference.as_str(), token, "only the digest is kept");
        assert!(DeviceRef::from_token(&"a".repeat(63)).is_none());
        assert!(DeviceRef::from_token(&"g".repeat(64)).is_none());
        assert!(DeviceRef::from_token("").is_none());
    }

    #[test]
    fn device_tokens_are_case_insensitive() {
        assert_eq!(
            DeviceRef::from_token(&"AB".repeat(32)),
            DeviceRef::from_token(&"ab".repeat(32))
        );
    }

    #[test]
    fn country_codes_are_two_characters_and_unknown_is_dropped() {
        assert_eq!(CountryCode::parse("jp").unwrap().as_str(), "JP");
        assert_eq!(CountryCode::parse("T1").unwrap().as_str(), "T1");
        assert!(CountryCode::parse("XX").is_none());
        assert!(CountryCode::parse("JPN").is_none());
        assert!(CountryCode::parse("J-").is_none());
        assert!(CountryCode::parse("").is_none());
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_device_name("  kyon-pc ").as_deref(),
            Some("kyon-pc")
        );
        assert!(normalize_device_name("   ").is_none());
        assert!(normalize_device_name(&"あ".repeat(MAX_DEVICE_NAME_CHARS + 1)).is_none());
        assert!(normalize_device_name(&"あ".repeat(MAX_DEVICE_NAME_CHARS)).is_some());
        assert!(normalize_device_name("a\nb").is_none());
    }

    #[test]
    fn devices_expire_after_being_unused_for_180_days() {
        let now = Utc::now();
        let device = UserDevice::register(
            Uuid::now_v7(),
            Uuid::now_v7(),
            DeviceRef::from_token(&"a".repeat(64)).unwrap(),
            "pc".to_string(),
            None,
            None,
            None,
            now,
        );
        assert_eq!(device.expires_at(), now + Duration::days(180));
        assert_eq!(unused_device_cutoff(now), now - Duration::days(180));
    }
}

/// 今の要求のブラウザの端末の印（web が内部の呼び出しに添えた平文。task #916）。
///
/// 登録した端末に限る組織で、ログインを成立させてよいかを決める所（[`crate::application::device_enrollment::DeviceGate`]）
/// が引く。要求の外（見回りなど）や、外から直接 api に来た要求では `None`。
pub trait RequestDevice: Send + Sync {
    fn current(&self) -> Option<DeviceRef>;
}

/// 端末の印を持たない（試験・要求の外）。
pub struct NoRequestDevice;

impl RequestDevice for NoRequestDevice {
    fn current(&self) -> Option<DeviceRef> {
        None
    }
}
