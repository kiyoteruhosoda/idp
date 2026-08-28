//! パスワードポリシー（AP7。ユーザー認証・認証ポリシー仕様書 §11.2）。
//!
//! 従来の要件は最小・最大文字数だけで、それは「入力そのものの形」しか見ていない。本モジュールは
//! そこへ**そのパスワードの来歴**を見る 3 つの要件を足す。
//!
//! | 要件 | 何を防ぐか | 判定に要る材料 |
//! |---|---|---|
//! | 漏えい済みパスワードの拒否 | 公開済みの資格情報リストからの詰め込み攻撃 | 外部の照合サービス（[`BreachedPasswordChecker`]） |
//! | 過去パスワードの再利用禁止 | 変更を強制しても元へ戻される | 退役ハッシュの履歴 |
//! | 有効期限 | 一度設定したまま何年も使われる | 設定時刻（`users.password_changed_at`） |
//!
//! 判定そのものはここ（Domain）に置き、材料の取得（DB・外部 API）は
//! [`crate::application::password_policy::PasswordPolicyService`] が担う。長さの判定だけが
//! 同期・材料不要で完結するため、本モジュールの [`PasswordPolicy::validate_length`] は
//! そこだけを引き受ける。
//!
//! # 有効期限が「強制変更」と同じ扱いになる理由
//!
//! 期限切れは**ログインを拒否しない**。拒否すると利用者は自力で復旧できず、管理者による再発行
//! （= 別経路のパスワード配布）を毎回挟むことになる。代わりに `must_change_password` と同じ
//! 「パスワード変更画面へ誘導する」状態として扱う（[`password_change_required`]）。フラグを
//! DB に書き足さないのは、期限は設定値の変更で**過去にさかのぼって変わる**ため、書き込み時点の
//! 判定を保存すると設定と食い違うからである。

use crate::domain::error::Result;
use crate::domain::message::MessageKey;
use crate::domain::user::User;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

/// 漏えい照合の既定の照合先（Have I Been Pwned のレンジ API）。実装は
/// `infrastructure::breached_password`。既定値の定義をドメイン側に置くのは、設定の既定値表
/// （`RUNTIME_SETTING_DEFINITIONS`）が参照するためである（設定の一覧が実装詳細へ依存しないようにする）。
pub const DEFAULT_BREACH_API_BASE_URL: &str = "https://api.pwnedpasswords.com/range";

/// パスワードの最小長（既定値。設定 `PASSWORD_MIN_LENGTH` で上書きする）。
pub const MIN_PASSWORD_LEN: usize = 8;

/// パスワードの最大長。argon2 は入力長に比例して CPU を消費するため、極端に長い入力による
/// 計算量 DoS を避ける上限を設ける（一般的なパスワードマネージャの生成長を十分に許容する）。
pub const MAX_PASSWORD_LEN: usize = 256;

/// 新しいパスワードが受け付けられなかった理由。
///
/// 「弱い」の一語にまとめないのは、利用者が次に取るべき行動が理由ごとに違うためである
/// （長さ不足は伸ばせばよいが、漏えい・再利用は**別の値を考える**しかない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordRejection {
    /// 長さ等、入力そのものの要件を満たさない。利用者向けの文言は同梱の翻訳キーで返す。
    Strength(MessageKey),
    /// 既知の漏えいパスワード（[`BreachedPasswordChecker`] が一致を返した）。
    Breached,
    /// 現行または過去に使ったパスワードの再利用。
    Reused,
}

impl PasswordRejection {
    /// 利用者へ返す翻訳キー（Presentation 層が `Accept-Language` に応じて訳す）。
    pub fn message_key(&self) -> MessageKey {
        match self {
            Self::Strength(key) => key.clone(),
            Self::Breached => MessageKey::new("api-password-breached"),
            Self::Reused => MessageKey::new("api-password-reused"),
        }
    }
}

impl std::fmt::Display for PasswordRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message_key())
    }
}

/// パスワードポリシーの設定値（`PASSWORD_*` から注入する単一の値表現）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// 最小文字数（バイト長で判定する。下記 [`PasswordPolicy::validate_length`] 参照）。
    pub min_length: usize,
    /// 最大文字数。
    pub max_length: usize,
    /// 再利用を禁じる直近パスワードの数（**現行を含む**）。`0` は履歴を見ない、
    /// `1` は現行と同じ値を拒否する。
    pub history_count: u32,
    /// パスワードの有効日数。`0` は無期限。
    pub max_age_days: u32,
    /// 漏えい済みパスワードを拒否するか。
    pub reject_breached: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: MIN_PASSWORD_LEN,
            max_length: MAX_PASSWORD_LEN,
            history_count: 0,
            max_age_days: 0,
            reject_breached: false,
        }
    }
}

impl PasswordPolicy {
    /// 長さだけを検証する（材料が要らず同期で完結する唯一の要件）。
    ///
    /// 長さはバイト単位で判定する。argon2 の計算量はバイト長に依存するため、マルチバイト文字でも
    /// 上限が意味を持つようにする。
    pub fn validate_length(&self, password: &str) -> std::result::Result<(), PasswordRejection> {
        if password.len() < self.min_length {
            return Err(PasswordRejection::Strength(MessageKey::with_value(
                "api-password-too-short",
                self.min_length.to_string(),
            )));
        }
        if password.len() > self.max_length {
            return Err(PasswordRejection::Strength(MessageKey::with_value(
                "api-password-too-long",
                self.max_length.to_string(),
            )));
        }
        Ok(())
    }

    /// 履歴を照合するか（`history_count >= 1`）。
    pub fn checks_history(&self) -> bool {
        self.history_count >= 1
    }

    /// 履歴表から読む退役ハッシュの件数。現行パスワード 1 件はユーザー行から読むため、
    /// 履歴側は 1 件少なくてよい。
    pub fn retired_hashes_to_check(&self) -> u32 {
        self.history_count.saturating_sub(1)
    }

    /// 退役ハッシュを利用者ごとに何件まで残すか（剪定の上限）。
    ///
    /// 判定に使う件数と一致させる。ポリシーを緩めた直後に足りなくなるのを避けたい場合でも、
    /// 使わないハッシュを持ち続ける理由は無い（保持は目的のある最小限にする）。
    pub fn retained_history_len(&self) -> u32 {
        self.retired_hashes_to_check()
    }

    /// `changed_at` に設定されたパスワードが `now` 時点で期限切れか。
    pub fn is_expired(&self, changed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        if self.max_age_days == 0 {
            return false;
        }
        match Duration::try_days(i64::from(self.max_age_days)) {
            Some(max_age) => now >= changed_at + max_age,
            // 日数が chrono の表現範囲を超える = 実質無期限。
            None => false,
        }
    }
}

/// 利用者に**パスワード変更を要求すべきか**（強制フラグ、または有効期限切れ）。
///
/// ログイン経路と変更経路の両方がこの 1 本を見る。ログインだけが期限を見て変更経路が見ない、
/// といったずれが起きると「変更画面へ送られたのに変更させてもらえない」状態になる。
pub fn password_change_required(user: &User, policy: &PasswordPolicy, now: DateTime<Utc>) -> bool {
    user.must_change_password || policy.is_expired(user.password_set_at(), now)
}

/// 既知の漏えいパスワードかを判定するポート（DIP 境界。実装は infrastructure 層）。
#[async_trait]
pub trait BreachedPasswordChecker: Send + Sync {
    /// 既知の漏えいパスワードなら `true`。
    ///
    /// **判定できなかった場合は `false` を返す**（fail-open）。外部サービスの不調で
    /// パスワード変更・パスワードリセットが一切できなくなると、侵害の最中に資格情報を
    /// 交換できないという逆の危険が生じる。到達不能は実装側が警告ログに残す。
    async fn is_breached(&self, password: &str) -> Result<bool>;
}

/// 漏えい確認を行わない実装（`PASSWORD_BREACH_CHECK_ENABLED=false` のとき、および
/// 外部通信を持たないテストで使う）。
pub struct NoBreachCheck;

#[async_trait]
impl BreachedPasswordChecker for NoBreachCheck {
    async fn is_breached(&self, _password: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::UserStatus;
    use uuid::Uuid;

    fn policy(history_count: u32, max_age_days: u32) -> PasswordPolicy {
        PasswordPolicy {
            history_count,
            max_age_days,
            ..PasswordPolicy::default()
        }
    }

    fn user(must_change: bool, password_changed_at: Option<DateTime<Utc>>) -> User {
        let now = Utc::now();
        User {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7().into(),
            sub: Uuid::now_v7(),
            email: "u@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "hash".to_string(),
            must_change_password: must_change,
            password_changed_at,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now - Duration::try_days(400).unwrap(),
            updated_at: now,
        }
    }

    #[test]
    fn rejects_short_password_and_accepts_long_enough() {
        let p = PasswordPolicy::default();
        assert!(p.validate_length("short").is_err());
        assert!(p.validate_length("longenough").is_ok());
    }

    #[test]
    fn accepts_boundary_lengths_and_rejects_overlong() {
        let p = PasswordPolicy::default();
        assert!(p.validate_length(&"a".repeat(p.min_length)).is_ok());
        assert!(p.validate_length(&"a".repeat(p.max_length)).is_ok());
        assert!(p.validate_length(&"a".repeat(p.max_length + 1)).is_err());
    }

    #[test]
    fn min_length_follows_the_configured_value() {
        let p = PasswordPolicy {
            min_length: 12,
            ..PasswordPolicy::default()
        };
        assert!(p.validate_length("elevenchars").is_err());
        assert!(p.validate_length("twelvechars!").is_ok());
    }

    #[test]
    fn history_count_maps_to_current_password_plus_retired_hashes() {
        assert!(!policy(0, 0).checks_history());
        assert_eq!(policy(0, 0).retired_hashes_to_check(), 0);
        // 1 = 現行パスワードのみ（履歴表は読まない）。
        assert!(policy(1, 0).checks_history());
        assert_eq!(policy(1, 0).retired_hashes_to_check(), 0);
        // 5 = 現行 + 退役 4 件。
        assert_eq!(policy(5, 0).retired_hashes_to_check(), 4);
    }

    #[test]
    fn zero_max_age_never_expires() {
        let now = Utc::now();
        let ancient = now - Duration::try_days(10_000).unwrap();
        assert!(!policy(0, 0).is_expired(ancient, now));
    }

    #[test]
    fn expires_exactly_at_the_configured_age() {
        let now = Utc::now();
        let p = policy(0, 90);
        assert!(!p.is_expired(now - Duration::try_days(89).unwrap(), now));
        assert!(p.is_expired(now - Duration::try_days(90).unwrap(), now));
        assert!(p.is_expired(now - Duration::try_days(91).unwrap(), now));
    }

    #[test]
    fn change_required_when_flagged_or_expired() {
        let now = Utc::now();
        let recent = Some(now - Duration::try_days(1).unwrap());

        // 期限を設けていなければ、古い作成日時だけでは要求しない。
        assert!(!password_change_required(
            &user(false, recent),
            &policy(0, 0),
            now
        ));
        // 強制フラグは期限設定と無関係に効く。
        assert!(password_change_required(
            &user(true, recent),
            &policy(0, 0),
            now
        ));
        // 期限切れは強制フラグが無くても要求する。
        assert!(password_change_required(
            &user(false, Some(now - Duration::try_days(100).unwrap())),
            &policy(0, 90),
            now
        ));
    }

    #[test]
    fn unrecorded_change_time_falls_back_to_account_creation() {
        // マイグレーション前に作られ、以後パスワードを変えていない利用者（列は NULL）。
        // 作成時刻（400 日前）を設定時刻とみなし、90 日の期限では切れていると判定する。
        let now = Utc::now();
        assert!(password_change_required(
            &user(false, None),
            &policy(0, 90),
            now
        ));
    }
}
