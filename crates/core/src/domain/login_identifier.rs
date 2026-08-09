//! ログイン識別子の登録簿（AP8。ユーザー認証・認証ポリシー仕様書 §4）。
//!
//! ログイン欄に入力できる値を `users.preferred_username` の 1 本から複数へ広げる。1 行が
//! 「この利用者は、この種別のこの値でもログインできる」を表す。
//!
//! # 表示値と正規化値
//!
//! 照合に使うのは [`UserLoginIdentifier::normalized_value`] だけで、画面に出すのは利用者が
//! 登録したままの [`UserLoginIdentifier::display_value`]。電話番号の `090-1234-5678` と
//! `+81 90 1234 5678` は同じ番号を指すが、利用者が自分の登録内容だと分かるのは前者である。
//! 正規化した値を表示にも使うと「登録した覚えのない値が並ぶ」ことになり、同一性を確認できない。
//!
//! # 無効化
//!
//! [`UserLoginIdentifier::is_active`] が `false` の行はログイン欄で一致しない。行を残すのは、
//! 「この値は使えない」と「この値は誰のものでもない」を区別するため。削除してしまうと同じ値を
//! 別人が登録でき、無効化した識別子の宛先が黙って変わる。
//!
//! # `users.preferred_username` との関係（expand フェーズ）
//!
//! 主たるログイン識別子は当面 `users.preferred_username` のままで、本登録簿にはその写しを
//! `username` 種別として持つ（migration 0029 の backfill）。解決は「登録簿の有効な行 →
//! 無ければ `users.preferred_username`」の順（[`crate::domain::repositories::UserRepository::find_by_login_identifier`]）。
//! 写しが古くならないよう、プロフィール更新の経路が同期する（ADR-0025）。
#![allow(dead_code)]

use crate::domain::message::MessageKey;
use crate::domain::tenant::TenantId;
use crate::domain::values::string_enum;
use chrono::{DateTime, Utc};
use uuid::Uuid;

string_enum!(
    /// 識別子の種別（仕様 §4）。
    ///
    /// 種別は**正規化のしかた**を決めるためにある。同じ文字列でも、ユーザー名としてなら大小を
    /// 無視し、電話番号としてなら区切り記号を無視する、という違いを型で表す。
    LoginIdentifierType {
        /// ユーザー名。`users.preferred_username` と同じ性質の識別子。
        Username => "username",
        /// メールアドレス。**既定では登録されない**（migration 0029 は取り込まない）。
        /// メールでのログインを許すかはテナントの判断であり、管理者が明示的に足したときだけ有効になる。
        Email => "email",
        /// 電話番号。区切り記号・空白を落とし、先頭の `+` のみ残した数字列で照合する。
        PhoneNumber => "phone_number",
        /// 社員番号など組織が配る番号。大小を無視し、空白を落として照合する。
        EmployeeNumber => "employee_number",
    }
);

/// 正規化値の上限（`user_login_identifiers.normalized_value` の `VARCHAR(255)`）。
pub const NORMALIZED_VALUE_MAX_LEN: usize = 255;
/// 表示値の上限（`user_login_identifiers.display_value` の `VARCHAR(320)`）。
pub const DISPLAY_VALUE_MAX_LEN: usize = 320;

/// 電話番号として受け付ける桁数の範囲（E.164 の最大 15 桁に、内線等の余地を見て上限 20）。
const PHONE_MIN_DIGITS: usize = 6;
const PHONE_MAX_DIGITS: usize = 20;

impl LoginIdentifierType {
    /// 入力値を照合キーへ正規化する。
    ///
    /// 書式の妥当性は見ない（[`Self::normalize_checked`] が行う）。ログイン時の解決は
    /// 「入力が各種別だったら何になるか」を全種別ぶん作って引くため、ここは失敗しない。
    pub fn normalize(&self, raw: &str) -> String {
        let trimmed = raw.trim();
        match self {
            // 大小を無視する。DB 側の照合順序（`utf8mb4_unicode_ci`）も大小無視だが、
            // 表示と保存の一貫性のためこちらでも落としておく。
            Self::Username | Self::Email => trimmed.to_lowercase(),
            // 区切り記号・空白を落とし、先頭の `+`（国際プレフィクス）だけ残す。
            Self::PhoneNumber => {
                let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
                if trimmed.starts_with('+') {
                    format!("+{digits}")
                } else {
                    digits
                }
            }
            // 大小と空白を無視する（`A-1234` と `a 1234` は別物なので、記号は落とさない）。
            Self::EmployeeNumber => trimmed
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_uppercase(),
        }
    }

    /// 入力値を検証したうえで正規化する（登録時）。
    ///
    /// エラーは利用者へ返るため訳文ではなく**翻訳キー**を返す（訳出は Presentation 層。MT19）。
    pub fn normalize_checked(&self, raw: &str) -> Result<String, MessageKey> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(MessageKey::new("api-login-identifier-required"));
        }
        if trimmed.chars().count() > DISPLAY_VALUE_MAX_LEN {
            return Err(MessageKey::with_value(
                "api-login-identifier-too-long",
                DISPLAY_VALUE_MAX_LEN.to_string(),
            ));
        }
        match self {
            Self::Email => crate::domain::values::validate_email(trimmed)?,
            Self::PhoneNumber => {
                let digits = trimmed.chars().filter(char::is_ascii_digit).count();
                // 数字と区切り記号以外が混ざっているものは弾く。通した先で「一致しない識別子」に
                // なるだけで、登録者には理由が分からない。
                let shaped = trimmed
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'));
                if !shaped || !(PHONE_MIN_DIGITS..=PHONE_MAX_DIGITS).contains(&digits) {
                    return Err(MessageKey::new("api-login-identifier-phone-invalid"));
                }
            }
            Self::Username | Self::EmployeeNumber => {}
        }
        let normalized = self.normalize(trimmed);
        if normalized.is_empty() {
            return Err(MessageKey::new("api-login-identifier-required"));
        }
        if normalized.chars().count() > NORMALIZED_VALUE_MAX_LEN {
            return Err(MessageKey::with_value(
                "api-login-identifier-too-long",
                NORMALIZED_VALUE_MAX_LEN.to_string(),
            ));
        }
        Ok(normalized)
    }
}

/// ログイン欄への入力を、種別ごとの照合キーの候補へ広げる。
///
/// 入力そのものには種別が書かれていない（利用者は「自分の番号」を打つだけ）ため、
/// **どの種別として読んだらどうなるか**を全通り作って一致を探す。種別ごとに正規化が違う以上、
/// 「1 つに正規化してから引く」ことはできない。
///
/// 空になる候補（数字を含まない入力を電話番号として読んだ場合など）は落とす。重複も落とす
/// （`alice` は username と email で同じ正規化になるが、`IN` に同じ組を 2 度置く意味はない）。
pub fn lookup_candidates(input: &str) -> Vec<(LoginIdentifierType, String)> {
    use LoginIdentifierType::*;
    let mut out: Vec<(LoginIdentifierType, String)> = Vec::new();
    for kind in [Username, Email, PhoneNumber, EmployeeNumber] {
        let normalized = kind.normalize(input);
        if normalized.is_empty()
            || normalized == "+"
            || normalized.chars().count() > NORMALIZED_VALUE_MAX_LEN
        {
            continue;
        }
        if !out.iter().any(|(k, v)| *k == kind && *v == normalized) {
            out.push((kind, normalized));
        }
    }
    out
}

/// 登録簿の 1 行。
#[derive(Debug, Clone)]
pub struct UserLoginIdentifier {
    pub id: Uuid,
    /// 所属元テナント。一意性はテナント内で見る（ADR-0009 §2）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    pub identifier_type: LoginIdentifierType,
    /// 利用者が登録したままの値（表示用）。
    pub display_value: String,
    /// 照合キー（種別ごとの正規化を適用済み）。
    pub normalized_value: String,
    /// `false` ならログイン欄で一致しない。
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_per_type() {
        assert_eq!(
            LoginIdentifierType::Username.normalize("  Alice  "),
            "alice"
        );
        assert_eq!(
            LoginIdentifierType::Email.normalize("Alice@Example.COM"),
            "alice@example.com"
        );
        assert_eq!(
            LoginIdentifierType::PhoneNumber.normalize("090-1234-5678"),
            "09012345678"
        );
        assert_eq!(
            LoginIdentifierType::PhoneNumber.normalize("+81 (90) 1234-5678"),
            "+819012345678"
        );
        assert_eq!(
            LoginIdentifierType::EmployeeNumber.normalize(" a-1234 "),
            "A-1234"
        );
    }

    #[test]
    fn phone_normalization_keeps_international_prefix_distinct() {
        // 先頭の `+` を落とすと国内表記と国際表記が同じキーになり、別人の番号と衝突し得る。
        assert_ne!(
            LoginIdentifierType::PhoneNumber.normalize("+819012345678"),
            LoginIdentifierType::PhoneNumber.normalize("819012345678")
        );
    }

    #[test]
    fn rejects_malformed_values() {
        assert!(LoginIdentifierType::Username
            .normalize_checked("   ")
            .is_err());
        assert!(LoginIdentifierType::Email
            .normalize_checked("not-an-email")
            .is_err());
        // 数字が足りない・記号が混ざる電話番号は登録させない。
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("12345")
            .is_err());
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("090-1234-abcd")
            .is_err());
        assert!(LoginIdentifierType::PhoneNumber
            .normalize_checked("090-1234-5678")
            .is_ok());
    }

    #[test]
    fn lookup_candidates_cover_every_type_and_drop_empties() {
        let candidates = lookup_candidates("Alice");
        // username / email は同じ正規化になるので 1 件に畳まれ、employee_number が別途載る。
        assert!(candidates.contains(&(LoginIdentifierType::Username, "alice".to_string())));
        assert!(candidates.contains(&(LoginIdentifierType::EmployeeNumber, "ALICE".to_string())));
        // 数字を含まない入力は電話番号の候補にならない。
        assert!(!candidates
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::PhoneNumber));

        let phone = lookup_candidates("090-1234-5678");
        assert!(phone.contains(&(LoginIdentifierType::PhoneNumber, "09012345678".to_string())));
    }

    #[test]
    fn lookup_candidates_are_empty_for_blank_input() {
        assert!(lookup_candidates("   ").is_empty());
        // `+` だけの入力を電話番号候補にすると、全員の番号に当たり得るキーになる。
        assert!(!lookup_candidates("+")
            .iter()
            .any(|(k, _)| *k == LoginIdentifierType::PhoneNumber));
    }
}
