//! パスワードハッシュの抽象（DIP 境界）。実装は infrastructure 層（argon2）。
//!
//! 「そのパスワードを受け付けてよいか」の要件は
//! [`crate::domain::password_policy`]（長さ・漏えい・再利用・有効期限）にある。

use crate::domain::error::DomainError;

pub trait PasswordHasher: Send + Sync {
    /// 平文パスワードをハッシュ化して PHC 文字列を返す。
    fn hash(&self, password: &str) -> Result<String, DomainError>;
    /// 平文パスワードが保存済みハッシュに一致するか検証する。
    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;
}

/// 存在しない（または曖昧で解決しなかった）利用者に対しても、実在利用者と**同じ計算量の**
/// パスワード検証を 1 回行い、応答時間で利用者の有無を推し量れないようにする（列挙対策。
/// OWASP Authentication Cheat Sheet の「timing の均一化」）。
///
/// 参照ハッシュは初回に 1 度だけ本物のハッシャで生成して使い回す（毎回ハッシュすると 2 倍の
/// コストになる）。生成に使う平文は秘密ではなく、値は照合結果に一切影響しない —— 呼び出し側は
/// 戻り値を捨て、常に資格情報エラーを返す。生成に失敗した場合は静かに諦める（best-effort。
/// 均一化は防御の足し算であって、成否を分ける判定ではない）。
pub fn verify_against_dummy(hasher: &dyn PasswordHasher, presented_password: &str) {
    use std::sync::OnceLock;
    static DUMMY_HASH: OnceLock<Option<String>> = OnceLock::new();
    let dummy = DUMMY_HASH.get_or_init(|| hasher.hash("timing-equalizer.not-a-credential").ok());
    if let Some(hash) = dummy {
        // 結果は使わない。実在利用者の `verify` と同じ argon2 計算を消費することだけが目的。
        let _ = hasher.verify(presented_password, hash);
    }
}
