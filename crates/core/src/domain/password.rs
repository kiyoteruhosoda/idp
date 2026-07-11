//! パスワードハッシュの抽象（DIP 境界）。実装は infrastructure 層（argon2）。

use crate::domain::error::DomainError;

pub trait PasswordHasher: Send + Sync {
    /// 平文パスワードをハッシュ化して PHC 文字列を返す。
    fn hash(&self, password: &str) -> Result<String, DomainError>;
    /// 平文パスワードが保存済みハッシュに一致するか検証する。
    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;
}

/// パスワードの最小長（登録・変更で共通の強度ポリシー）。
pub const MIN_PASSWORD_LEN: usize = 8;

/// パスワード強度を検証する（登録・変更で共通）。
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_password_and_accepts_long_enough() {
        assert!(validate_password_strength("short").is_err());
        assert!(validate_password_strength("longenough").is_ok());
    }
}
