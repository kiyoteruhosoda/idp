//! パスワードハッシュの抽象（DIP 境界）。実装は infrastructure 層（argon2）。

use crate::domain::error::DomainError;

pub trait PasswordHasher: Send + Sync {
    /// 平文パスワードをハッシュ化して PHC 文字列を返す。
    fn hash(&self, password: &str) -> Result<String, DomainError>;
    /// 平文パスワードが保存済みハッシュに一致するか検証する。
    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;
}
