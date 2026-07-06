//! 管理コンソールの CSRF 同期トークン（web 内で生成・検証する。ADR-0007 §4）。
//!
//! 管理コンソールの CSRF は web が閉じて扱う（生成も検証も web）。
//! - [`admin_csrf_token`]: ログインフォーム（未認証）。GET で発行する推測不能な乱数（HttpOnly Cookie
//!   `admin_csrf_id`）の一方向ハッシュをフォームへ埋め込み、POST 時に Cookie から再計算して照合する。
//! - [`console_csrf_token`]: ログイン後の状態変更フォーム。SSO セッション id（HttpOnly Cookie）由来の
//!   同期トークン（名前空間で `admin_csrf_token` と分離）。

use sha2::{Digest, Sha256};

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// 管理ログインフォームの CSRF トークンを Cookie の種から導出する。
pub fn admin_csrf_token(csrf_id: &str) -> String {
    sha256_hex(&format!("admin-csrf:{csrf_id}"))
}

/// ログイン後の管理コンソール（状態変更フォーム）用の CSRF トークンを SSO セッション id から導出する。
pub fn console_csrf_token(sso_session_id: &str) -> String {
    sha256_hex(&format!("console-csrf:{sso_session_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_deterministic_and_namespaced() {
        assert_eq!(admin_csrf_token("s"), admin_csrf_token("s"));
        assert_ne!(admin_csrf_token("a"), admin_csrf_token("b"));
        assert_eq!(console_csrf_token("s"), console_csrf_token("s"));
        // 名前空間が違えば同じ種でも一致しない。
        assert_ne!(admin_csrf_token("x"), console_csrf_token("x"));
        assert_eq!(admin_csrf_token("x").len(), 64);
    }
}
