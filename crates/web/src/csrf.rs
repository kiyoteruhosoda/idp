//! 管理コンソールの CSRF 同期トークン（web 内で生成・検証する。ADR-0007 §4）。
//!
//! 管理コンソールの CSRF は web が閉じて扱う（生成も検証も web）。
//! - [`admin_csrf_token`]: ログインフォーム（未認証）。GET で発行する推測不能な乱数（HttpOnly Cookie
//!   `admin_csrf_id`）の HMAC をフォームへ埋め込み、POST 時に Cookie から再計算して照合する。
//! - [`console_csrf_token`]: ログイン後の状態変更フォーム。SSO セッション id（HttpOnly Cookie）由来の
//!   同期トークン（名前空間で `admin_csrf_token` と分離）。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_hex(key: &[u8], input: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// 管理ログインフォームの CSRF トークンを Cookie の種から導出する。
pub fn admin_csrf_token(csrf_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("admin-csrf:{csrf_id}"))
}

/// ログイン後の管理コンソール（状態変更フォーム）用の CSRF トークンを SSO セッション id から導出する。
pub fn console_csrf_token(sso_session_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("console-csrf:{sso_session_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_deterministic_and_namespaced() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        assert_eq!(admin_csrf_token("s", key), admin_csrf_token("s", key));
        assert_ne!(admin_csrf_token("a", key), admin_csrf_token("b", key));
        assert_eq!(console_csrf_token("s", key), console_csrf_token("s", key));
        // 名前空間が違えば同じ種でも一致しない。
        assert_ne!(admin_csrf_token("x", key), console_csrf_token("x", key));
        assert_eq!(admin_csrf_token("x", key).len(), 64);
        // 異なるキーでは同じ入力でも一致しない。
        let other_key = b"other-key-for-csrf-32-bytes-xxxx";
        assert_ne!(admin_csrf_token("x", key), admin_csrf_token("x", other_key));
    }
}
