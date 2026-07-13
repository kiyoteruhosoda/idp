//! ログイン・同意画面の CSRF 同期トークン（web が生成し api が検証する契約）。
//!
//! `auth_session_id`（HttpOnly Cookie にのみ存在する推測不能な乱数）の HMAC-SHA256 をフォームへ
//! 埋め込み、POST 時に api のサービスが同じ値を再計算して照合する（同期トークン方式。サーバ側の
//! 追加保存は不要）。サーバ側のシークレットキー（`CSRF_SECRET`）を HMAC 鍵として使うことで、
//! 攻撃者が session_id と導出式を知っていてもトークンを偽造できない（SEC7）。
//! web（フォーム描画）と api（検証）で導出を一致させるため本 crate に置く。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// `auth_session_id` に紐づくログイン画面用 CSRF トークンを導出する。
/// `key` は `CSRF_SECRET`（`[u8; 32]`）を渡す。
pub fn login_csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    hmac_sha256_hex(key, &format!("csrf:{auth_session_id}"))
}

/// `auth_session_id` に紐づく同意画面用 CSRF トークンを導出する。
/// ログイン用と異なるプレフィックス（`consent-csrf:`）を使うことで衝突を防ぐ。
/// `key` は `CSRF_SECRET`（`[u8; 32]`）を渡す。
pub fn consent_csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    hmac_sha256_hex(key, &format!("consent-csrf:{auth_session_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"test-key-for-unit-tests-32bytes!";

    #[test]
    fn login_csrf_is_deterministic_and_session_bound() {
        let a = login_csrf_token("session-a", TEST_KEY);
        assert_eq!(a, login_csrf_token("session-a", TEST_KEY));
        assert_ne!(a, login_csrf_token("session-b", TEST_KEY));
        // HMAC-SHA256 hex（64 文字）でフォームに埋め込める安全な文字のみ。
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn login_csrf_is_key_bound() {
        // 同じ session_id でも異なるキーなら異なるトークン。
        let key1 = b"key1-for-test-32-bytes-xxxxxxxxx";
        let key2 = b"key2-for-test-32-bytes-xxxxxxxxx";
        assert_ne!(
            login_csrf_token("session", key1),
            login_csrf_token("session", key2)
        );
    }

    #[test]
    fn consent_csrf_is_distinct_from_login_csrf() {
        let login = login_csrf_token("abc", TEST_KEY);
        let consent = consent_csrf_token("abc", TEST_KEY);
        assert_ne!(login, consent);
        assert_eq!(consent.len(), 64);
        assert!(consent.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
