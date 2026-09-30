//! 管理コンソールの CSRF 同期トークン（web 内で生成・検証する。ADR-0007 §4）。
//!
//! 管理コンソールの CSRF は web が閉じて扱う（生成も検証も web）。
//! - [`admin_csrf_token`]: ログインフォーム（未認証）。GET で発行する推測不能な乱数（HttpOnly Cookie
//!   `admin_csrf_id`）の HMAC をフォームへ埋め込み、POST 時に Cookie から再計算して照合する。
//! - [`console_csrf_token`]: ログイン後の状態変更フォーム。SSO セッション id（HttpOnly Cookie）由来の
//!   同期トークン（名前空間で `admin_csrf_token` と分離）。
//!
//! **照合はこの module の `*_valid` だけで行う**（task #143）。どれも定数時間の比較
//! （[`assay_contracts::csrf::verify`]）を通し、種（Cookie）が無い・空なら拒否する。以前は管理画面の
//! ハンドラごとに `csrf_valid` が書かれ、いくつかは `==`（不一致の位置で早く返る）で比べていた。

use axum::http::HeaderMap;
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

/// エンドユーザー・ポータルのログイン／TOTP フォーム用の CSRF トークンを Cookie の種から導出する
/// （`admin_csrf_token` と同じ仕組み・別名前空間）。
pub fn portal_csrf_token(csrf_id: &str, key: &[u8]) -> String {
    hmac_hex(key, &format!("portal-csrf:{csrf_id}"))
}

/// 提示されたトークンを、種から導出したトークンと定数時間で照合する。種が無い・空なら `false`
/// （空の種から導出したトークンを受け入れない）。
fn seeded_valid(
    seed: Option<&str>,
    submitted: &str,
    key: &[u8],
    derive: fn(&str, &[u8]) -> String,
) -> bool {
    seed.filter(|s| !s.is_empty())
        .is_some_and(|s| assay_contracts::csrf::verify(&derive(s, key), submitted))
}

/// 管理ログイン・強制パスワード変更のフォームの CSRF を、種 Cookie（`admin_csrf_id`）と照合する。
pub fn admin_csrf_valid(csrf_id: Option<&str>, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(csrf_id, submitted, key, admin_csrf_token)
}

/// エンドユーザー・ポータルのログイン・強制パスワード変更・TOTP のフォームの CSRF を、種 Cookie
/// （`portal_csrf_id`）と照合する。
pub fn portal_csrf_valid(csrf_id: Option<&str>, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(csrf_id, submitted, key, portal_csrf_token)
}

/// ログイン後の状態変更フォーム（管理コンソール・アカウント設定・ログアウト）の CSRF を、SSO
/// セッション id と照合する。SSO セッション id を既に取り出しているハンドラ向け。
pub fn console_csrf_valid(sso_session_id: &str, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(Some(sso_session_id), submitted, key, console_csrf_token)
}

/// [`console_csrf_valid`] の SSO Cookie から読む版。SSO Cookie が無ければ `false`。
pub fn console_csrf_valid_in(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    seeded_valid(
        crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).as_deref(),
        submitted,
        key,
        console_csrf_token,
    )
}

/// フォームへ埋める [`console_csrf_token`] を SSO Cookie から導出する。SSO Cookie が無ければ空文字
/// （空のトークンは [`console_csrf_valid_in`] が必ず拒否する）。
pub fn console_csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE)
        .filter(|s| !s.is_empty())
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::COOKIE;

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

    fn sso_headers(sso: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={sso}", crate::cookies::SSO_SESSION_COOKIE)
                .parse()
                .unwrap(),
        );
        headers
    }

    /// 照合は導出したトークンと完全に一致するときだけ通る（名前空間・種・鍵・長さのどれが違っても
    /// 拒否）。種が無い・空なら、空の種から導出したトークンを出されても拒否する。
    #[test]
    fn valid_accepts_only_the_token_derived_from_the_seed() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        let token = console_csrf_token("sso-1", key);
        assert!(console_csrf_valid("sso-1", &token, key));
        assert!(!console_csrf_valid("sso-2", &token, key));
        assert!(!console_csrf_valid("sso-1", "", key));
        assert!(!console_csrf_valid("sso-1", &token[..63], key));
        assert!(!console_csrf_valid("sso-1", &format!("{token}0"), key));
        assert!(!console_csrf_valid(
            "sso-1",
            &token,
            b"other-key-for-csrf-32-bytes-xxxx"
        ));
        // 空の種から導出した値は、種が空なら受け入れない。
        assert!(!console_csrf_valid("", &console_csrf_token("", key), key));
        // 名前空間が違うトークン（管理ログイン用）は同じ種でも通らない。
        assert!(!console_csrf_valid(
            "sso-1",
            &admin_csrf_token("sso-1", key),
            key
        ));

        let admin = admin_csrf_token("seed", key);
        assert!(admin_csrf_valid(Some("seed"), &admin, key));
        assert!(!admin_csrf_valid(None, &admin, key));
        assert!(!admin_csrf_valid(Some(""), &admin_csrf_token("", key), key));
        let portal = portal_csrf_token("seed", key);
        assert!(portal_csrf_valid(Some("seed"), &portal, key));
        assert!(!portal_csrf_valid(Some("seed"), &admin, key));
        assert!(!portal_csrf_valid(None, &portal, key));
    }

    /// Cookie から読む版は SSO Cookie の値を種にする。Cookie が無ければ埋めるトークンは空で、
    /// 照合は必ず落ちる。
    #[test]
    fn valid_in_reads_the_sso_cookie() {
        let key = b"test-key-for-csrf-32-bytes-xxxxx";
        let headers = sso_headers("sso-1");
        let token = console_csrf_from(&headers, key);
        assert_eq!(token, console_csrf_token("sso-1", key));
        assert!(console_csrf_valid_in(&headers, &token, key));
        assert!(!console_csrf_valid_in(&headers, "", key));
        assert!(!console_csrf_valid_in(&sso_headers("sso-2"), &token, key));

        let none = HeaderMap::new();
        assert_eq!(console_csrf_from(&none, key), "");
        assert!(!console_csrf_valid_in(&none, "", key));
        assert!(!console_csrf_valid_in(&none, &token, key));
    }

    /// 照合は必ずこの module を通す（task #143）。ハンドラに照合を書き戻したり、トークンを `==` /
    /// `!=`（不一致の位置で早く返る）で比べたりした瞬間にここで落ちる。
    #[test]
    fn handlers_do_not_compare_tokens_by_themselves() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/handlers");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read handlers dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read handler source");
            for (n, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with("assert") {
                    continue;
                }
                let compares =
                    code.contains("csrf") && (code.contains("==") || code.contains("!="));
                let own_helper = code.contains("fn csrf_valid") || code.contains("fn csrf_from");
                if compares || own_helper {
                    offenders.push(format!("{}:{}: {code}", path.display(), n + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "CSRF の照合は crate::csrf の *_valid を使うこと:\n{}",
            offenders.join("\n")
        );
    }
}
