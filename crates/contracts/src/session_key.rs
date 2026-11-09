//! SSO セッションを端末の鍵へ結び付ける（DBSC）ための、web と api で一致していないと壊れる値（task #887。ADR-0074）。
//!
//! - **challenge**: web が Chrome へ渡し、Chrome が鍵で署名して返す使い捨ての値。「どの SSO セッションに・いつ出したか」の
//!   HMAC で、DB に置かない。web が作り（登録の求め・更新の 403）、api が確かめる。
//! - **短い Cookie**（[`BOUND_COOKIE`]）: 結び付けたログイン状態が「いま鍵で署名できた」ことの印。「SSO セッション・期限」の
//!   HMAC で、DB に置かない。web が出し、web が入口で確かめる。
//!
//! HMAC の鍵は `CSRF_SECRET` から用途ごとに分けて導く（同じ値で CSRF のトークンを作れないように）。

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// 結び付けたログイン状態の短い Cookie の名前（HTTPS では `__Host-` を前置して置く）。
pub const BOUND_COOKIE: &str = "sso_bound";
/// 短い Cookie の寿命（秒）。Chrome はこれが切れるたびに鍵で署名して更新する。
pub const BOUND_COOKIE_MAX_AGE_SECS: i64 = 600;
/// challenge を受け付ける長さ（秒）。
pub const CHALLENGE_MAX_AGE_SECS: i64 = 300;
/// 登録の口（web）。ヘッダーの `path` に入れる。
pub const REGISTRATION_PATH: &str = "/dbsc/register";
/// 更新の口（web）。登録の応答の `refresh_url` に入れる。
pub const REFRESH_PATH: &str = "/dbsc/refresh";
/// 受け付ける署名の方式（DBSC の草案が定めるもののうち鍵を使う 2 つ）。
pub const ALGORITHMS: &[&str] = &["ES256", "RS256"];
/// 署名の JWT の `typ`。
pub const PROOF_TYPE: &str = "dbsc+jwt";

/// ログイン状態を求める側のヘッダー（Chrome が読む）。
pub const REGISTRATION_HEADER: &str = "secure-session-registration";
/// 更新で新しい challenge を渡すヘッダー。
pub const CHALLENGE_HEADER: &str = "secure-session-challenge";
/// Chrome が署名（JWT）を載せるヘッダー。
pub const RESPONSE_HEADER: &str = "secure-session-response";
/// Chrome が更新のときに載せる、結び付けの識別子。
pub const SESSION_ID_HEADER: &str = "sec-secure-session-id";

fn mac(key: &[u8], purpose: &str, message: &str) -> Vec<u8> {
    let mut derived = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    derived.update(purpose.as_bytes());
    let derived = derived.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&derived).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn session_ref(sso_session_id: &str) -> String {
    hex::encode(Sha256::digest(sso_session_id.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `{発行時刻}.{HMAC}` の形の値を作る。
fn stamp(key: &[u8], purpose: &str, sso_session_id: &str, at: i64) -> String {
    let tag = mac(
        key,
        purpose,
        &format!("{}:{at}", session_ref(sso_session_id)),
    );
    format!("{at}.{}", hex::encode(tag))
}

/// [`stamp`] の値を確かめ、刻まれた時刻を返す。
fn read_stamp(key: &[u8], purpose: &str, sso_session_id: &str, value: &str) -> Option<i64> {
    let (at, tag) = value.split_once('.')?;
    if at.len() > 20 || tag.len() != 64 {
        return None;
    }
    let at: i64 = at.parse().ok()?;
    let provided = hex::decode(tag).ok()?;
    let expected = mac(
        key,
        purpose,
        &format!("{}:{at}", session_ref(sso_session_id)),
    );
    constant_time_eq(&expected, &provided).then_some(at)
}

/// SSO セッションに結び付いた challenge を作る（`now` は UNIX 秒）。
pub fn challenge(key: &[u8], sso_session_id: &str, now: i64) -> String {
    stamp(key, "dbsc-challenge", sso_session_id, now)
}

/// challenge がこの SSO セッションのもので、出してから [`CHALLENGE_MAX_AGE_SECS`] 以内か。
pub fn challenge_is_fresh(key: &[u8], sso_session_id: &str, value: &str, now: i64) -> bool {
    read_stamp(key, "dbsc-challenge", sso_session_id, value)
        .is_some_and(|at| at <= now + 5 && now - at <= CHALLENGE_MAX_AGE_SECS)
}

/// 短い Cookie の値（期限 `expires_at` は UNIX 秒）。
pub fn bound_cookie(key: &[u8], sso_session_id: &str, expires_at: i64) -> String {
    stamp(key, "dbsc-bound-cookie", sso_session_id, expires_at)
}

/// 短い Cookie がこの SSO セッションのもので、まだ切れていないか。
pub fn bound_cookie_is_valid(key: &[u8], sso_session_id: &str, value: &str, now: i64) -> bool {
    read_stamp(key, "dbsc-bound-cookie", sso_session_id, value)
        .is_some_and(|expires_at| now < expires_at && expires_at - now <= BOUND_COOKIE_MAX_AGE_SECS)
}

/// 短い Cookie がこの SSO セッションのもので、まだ切れていなければ、その期限（UNIX 秒）。
/// 本人の「状況」に出すため（task #896）。
pub fn bound_cookie_expires_at(
    key: &[u8],
    sso_session_id: &str,
    value: &str,
    now: i64,
) -> Option<i64> {
    bound_cookie_is_valid(key, sso_session_id, value, now)
        .then(|| read_stamp(key, "dbsc-bound-cookie", sso_session_id, value))
        .flatten()
}

/// ログインの応答に付ける `Secure-Session-Registration` の値。
pub fn registration_header(challenge: &str) -> String {
    format!(
        "({});path=\"{REGISTRATION_PATH}\";challenge=\"{challenge}\"",
        ALGORITHMS.join(" ")
    )
}

/// 更新の 403 に付ける `Secure-Session-Challenge` の値。
pub fn challenge_header(challenge: &str, session_identifier: &str) -> String {
    format!("\"{challenge}\";id=\"{session_identifier}\"")
}

/// `DBSC_ALLOWED_REFRESH_INITIATORS` を検査する（task #934）。登録・更新の応答の `allowed_refresh_initiators` に入る。
///
/// DBSC の草案（§8.3・§8.4）では、結び付けの範囲は assay のオリジンだけ（`include_site: false`）なので、
/// 要求を出したオリジンが assay でないとき（各アプリの見えない枠の `prompt=none` など）は、ここに当たる
/// ホストでないと Chrome は短い Cookie を取り直さない。
///
/// 書けるのは `*.<名前>` と `<名前>`（ホスト名だけ）を空白で区切ったもの。草案の照合はホストの文字列なので、
/// スキーム・ポート・パスは書けない。何にでも当たる `*` と、`*.` の後ろが 1 段のもの（`*.com`）は断る。
/// `*.example.com` は `example.com` 自身には当たらない（要るなら両方書く）。1 つでも書けないものがあれば全体を断る。
pub fn parse_refresh_initiators(raw: &str) -> Result<Vec<String>, String> {
    raw.split_whitespace()
        .map(parse_refresh_initiator)
        .collect()
}

fn parse_refresh_initiator(raw: &str) -> Result<String, String> {
    let refuse = |why: &str| {
        Err(format!(
            "DBSC_ALLOWED_REFRESH_INITIATORS: `{raw}` {why} (write `*.example.com` or `app.example.com`)"
        ))
    };
    let (wildcard, host) = match raw.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return refuse("is not a lowercase host name");
    }
    if host.split('.').any(str::is_empty) {
        return refuse("is not a host name");
    }
    if wildcard && !host.contains('.') {
        return refuse("is too broad");
    }
    Ok(raw.to_string())
}

/// 結び付けの識別子として受け付ける形か（32 文字の 16 進。assay が作る）。
pub fn is_session_identifier(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-for-unit-tests-32bytes!";

    #[test]
    fn refresh_initiators_accept_host_patterns() {
        assert_eq!(
            parse_refresh_initiators(" *.nolumia.com  nolumia.com ").unwrap(),
            vec!["*.nolumia.com".to_string(), "nolumia.com".to_string()]
        );
        assert!(parse_refresh_initiators("").unwrap().is_empty());
        assert_eq!(
            parse_refresh_initiators("localhost").unwrap(),
            vec!["localhost".to_string()]
        );
    }

    #[test]
    fn refresh_initiators_refuse_what_the_draft_cannot_match() {
        for raw in [
            "*",
            "*.com",
            "https://*.nolumia.com",
            "*.nolumia.com:443",
            "*.nolumia.com/",
            "*.Nolumia.com",
            "a..nolumia.com",
            "*.",
            "**.nolumia.com",
        ] {
            assert!(
                parse_refresh_initiators(raw).is_err(),
                "{raw} must be refused"
            );
        }
        // 1 つでも書けないものがあれば全体を断る
        assert!(parse_refresh_initiators("*.nolumia.com *").is_err());
    }
    const SESSION: &str = "session-a";

    #[test]
    fn the_bound_cookie_reveals_its_expiry_only_when_valid() {
        let value = bound_cookie(KEY, SESSION, 1_000);
        assert_eq!(
            bound_cookie_expires_at(KEY, SESSION, &value, 900),
            Some(1_000)
        );
        assert_eq!(bound_cookie_expires_at(KEY, SESSION, &value, 1_000), None);
        assert_eq!(bound_cookie_expires_at(KEY, "session-b", &value, 900), None);
    }

    #[test]
    fn a_challenge_is_bound_to_the_session_and_expires() {
        let c = challenge(KEY, SESSION, 1_000);
        assert!(challenge_is_fresh(KEY, SESSION, &c, 1_000));
        assert!(challenge_is_fresh(KEY, SESSION, &c, 1_300));
        assert!(!challenge_is_fresh(KEY, SESSION, &c, 1_301));
        assert!(!challenge_is_fresh(KEY, "session-b", &c, 1_000));
        assert!(!challenge_is_fresh(
            b"another-key-for-unit-tests-32by!",
            SESSION,
            &c,
            1_000
        ));
        // 未来の時刻を刻んだもの（時計のずれを越える）は受け付けない。
        assert!(!challenge_is_fresh(
            KEY,
            SESSION,
            &challenge(KEY, SESSION, 2_000),
            1_000
        ));
    }

    #[test]
    fn a_challenge_is_not_a_bound_cookie() {
        let c = challenge(KEY, SESSION, 1_000);
        assert!(!bound_cookie_is_valid(KEY, SESSION, &c, 900));
        let b = bound_cookie(KEY, SESSION, 1_000);
        assert!(!challenge_is_fresh(KEY, SESSION, &b, 1_000));
    }

    #[test]
    fn a_bound_cookie_is_bound_to_the_session_and_expires() {
        let b = bound_cookie(KEY, SESSION, 1_600);
        assert!(bound_cookie_is_valid(KEY, SESSION, &b, 1_000));
        assert!(bound_cookie_is_valid(KEY, SESSION, &b, 1_599));
        assert!(!bound_cookie_is_valid(KEY, SESSION, &b, 1_600));
        assert!(!bound_cookie_is_valid(KEY, "session-b", &b, 1_000));
        // 寿命より先の期限を刻んだもの（鍵を知らなければ作れないが、念のため）は受け付けない。
        assert!(!bound_cookie_is_valid(
            KEY,
            SESSION,
            &bound_cookie(KEY, SESSION, 5_000),
            1_000
        ));
    }

    #[test]
    fn broken_values_are_rejected() {
        for value in [
            "",
            ".",
            "1000",
            "1000.zz",
            "abc.0000",
            &format!("1000.{}", "0".repeat(64)),
        ] {
            assert!(!challenge_is_fresh(KEY, SESSION, value, 1_000), "{value}");
            assert!(!bound_cookie_is_valid(KEY, SESSION, value, 900), "{value}");
        }
    }

    #[test]
    fn headers_follow_the_draft() {
        assert_eq!(
            registration_header("c1"),
            "(ES256 RS256);path=\"/dbsc/register\";challenge=\"c1\""
        );
        assert_eq!(challenge_header("c2", "abc"), "\"c2\";id=\"abc\"");
    }

    #[test]
    fn session_identifiers_are_32_hex() {
        assert!(is_session_identifier(&"a".repeat(32)));
        assert!(!is_session_identifier(&"a".repeat(31)));
        assert!(!is_session_identifier(&"g".repeat(32)));
    }
}
