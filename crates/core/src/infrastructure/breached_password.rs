//! `BreachedPasswordChecker` の実装（AP7。k-匿名性のレンジ API）。
//!
//! # 平文を外へ出さない照合の仕組み
//!
//! パスワードの SHA-1 を取り、**先頭 5 桁の 16 進数だけ**をサービスへ送る。サービスはその
//! 接頭辞で始まるハッシュの残り 35 桁を数百件まとめて返し、一致判定は本プロセス内で行う。
//! つまり外部に出るのは「同じ 5 桁で始まる何十万件かのうちのどれか」という情報だけで、
//! パスワードそのものも、どのアカウントの話かも渡らない（Pwned Passwords のレンジ API と
//! 同じ契約。互換のミラーを自前で立てる場合は `PASSWORD_BREACH_API_BASE_URL` を向ける）。
//!
//! SHA-1 をここで使うのは**照合プロトコルが SHA-1 で定義されている**ためで、保存や認証に
//! 使うわけではない（保存は argon2 のまま）。
//!
//! # 到達できないときは通す（fail-open）
//!
//! 外部サービスが落ちている間パスワードを変更できなくすると、資格情報が漏れた**まさにその
//! 状況**で交換ができなくなる。判定不能は `Ok(false)`（＝拒否しない）とし、警告ログに残す。
//! この選択は「漏えい済みの値をたまに取りこぼす」ことより「変更を止める」ことの方が危険だ、
//! という判断であり、ドメイン側のトレイト定義（`BreachedPasswordChecker`）にも書いてある。

use crate::domain::error::Result;
use crate::domain::password_policy::BreachedPasswordChecker;
use async_trait::async_trait;
use sha1::{Digest, Sha1};

/// 照合サービスへ名乗る `User-Agent`。
///
/// **省略できない。** Pwned Passwords は `User-Agent` の無い要求を 403 で拒否し、reqwest は既定で
/// このヘッダを付けない。拒否された応答は下の非成功分岐で「判定できなかった」として通されるため、
/// 付け忘れると**有効にしたはずの漏えい確認が全件素通りになる**（しかも警告ログ以外に兆候が無い）。
const USER_AGENT: &str = "idp-oidc-provider";

pub struct RangeApiBreachedPasswordChecker {
    http: reqwest::Client,
    base_url: String,
}

impl RangeApiBreachedPasswordChecker {
    /// `base_url` は接頭辞を付け足す土台（`{base_url}/{prefix}` を GET する）。
    pub fn new(base_url: impl Into<String>, timeout: std::time::Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| {
                crate::domain::error::DomainError::InvalidValue(format!(
                    "failed to build breached password http client: {e}"
                ))
            })?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }
}

/// パスワードの SHA-1 を大文字 16 進で返し、送出する接頭辞（5 桁）と手元で照合する残り（35 桁）へ割る。
fn split_hash(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    let (prefix, suffix) = hex.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/// レンジ API の本文（`SUFFIX:COUNT` の行の並び）に該当の接尾辞があるか。
///
/// 出現回数は見ない。1 度でも漏えいリストに載った値は使わせない。
fn body_contains_suffix(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        line.split(':')
            .next()
            .is_some_and(|candidate| candidate.trim().eq_ignore_ascii_case(suffix))
    })
}

#[async_trait]
impl BreachedPasswordChecker for RangeApiBreachedPasswordChecker {
    async fn is_breached(&self, password: &str) -> Result<bool> {
        let (prefix, suffix) = split_hash(password);
        let url = format!("{}/{prefix}", self.base_url);
        // `Add-Padding` は応答の件数から接頭辞を推測されないようダミー行を混ぜてもらう指示
        // （対応していないミラーは黙って無視する）。
        let response = match self
            .http
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "breached password check unavailable; accepting the password"
                );
                return Ok(false);
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "breached password check returned an error status; accepting the password"
            );
            return Ok(false);
        }
        match response.text().await {
            Ok(body) => Ok(body_contains_suffix(&body, &suffix)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "breached password check response unreadable; accepting the password"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_hash_into_a_five_digit_prefix_and_the_rest() {
        // "password" の SHA-1 は 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8（レンジ API の既知の例）。
        let (prefix, suffix) = split_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn finds_the_suffix_regardless_of_case_and_ignores_the_count() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:37359195\r\n";
        assert!(body_contains_suffix(
            body,
            "1e4c9b93f3f0682250b6cf8331b7ee68fd8"
        ));
        assert!(!body_contains_suffix(
            body,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        ));
    }

    #[test]
    fn does_not_match_a_count_field() {
        // 接尾辞ではなく出現回数の側にたまたま一致する値が来ても拾わない。
        let body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:12345\r\n";
        assert!(!body_contains_suffix(body, "12345"));
    }
}
