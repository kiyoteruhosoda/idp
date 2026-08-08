//! `BackchannelLogoutSender` の reqwest 実装（G5）。
//!
//! RP の `backchannel_logout_uri` へ `application/x-www-form-urlencoded` の
//! `logout_token=<JWT>` を POST する（OpenID Connect Back-Channel Logout 1.0 §2.5）。
//! 失敗理由は**運用言語（英語）**で組み立てる（`last_error` に保存され、監査ではなく運用情報として
//! 読まれるため。CLAUDE.md「国際化」の対象外）。

use crate::application::backchannel_logout::BackchannelLogoutSender;
use async_trait::async_trait;

/// RP のエンドポイントが応答しないまま待ち続けないための上限。
const REQUEST_TIMEOUT_SECS: u64 = 5;
/// `last_error` に載せる応答本文の最大文字数（RP が長大な HTML を返しても行を膨らませない）。
const BODY_SNIPPET_MAX_CHARS: usize = 200;

pub struct ReqwestBackchannelLogoutSender {
    client: reqwest::Client,
}

impl ReqwestBackchannelLogoutSender {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                // リダイレクトは追わない。登録済み URI 以外へ logout_token を渡さないため
                //（RP がリダイレクトを設定していれば、それは登録内容の誤りとして失敗させる）。
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
        }
    }
}

impl Default for ReqwestBackchannelLogoutSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BackchannelLogoutSender for ReqwestBackchannelLogoutSender {
    async fn post(&self, uri: &str, logout_token: &str) -> Result<(), String> {
        let response = self
            .client
            .post(uri)
            .form(&[("logout_token", logout_token)])
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        // 本文は診断の手掛かりになるので先頭だけ残す（取得に失敗しても状態コードは記録する）。
        let snippet = response
            .text()
            .await
            .map(|body| body.chars().take(BODY_SNIPPET_MAX_CHARS).collect::<String>())
            .unwrap_or_default();
        Err(format!("endpoint returned {status}: {snippet}"))
    }
}
