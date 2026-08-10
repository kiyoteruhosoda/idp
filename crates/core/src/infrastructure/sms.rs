//! `SmsSender` の HTTP ゲートウェイ実装（AP13）。
//!
//! 送信要求を **JSON で 1 本 POST する**だけの汎用実装である。事業者ごとの API 差異は
//! 運用側の中継（関数・Webhook）が吸収する（理由は [`crate::domain::sms`] のモジュール
//! ドキュメント）。送る本文は次の形:
//!
//! ```json
//! { "to": "+819012345678", "text": "Your verification code is 123456.", "from": "IDP" }
//! ```
//!
//! `from` は差出人表示（`sender_id`）が設定されているときだけ載せる。
//!
//! # ログに出さないもの
//!
//! 宛先（PII）・本文（ワンタイムコード）・認証トークン。エラーには接続先の**ホスト名すら**
//! 載せず、固定の文脈と下位のエラー種別だけを残す。送信の成否は監査イベント
//! （`sms_otp.sent`）で追う。

use crate::domain::error::{DomainError, Result};
use crate::domain::outbound_uri::is_internal_destination;
use crate::domain::sms::{OutgoingSms, SmsGatewayConfig, SmsSender};
use async_trait::async_trait;
use std::time::Duration;

/// ゲートウェイへの接続・応答待ちの上限。ログイン中の利用者を待たせ続けないため短くする。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpSmsGateway {
    client: reqwest::Client,
}

impl HttpSmsGateway {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                // 既定の TLS backend（rustls）で失敗する構成はビルド設定の誤りで、
                // 実行時の入力では起きない。
                .expect("reqwest client builds with the compiled-in TLS backend"),
        }
    }
}

impl Default for HttpSmsGateway {
    fn default() -> Self {
        Self::new()
    }
}

/// エラーに秘匿値・宛先が混ざらないよう、固定の文脈だけ付ける。
fn sms_err<E: std::fmt::Display>(context: &'static str) -> impl FnOnce(E) -> DomainError {
    move |e| DomainError::Repository(format!("sms gateway {context}: {e}"))
}

#[async_trait]
impl SmsSender for HttpSmsGateway {
    async fn send(&self, gateway: &SmsGatewayConfig, sms: &OutgoingSms) -> Result<()> {
        let url = gateway.endpoint_url.trim();
        // 設定値の URL をそのまま叩くため、内部宛（localhost・私設アドレス・メタデータ
        // エンドポイント）を拒む。クライアント登録の outbound URI と同じ判定を使う
        // （設定を書き換えられる立場の攻撃者に、内部ネットワークへの POST を許さない）。
        if is_internal_destination(url) {
            return Err(DomainError::InvalidValue(
                "sms gateway url must not point at an internal destination".to_string(),
            ));
        }

        let mut body = serde_json::json!({
            "to": sms.to,
            "text": sms.body_text,
        });
        if !gateway.sender_id.trim().is_empty() {
            body["from"] = serde_json::json!(gateway.sender_id.trim());
        }

        let mut request = self.client.post(url).json(&body);
        if !gateway.auth_header.trim().is_empty() && !gateway.auth_token.is_empty() {
            request = request.header(gateway.auth_header.trim(), &gateway.auth_token);
        }

        let response = request.send().await.map_err(sms_err("request failed"))?;
        if !response.status().is_success() {
            // 本文はエラーへ載せない（事業者が要求内容を反射して返すと、宛先・コードが
            // ログへ回り込む）。判断に要るのはステータスだけ。
            return Err(DomainError::Repository(format!(
                "sms gateway rejected the request with status {}",
                response.status()
            )));
        }
        Ok(())
    }
}
