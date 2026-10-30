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
use crate::domain::outbound_uri::{is_internal_destination, OutboundTrust};
use crate::domain::sms::{OutgoingSms, SmsGatewayConfig, SmsSender};
use crate::infrastructure::outbound_http::guarded_client_builder;
use async_trait::async_trait;
use std::time::Duration;

/// ゲートウェイへの接続・応答待ちの上限。ログイン中の利用者を待たせ続けないため短くする。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpSmsGateway {
    client: reqwest::Client,
}

impl HttpSmsGateway {
    pub fn new() -> Self {
        Self::with_trust(OutboundTrust::none())
    }

    /// 名前を引いた結果が内部の住所でも送ってよい名前を指定して作る（task #740）。
    pub fn with_trust(trust: OutboundTrust) -> Self {
        Self {
            // 繋ぐ直前に引いた住所を確かめる（内部なら送らない。`outbound_http`）。
            client: guarded_client_builder(trust)
                .timeout(REQUEST_TIMEOUT)
                // リダイレクトは追わない。設定した URL 以外へ宛先とワンタイムコードを渡さないため。
                .redirect(reqwest::redirect::Policy::none())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn gateway(url: String) -> SmsGatewayConfig {
        SmsGatewayConfig {
            endpoint_url: url,
            auth_header: String::new(),
            auth_token: String::new(),
            sender_id: String::new(),
        }
    }

    fn sms() -> OutgoingSms {
        OutgoingSms {
            to: "+819012345678".to_string(),
            body_text: "code".to_string(),
        }
    }

    /// 引いた先が内部の名前には繋がない（`localhost` は字面でも断るので、クライアントを直に確かめる）。
    #[tokio::test]
    async fn the_client_refuses_a_name_that_resolves_inside() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let sender = HttpSmsGateway::new();
        let result = sender
            .client
            .post(format!("http://localhost:{port}/"))
            .send()
            .await;
        assert!(result.is_err());
    }

    /// リダイレクトを追わない（追う先へ宛先とコードを渡さない）。
    #[tokio::test]
    async fn the_client_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 1024];
            let _ = socket.read(&mut buffer).await;
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://localhost:1/next\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let sender = HttpSmsGateway::with_trust(OutboundTrust::parse("localhost"));
        let response = sender
            .client
            .post(format!("http://localhost:{port}/"))
            .send()
            .await
            .expect("the first response comes back");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.expect("server task");
    }

    /// 字面で内部と分かる URL は、信用する名前の指定があっても送らない。
    #[tokio::test]
    async fn an_internal_url_is_refused() {
        let sender = HttpSmsGateway::with_trust(OutboundTrust::parse("localhost"));
        let err = sender
            .send(&gateway("http://localhost:1/".to_string()), &sms())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("internal destination"), "{err}");
    }
}
