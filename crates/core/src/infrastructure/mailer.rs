//! `Mailer` の lettre（SMTP）実装（MT17）。
//!
//! 接続情報は送信ごとに受け取る（システム設定は実行時に変更されるため、トランスポートを
//! 使い回さない）。TLS は rustls。`use_tls = true` のとき、ポート 465 は implicit TLS
//! （接続直後から TLS）、それ以外（587 等）は STARTTLS 必須として扱う。
//! パスワード等の秘匿値はログ・エラーメッセージへ出さない。

use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::{Mailer, OutgoingEmail, SmtpServerConfig};
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// implicit TLS（SMTPS）の標準ポート。これ以外の TLS 指定は STARTTLS とみなす。
const SMTPS_PORT: u16 = 465;

pub struct LettreSmtpMailer;

impl LettreSmtpMailer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LettreSmtpMailer {
    fn default() -> Self {
        Self::new()
    }
}

/// エラーに秘匿値が混ざらないよう、接続情報を含まない固定の文脈だけ付ける。
fn mail_err<E: std::fmt::Display>(context: &str) -> impl FnOnce(E) -> DomainError + '_ {
    move |e| DomainError::Repository(format!("smtp {context}: {e}"))
}

#[async_trait]
impl Mailer for LettreSmtpMailer {
    async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> Result<()> {
        let message = Message::builder()
            .from(
                server
                    .from_address
                    .parse()
                    .map_err(mail_err("invalid from address"))?,
            )
            .to(mail.to.parse().map_err(mail_err("invalid to address"))?)
            .subject(&mail.subject)
            .header(ContentType::TEXT_PLAIN)
            .body(mail.body_text.clone())
            .map_err(mail_err("build message"))?;

        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&server.host);
        if let Some(port) = server.port {
            builder = builder.port(port);
        }
        if server.use_tls {
            let params =
                TlsParameters::new(server.host.clone()).map_err(mail_err("tls parameters"))?;
            let implicit_tls = server.port.unwrap_or(SMTPS_PORT) == SMTPS_PORT;
            builder = builder.tls(if implicit_tls {
                Tls::Wrapper(params)
            } else {
                Tls::Required(params)
            });
            if server.port.is_none() {
                builder = builder.port(SMTPS_PORT);
            }
        }
        if !server.username.is_empty() {
            builder = builder.credentials(Credentials::new(
                server.username.clone(),
                server.password.clone(),
            ));
        }

        builder
            .build()
            .send(message)
            .await
            .map_err(mail_err("send"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// 最小の SMTP 対話を話すインプロセスサーバ。受信した DATA 本文を返す。
    async fn run_minimal_smtp_server(listener: TcpListener) -> String {
        let (socket, _) = listener.accept().await.expect("accept");
        let (read_half, mut write_half) = socket.into_split();
        let mut lines = BufReader::new(read_half).lines();
        write_half.write_all(b"220 test ESMTP\r\n").await.unwrap();
        let mut data = String::new();
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            if in_data {
                if line == "." {
                    in_data = false;
                    write_half.write_all(b"250 OK\r\n").await.unwrap();
                } else {
                    data.push_str(&line);
                    data.push('\n');
                }
                continue;
            }
            let verb = line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            match verb.as_str() {
                "EHLO" | "HELO" => {
                    write_half.write_all(b"250 test\r\n").await.unwrap();
                }
                "MAIL" | "RCPT" => {
                    write_half.write_all(b"250 OK\r\n").await.unwrap();
                }
                "DATA" => {
                    in_data = true;
                    write_half
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await
                        .unwrap();
                }
                "QUIT" => {
                    write_half.write_all(b"221 Bye\r\n").await.unwrap();
                    break;
                }
                _ => {
                    write_half.write_all(b"250 OK\r\n").await.unwrap();
                }
            }
        }
        data
    }

    #[tokio::test]
    async fn sends_mail_through_a_real_smtp_conversation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(run_minimal_smtp_server(listener));

        let mailer = LettreSmtpMailer::new();
        let config = SmtpServerConfig {
            host: "127.0.0.1".to_string(),
            port: Some(port),
            username: String::new(), // 認証なし
            password: String::new(),
            from_address: "noreply@example.test".to_string(),
            use_tls: false,
        };
        let mail = OutgoingEmail {
            to: "guest@example.test".to_string(),
            subject: "invitation test".to_string(),
            body_text: "accept: https://idp.example.test/t/invitations/accept?token=abc"
                .to_string(),
        };
        mailer.send(&config, &mail).await.expect("smtp send");

        let received = server.await.expect("server task");
        assert!(received.contains("Subject: invitation test"));
        assert!(received.contains("token=3Dabc") || received.contains("token=abc"));
    }

    #[tokio::test]
    async fn send_fails_with_unreachable_server() {
        let mailer = LettreSmtpMailer::new();
        let config = SmtpServerConfig {
            host: "127.0.0.1".to_string(),
            // 予約済みポートを bind して即クローズ → 接続拒否を確実にする代わりに、
            // 未使用ポートへの接続失敗を検証する。
            port: Some(1), // 特権ポート（listener なし）
            username: String::new(),
            password: String::new(),
            from_address: "noreply@example.test".to_string(),
            use_tls: false,
        };
        let mail = OutgoingEmail {
            to: "guest@example.test".to_string(),
            subject: "x".to_string(),
            body_text: "y".to_string(),
        };
        assert!(mailer.send(&config, &mail).await.is_err());
    }
}
