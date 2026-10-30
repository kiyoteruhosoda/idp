//! `Mailer` の lettre（SMTP）実装（MT17）。
//!
//! 接続情報は送信ごとに受け取る（システム設定は実行時に変更されるため、トランスポートを
//! 使い回さない）。TLS は rustls。`use_tls = true` のとき、ポート 465 は implicit TLS
//! （接続直後から TLS）、それ以外（587 等）は STARTTLS 必須として扱う。
//! パスワード等の秘匿値はログ・エラーメッセージへ出さない。

use crate::domain::error::{DomainError, Result};
use crate::domain::mailer::{Mailer, OutgoingEmail, SmtpRoute, SmtpServerConfig};
use crate::domain::outbound_uri::{is_internal_host, OutboundTrust};
use crate::infrastructure::outbound_http::check_resolved;
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// implicit TLS（SMTPS）の標準ポート。これ以外の TLS 指定は STARTTLS とみなす。
const SMTPS_PORT: u16 = 465;
/// 接続・応答待ちの上限。宛先が応答しないと、再発行の要求などがメールの送信を待ち続ける（task #740）。
const SMTP_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LettreSmtpMailer {
    trust: OutboundTrust,
}

impl LettreSmtpMailer {
    pub fn new() -> Self {
        Self::with_trust(OutboundTrust::none())
    }

    /// 名前を引いた結果が内部の住所でも送ってよい名前を指定して作る（task #740）。
    pub fn with_trust(trust: OutboundTrust) -> Self {
        Self { trust }
    }
}

impl Default for LettreSmtpMailer {
    fn default() -> Self {
        Self::new()
    }
}

/// テナントの経路の宛先を確かめ、繋ぐ相手（確かめた住所）を返す（task #740）。
///
/// 引いた結果を確かめてから名前のまま繋ぐと、繋ぐときに引き直した先が内部の住所になり得る
/// （DNS rebinding）。そこで確かめた住所へ直接繋ぐ。TLS の証明書は元の名前で確かめる。
/// 例外は運用者が名指しした名前だけで、字面で内部と分かるものは例外にしない（`OutboundTrust`）。
async fn checked_tenant_destination(host: &str, trust: &OutboundTrust) -> Result<String> {
    if is_internal_host(host) {
        return Err(internal_destination());
    }
    if trust.trusts(host) {
        return Ok(host.to_string());
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(mail_err("resolve"))?
        .collect();
    first_external_address(host, &addrs)
}

fn first_external_address(host: &str, addrs: &[std::net::SocketAddr]) -> Result<String> {
    check_resolved(host, addrs, false).map_err(|_| internal_destination())?;
    Ok(addrs[0].ip().to_string())
}

fn internal_destination() -> DomainError {
    DomainError::InvalidValue("smtp host must not point at an internal destination".to_string())
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

        let connect_to = match server.route {
            SmtpRoute::WholeIdp => server.host.clone(),
            SmtpRoute::Tenant => checked_tenant_destination(&server.host, &self.trust).await?,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&connect_to)
            .timeout(Some(SMTP_TIMEOUT));
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
            route: SmtpRoute::WholeIdp,
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
            route: SmtpRoute::WholeIdp,
        };
        let mail = OutgoingEmail {
            to: "guest@example.test".to_string(),
            subject: "x".to_string(),
            body_text: "y".to_string(),
        };
        assert!(mailer.send(&config, &mail).await.is_err());
    }

    fn addr(ip: &str) -> std::net::SocketAddr {
        std::net::SocketAddr::new(ip.parse().unwrap(), 0)
    }

    /// テナントの経路は、宅内・ループバック・リンクローカルの字面なら繋がない（task #740）。
    /// ⚠ 運用者が名指しした名前でも、字面で内部と分かるものは例外にしない。
    #[tokio::test]
    async fn a_tenant_route_never_connects_to_an_internal_literal() {
        for host in [
            "127.0.0.1",
            "10.10.2.11",
            "169.254.169.254",
            "[::1]",
            "mariadb",
            "localhost",
        ] {
            let trust = OutboundTrust::parse(host);
            let err = checked_tenant_destination(host, &trust).await.unwrap_err();
            assert!(
                err.to_string().contains("internal destination"),
                "{host}: {err}"
            );
        }
    }

    /// 引いた結果に内部の住所が 1 つでも混ざれば繋がず、外だけなら確かめた住所へ繋ぐ。
    #[test]
    fn a_tenant_route_connects_only_to_checked_external_addresses() {
        assert!(first_external_address("mail.example.com", &[addr("192.168.1.2")]).is_err());
        assert!(first_external_address(
            "mail.example.com",
            &[addr("104.16.0.1"), addr("169.254.169.254")]
        )
        .is_err());
        assert!(first_external_address("mail.example.com", &[]).is_err());
        assert_eq!(
            first_external_address("mail.example.com", &[addr("104.16.0.1")]).unwrap(),
            "104.16.0.1"
        );
    }

    /// 運用者が名指しした名前は、内側へ引けても名前のまま繋ぐ（split DNS）。
    #[tokio::test]
    async fn a_trusted_name_keeps_its_name() {
        let trust = OutboundTrust::parse("nolumia.com");
        assert_eq!(
            checked_tenant_destination("smtp.nolumia.com", &trust)
                .await
                .unwrap(),
            "smtp.nolumia.com"
        );
    }

    /// 全体の経路は root だけが決めるので確かめない（開発環境の宛先も内部の名前になる）。
    #[tokio::test]
    async fn the_whole_idp_route_is_not_checked_but_a_tenant_route_is() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(run_minimal_smtp_server(listener));
        let mailer = LettreSmtpMailer::new();
        let mut config = SmtpServerConfig {
            host: "127.0.0.1".to_string(),
            port: Some(port),
            username: String::new(),
            password: String::new(),
            from_address: "noreply@example.test".to_string(),
            use_tls: false,
            route: SmtpRoute::Tenant,
        };
        let mail = OutgoingEmail {
            to: "guest@example.test".to_string(),
            subject: "route".to_string(),
            body_text: "body".to_string(),
        };
        assert!(mailer.send(&config, &mail).await.is_err());
        config.route = SmtpRoute::WholeIdp;
        mailer.send(&config, &mail).await.expect("whole idp route");
        server.await.expect("server task");
    }
}
