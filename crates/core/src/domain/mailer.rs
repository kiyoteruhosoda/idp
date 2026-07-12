//! メール配送のポート（DIP 境界。MT17 招待メール・MT18 パスワードリセットが使う）。
//!
//! SMTP 接続情報はシステム設定（`system_settings`。MT14）で実行時に変更されるため、接続情報は
//! 構築時ではなく**送信ごと**に受け取る。実装（lettre）は `infrastructure::mailer` にある。
//! `SmtpServerConfig::password` は平文の秘匿値なので、ログ・監査・エラーメッセージに出さない。

use crate::domain::error::Result;
use async_trait::async_trait;

/// SMTP 接続情報（配送時に使う実体。パスワードは復号済みの平文）。
///
/// `Debug` を意図的に実装しない（`{:?}` 経由でパスワードがログへ漏れることを型で防ぐ）。
#[derive(Clone)]
pub struct SmtpServerConfig {
    pub host: String,
    /// 未指定はプロトコル既定（TLS 有効時 465/587、無効時 25）に任せる。
    pub port: Option<u16>,
    /// 空文字列 = SMTP 認証なし。
    pub username: String,
    pub password: String,
    /// 差出人アドレス（`From`）。
    pub from_address: String,
    pub use_tls: bool,
}

/// 送信するメール 1 通（プレーンテキストのみ。HTML メールは扱わない）。
#[derive(Debug, Clone)]
pub struct OutgoingEmail {
    pub to: String,
    pub subject: String,
    pub body_text: String,
}

/// メール配送のポート。実装はブロッキングせずに送信し、恒久的な失敗はエラーで返す。
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> Result<()>;
}
