//! SMS 送信のポート（DIP 境界。AP13。SMS OTP が使う）。
//!
//! メール配送（[`crate::domain::mailer`]）と同じ形にしてある: 接続情報はシステム設定
//! （`system_settings`）で実行時に変わるため、構築時ではなく**送信ごと**に受け取る。
//!
//! # 送信事業者を選ばない
//!
//! SMS ゲートウェイの API は事業者ごとに違い、どれを使うかは配置ごとの判断（国・料金・
//! 到達率・契約）である。ここで特定の事業者に寄せると、選び直すたびにコードが変わる。
//! そこで本 IdP は **JSON を 1 本 POST するだけ**の汎用ゲートウェイを口とし、事業者固有の
//! 差異は運用側に置いた小さな中継（関数・Webhook）へ追い出す。中継が受け取る形は
//! [`OutgoingSms`] のとおりで、事業者の SDK をこのリポジトリへ持ち込まない。
//!
//! # PII
//!
//! 電話番号は PII である。ログ・監査・エラーメッセージへ出さない（`Debug` を実装しないのは
//! `{:?}` 経由の漏れを型で防ぐため）。保存先は認証器の登録簿の `target` 列で、メール OTP の
//! 送信先アドレスと同じ扱いにする。

use crate::domain::error::Result;
use async_trait::async_trait;

/// SMS ゲートウェイの接続情報（送信時に使う実体。トークンは復号済みの平文）。
///
/// `Debug` を意図的に実装しない（`{:?}` 経由でトークンがログへ漏れることを型で防ぐ）。
#[derive(Clone)]
pub struct SmsGatewayConfig {
    /// 送信要求を POST する URL。
    pub endpoint_url: String,
    /// 認証ヘッダ名（例 `Authorization`）。空文字列 = 認証ヘッダを付けない。
    pub auth_header: String,
    /// 認証ヘッダの値（例 `Bearer xxx`）。空文字列 = 認証ヘッダを付けない。
    pub auth_token: String,
    /// 差出人表示（事業者が `sender id` / `from` として扱う値）。空文字列 = 指定しない。
    pub sender_id: String,
}

impl SmsGatewayConfig {
    /// 送信できる設定か（URL が空なら SMS 送信は無効）。
    pub fn is_usable(&self) -> bool {
        !self.endpoint_url.trim().is_empty()
    }
}

/// 送信する SMS 1 通。
///
/// `Debug` を実装しない（宛先が PII、本文にワンタイムコードが載るため）。
#[derive(Clone)]
pub struct OutgoingSms {
    /// 宛先電話番号（E.164 正規化済み）。
    pub to: String,
    pub body_text: String,
}

/// SMS 送信のポート。実装はブロッキングせずに送信し、恒久的な失敗はエラーで返す。
#[async_trait]
pub trait SmsSender: Send + Sync {
    async fn send(&self, gateway: &SmsGatewayConfig, sms: &OutgoingSms) -> Result<()>;
}
