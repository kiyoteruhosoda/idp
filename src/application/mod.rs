//! アプリケーション層（ユースケース・トランザクション境界）。
//!
//! ドメイン層のトレイトを介して Infrastructure に依存する（具象に直接依存しない）。

pub mod key_service;
pub mod register;
