//! アプリケーション層（ユースケース・トランザクション境界）。
//!
//! ドメイン層のトレイトを介して Infrastructure に依存する（具象に直接依存しない）。

pub mod admin_access;
pub mod audit;
pub mod audit_query;
pub mod authorize;
pub mod client_management;
pub mod code_issuance;
pub mod key_service;
pub mod login;
pub mod register;
pub mod token;
pub mod userinfo;
