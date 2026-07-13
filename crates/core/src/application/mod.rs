//! アプリケーション層（ユースケース・トランザクション境界）。
//!
//! ドメイン層のトレイトを介して Infrastructure に依存する（具象に直接依存しない）。

pub mod account_language;
pub mod account_password;
pub mod admin_access;
pub mod admin_login;
pub mod audit;
pub mod audit_query;
pub mod authorize;
pub mod change_password;
pub mod client_management;
pub mod client_status;
pub mod code_issuance;
pub mod consent;
pub mod email_verification;
pub mod introspection;
pub mod invitation;
pub mod key_service;
pub mod login;
pub mod logout;
pub mod mfa_login;
pub mod passkey_authentication;
pub mod passkey_registration;
pub mod password_reset;
pub mod permission_management;
pub mod register;
pub mod revocation;
pub mod system_settings;
pub mod tenant_management;
pub mod tenant_resolution;
pub mod token;
pub mod totp_registration;
pub mod user_management;
pub mod userinfo;
