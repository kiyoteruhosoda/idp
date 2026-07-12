//! sqlx（MariaDB）によるドメインリポジトリトレイトの実装。

pub mod audit_log;
pub mod auth_session;
pub mod authorization_code;
pub mod cached_user_permission;
pub mod client;
pub mod consent;
pub mod passkey_challenge;
pub mod password_reset_token;
pub mod refresh_token;
pub mod revoked_access_token;
pub mod signing_key;
pub mod sso_session;
pub mod system_setting;
pub mod tenant;
pub mod tenant_membership;
pub mod tenant_provisioning;
pub mod totp_secret;
pub mod user;
pub mod user_permission;
pub mod webauthn_credential;
