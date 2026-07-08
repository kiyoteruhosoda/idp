//! sqlx（MariaDB）によるドメインリポジトリトレイトの実装。

pub mod audit_log;
pub mod auth_session;
pub mod authorization_code;
pub mod client;
pub mod consent;
pub mod refresh_token;
pub mod revoked_access_token;
pub mod signing_key;
pub mod sso_session;
pub mod user;
pub mod user_permission;
