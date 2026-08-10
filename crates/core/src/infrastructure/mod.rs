//! インフラ層（ドメイン層トレイトの実装）。
//!
//! sqlx による MariaDB リポジトリ実装、JWT 署名、暗号ユーティリティ、Clock 実装などを収める。

pub mod backchannel_logout;
pub mod breached_password;
pub mod cache;
pub mod clock;
pub mod crypto;
pub mod db;
pub mod external_oidc;
pub mod id_generator;
pub mod jwt;
pub mod log_capture;
pub mod mailer;
pub mod password;
pub mod rate_limit;
pub mod repositories;
pub mod sms;
pub mod webauthn;
