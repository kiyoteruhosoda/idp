//! ドメイン層（フレームワーク・DB 非依存のビジネスロジックと型）。
//!
//! 依存方向は Presentation → Application → Domain。Infrastructure は本層で定義する
//! トレイト（リポジトリ等の DIP 境界）を実装する。ここには sqlx/axum など具体技術を持ち込まない。

pub mod audit;
pub mod auth_session;
pub mod authorization_code;
pub mod cache;
pub mod client;
pub mod clock;
pub mod consent;
pub mod crypto;
pub mod email_verification;
pub mod error;
pub mod id_generator;
pub mod issuer;
pub mod jwt;
pub mod mailer;
pub mod passkey_challenge;
pub mod password;
pub mod password_reset;
pub mod permission;
pub mod pkce;
pub mod rate_limit;
pub mod refresh_token;
pub mod repositories;
pub mod revoked_access_token;
pub mod saml_metadata;
pub mod saml_provider;
pub mod saml_service_provider;
pub mod signing_key;
pub mod sso_session;
pub mod system_setting;
pub mod tenant;
pub mod tenant_context;
pub mod tenant_membership;
pub mod totp_secret;
pub mod user;
pub mod values;
pub mod webauthn_credential;
pub mod webauthn_port;
