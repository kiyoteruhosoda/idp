//! ドメイン層（フレームワーク・DB 非依存のビジネスロジックと型）。
//!
//! 依存方向は Presentation → Application → Domain。Infrastructure は本層で定義する
//! トレイト（リポジトリ等の DIP 境界）を実装する。ここには sqlx/axum など具体技術を持ち込まない。

pub mod audit;
pub mod auth_session;
pub mod authorization_code;
pub mod client;
pub mod clock;
pub mod consent;
pub mod error;
pub mod password;
pub mod permission;
pub mod pkce;
pub mod rate_limit;
pub mod refresh_token;
pub mod repositories;
pub mod revoked_access_token;
pub mod signing_key;
pub mod sso_session;
pub mod user;
pub mod values;
