//! ドメイン層（フレームワーク・DB 非依存のビジネスロジックと型）。
//!
//! 依存方向は Presentation → Application → Domain。Infrastructure は本層で定義する
//! トレイト（リポジトリ等の DIP 境界）を実装する。ここには sqlx/axum など具体技術を持ち込まない。

pub mod audit;
pub mod auth_session;
pub mod authorization_code;
pub mod client;
pub mod clock;
pub mod error;
pub mod password;
pub mod repositories;
pub mod signing_key;
pub mod sso_session;
pub mod user;
pub mod values;
