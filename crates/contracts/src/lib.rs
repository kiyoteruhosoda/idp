//! OIDC IdP のサービス間 DTO 契約（`assay-contracts`）。
//!
//! ADR-0007（API/Web サービス分割）§6。api（サーバ）が返す JSON DTO と、web（クライアント）が
//! 用いる型を **同一の serde 構造体**で共有し、コンパイル時に契約整合を保証する。DB・axum・sqlx へは
//! 依存しない（HTTP は `http` の基本型のみ。[`http_trace`] 参照）。OpenAPI からのコード生成は採らず、
//! 型は Rust で単一定義する。
//! utoipa による OpenAPI は api 側で継続する（外部公開 API の DTO は api の presentation に置く）。

pub mod admin;
pub mod application_log;
pub mod auth;
pub mod cookie_domain;
pub mod cookies;
pub mod csrf;
pub mod deployment;
pub mod forwarded;
pub mod health;
pub mod http_trace;
pub mod internal_auth;
pub mod runtime_settings;

pub mod version;
