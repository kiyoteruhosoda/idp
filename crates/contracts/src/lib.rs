//! OIDC IdP のサービス間 DTO 契約（`idp-contracts`）。
//!
//! ADR-0007（API/Web サービス分割）§6。api（サーバ）が返す JSON DTO と、web（クライアント）が
//! 用いる型を **同一の serde 構造体**で共有し、コンパイル時に契約整合を保証する。DB・axum・sqlx へは
//! 依存しない（`serde` のみ）。OpenAPI からのコード生成は採らず、型は Rust で単一定義する。
//! utoipa による OpenAPI は api 側で継続する（外部公開 API の DTO は api の presentation に置く）。

pub mod admin;
pub mod auth;
pub mod csrf;

pub mod version;
