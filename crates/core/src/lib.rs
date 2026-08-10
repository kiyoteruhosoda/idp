//! OIDC IdP のコア（`idp-core`）。
//!
//! DDD の Domain / Application / Infrastructure と、DB 直結の設定・ログ基盤を提供する。
//! ADR-0007（API/Web サービス分割）に基づき、DB・sqlx へ依存するのはこの crate に集約する。
//! presentation（axum）と HTML 画面は `idp-api` / 将来の `idp-web` 側に置く。

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod metrics;
pub mod telemetry;
