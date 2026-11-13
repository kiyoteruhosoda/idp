//! Core of the OIDC IdP (`assay-core`).
//!
//! Provides DDD Domain / Application / Infrastructure plus the DB-backed settings and log foundation.
//! Per ADR-0007 (API/Web service split), dependencies on the DB and sqlx are concentrated in this crate.
//! Presentation (axum) and HTML screens live in `assay-api` / the future `assay-web`.

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod metrics;
pub mod telemetry;
